"""二进制离线候选版本源（自定义小格式，纯标准库 struct/zlib/hashlib）。

格式（大端）::

    magic     = b"ODRJ"                    # Offline Dependency Registry
    version   = uint16                     # 当前为 1
    flags     = uint16                     # bit0 = payload 经 zlib 压缩
    sha256    = 32 字节                    # 对 payload 原始（解压后）字节的摘要
    length    = uint32                     # payload 字节数
    payload   = JSON UTF-8（可能 zlib 压缩）

payload 逻辑结构::

    {"packages": [{"package": <包引用>, "candidates": ["1.0.0", ...]}, ...]}

候选版本在读取时即排序去重；该文件完全离线生成与读取，不代表任何真实服务。
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

from .errors import E_REGISTRY, E_SCHEMA, InputError
from .models import Version
from .packages import AliasMap, PackageKey

MAGIC = b"ODRJ"
FORMAT_VERSION = 1
FLAG_ZLIB = 0x0001
_HEADER = struct.Struct(">4sHH32sI")


def build_registry_payload(raw: dict, aliases: AliasMap) -> dict:
    """校验并归并候选源的逻辑内容，返回规范化 payload。"""
    if not isinstance(raw, dict) or not isinstance(raw.get("packages"), list):
        raise InputError(E_SCHEMA, "registry payload 需要 packages 列表")
    normalized: dict[str, list[Version]] = {}
    for i, item in enumerate(raw["packages"]):
        if not isinstance(item, dict) or "package" not in item \
                or "candidates" not in item:
            raise InputError(
                E_SCHEMA,
                "registry.packages 每项需要 package 与 candidates",
                context=f"registry.packages[{i}]",
            )
        key = aliases.resolve(PackageKey.parse(item["package"]))
        versions = sorted({Version.parse(v) for v in item["candidates"]})
        bucket = normalized.setdefault(key.canonical(), [])
        bucket.extend(versions)
    return {
        "packages": [
            {"package": canon,
             "candidates": [str(v) for v in sorted(set(versions))]}
            for canon, versions in sorted(normalized.items())
        ]
    }


def write_registry(path: str | Path, raw: dict, aliases: AliasMap,
                   compress: bool = True) -> str:
    """生成二进制候选源文件，返回 payload 的 sha256（十六进制）。"""
    payload = json.dumps(
        build_registry_payload(raw, aliases),
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    stored = zlib.compress(payload, 9) if compress else payload
    flags = FLAG_ZLIB if compress else 0
    header = _HEADER.pack(
        MAGIC, FORMAT_VERSION, flags, bytes.fromhex(digest), len(stored)
    )
    Path(path).write_bytes(header + stored)
    return digest


class Registry:
    """内存中的候选版本源：canonical 包字符串 -> 升序 Version 列表。"""

    def __init__(self, payload: dict, aliases: AliasMap, source: str | None = None):
        normalized = build_registry_payload(payload, aliases)
        self.source = source
        self._aliases = aliases
        self._candidates: dict[str, list[Version]] = {}
        for item in normalized["packages"]:
            # 再次归并：同一规范包可能由多个别名条目写入
            key = aliases.resolve(PackageKey.parse(item["package"]))
            bucket = self._candidates.setdefault(key.canonical(), [])
            bucket.extend(Version.parse(v) for v in item["candidates"])
        self._candidates = {
            canon: sorted(set(versions))
            for canon, versions in self._candidates.items()
        }

    @staticmethod
    def read(path: str | Path, aliases: AliasMap,
             expected_sha256: str | None = None) -> "Registry":
        p = Path(path)
        if not p.exists():
            raise InputError(E_REGISTRY, f"候选源文件不存在：{p}")
        blob = p.read_bytes()
        if len(blob) < _HEADER.size:
            raise InputError(E_REGISTRY, f"候选源文件过短，头部不完整：{p}")
        magic, fmt_version, flags, digest_bytes, length = _HEADER.unpack(
            blob[: _HEADER.size]
        )
        if magic != MAGIC:
            raise InputError(E_REGISTRY, f"候选源魔数错误：{p}")
        if fmt_version != FORMAT_VERSION:
            raise InputError(
                E_REGISTRY, f"候选源格式版本 {fmt_version} 不受支持：{p}"
            )
        stored = blob[_HEADER.size: _HEADER.size + length]
        if len(stored) != length:
            raise InputError(E_REGISTRY, f"候选源 payload 长度不完整：{p}")
        try:
            payload_bytes = (
                zlib.decompress(stored) if flags & FLAG_ZLIB else stored
            )
        except zlib.error as exc:
            raise InputError(E_REGISTRY, f"候选源 zlib 解压失败：{exc}") from exc
        actual = hashlib.sha256(payload_bytes).hexdigest()
        expected = digest_bytes.hex()
        if actual != expected:
            raise InputError(
                E_REGISTRY,
                f"候选源校验和不匹配：头摘要 {expected} != 实际 {actual}",
            )
        if expected_sha256 is not None and actual != expected_sha256.lower():
            raise InputError(
                E_REGISTRY,
                f"候选源 sha256 与用例声明不符：声明 {expected_sha256} 实际 {actual}",
            )
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InputError(E_REGISTRY, f"候选源 payload 不是合法 JSON：{exc}") from exc
        return Registry(payload, aliases, source=str(p))

    def _resolve(self, key: PackageKey) -> str:
        return self._aliases.resolve(key).canonical()

    def candidates(self, key: PackageKey) -> list[Version]:
        return list(self._candidates.get(self._resolve(key), []))

    def has_package(self, key: PackageKey) -> bool:
        return self._resolve(key) in self._candidates

    def all_packages(self) -> list[str]:
        return sorted(self._candidates)
