"""包标识与别名归并。

包的身份是三元组 ``(ecosystem, namespace, name)``：

* 生态不同（如 pypi 与 npm）的同名包绝不能混合；
* 同一生态内命名空间不同（如 npm 的 ``@a/x`` 与 ``@b/x``）也不能混合；
* 别名包按输入中 *显式给出* 的映射归并到规范包，映射必须无冲突、无环。
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import E_ALIAS_CONFLICT, E_SCHEMA, InputError


@dataclass(frozen=True)
class PackageKey:
    ecosystem: str
    namespace: str       # 空字符串表示默认/无命名空间
    name: str

    @staticmethod
    def parse(ref) -> "PackageKey":
        """接受 dict ``{ecosystem, namespace?, name}`` 或字符串
        ``ecosystem:[/namespace/]name``（namespace 可省略）。"""
        if isinstance(ref, PackageKey):
            return ref
        if isinstance(ref, str):
            if ":" not in ref:
                raise InputError(
                    E_SCHEMA,
                    f"包引用 {ref!r} 缺少生态前缀，应为 ecosystem:name 或 "
                    "ecosystem:namespace/name",
                )
            ecosystem, rest = ref.split(":", 1)
            if "/" in rest:
                namespace, name = rest.split("/", 1)
            else:
                namespace, name = "", rest
            return PackageKey(ecosystem.strip(), namespace.strip(), name.strip())
        if isinstance(ref, dict):
            try:
                ecosystem = str(ref["ecosystem"])
                name = str(ref["name"])
            except (KeyError, TypeError) as exc:
                raise InputError(
                    E_SCHEMA, f"包引用缺少 ecosystem/name 字段：{ref!r}"
                ) from exc
            namespace = str(ref.get("namespace", ""))
            return PackageKey(ecosystem, namespace, name)
        raise InputError(
            E_SCHEMA, f"无法识别的包引用类型 {type(ref).__name__}: {ref!r}"
        )

    def canonical(self) -> str:
        """稳定的字符串形式，用于输出与字典序平局判定。"""
        if self.namespace:
            return f"{self.ecosystem}:{self.namespace}/{self.name}"
        return f"{self.ecosystem}:{self.name}"

    def __str__(self) -> str:
        return self.canonical()


class AliasMap:
    """显式别名映射：alias -> canonical，支持传递但必须无冲突、无环。"""

    def __init__(self, raw_entries: list | None = None):
        # 原始直接边
        self._direct: dict[PackageKey, PackageKey] = {}
        for i, entry in enumerate(raw_entries or []):
            if not isinstance(entry, dict) or "alias" not in entry \
                    or "canonical" not in entry:
                raise InputError(
                    E_SCHEMA,
                    "alias_mappings 每项需要 alias 与 canonical 两个包引用",
                    context=f"alias_mappings[{i}]",
                )
            alias = PackageKey.parse(entry["alias"])
            canonical = PackageKey.parse(entry["canonical"])
            if alias == canonical:
                # 自映射无意义，忽略
                continue
            if alias in self._direct and self._direct[alias] != canonical:
                raise InputError(
                    E_ALIAS_CONFLICT,
                    f"别名 {alias} 同时映射到 {self._direct[alias]} 与 {canonical}",
                    context=f"alias_mappings[{i}]",
                )
            self._direct[alias] = canonical
        self._cache: dict[PackageKey, PackageKey] = {}
        self._validate_acyclic()

    def _validate_acyclic(self) -> None:
        for start in self._direct:
            seen: set[PackageKey] = set()
            cur = start
            while cur in self._direct:
                if cur in seen:
                    chain = " -> ".join(str(p) for p in (*seen, cur))
                    raise InputError(
                        E_ALIAS_CONFLICT,
                        f"别名映射存在环：{chain}",
                    )
                seen.add(cur)
                cur = self._direct[cur]

    def resolve(self, key: PackageKey) -> PackageKey:
        """把任意包引用归并到规范包（非别名原样返回）。"""
        if key in self._cache:
            return self._cache[key]
        chain: list[PackageKey] = []
        cur = key
        while cur in self._direct:
            chain.append(cur)
            cur = self._direct[cur]
        for node in chain:
            self._cache[node] = cur
        return cur

    def as_dict(self) -> dict[str, str]:
        return {
            str(k): str(self.resolve(k))
            for k in sorted(self._direct, key=lambda p: p.canonical())
        }
