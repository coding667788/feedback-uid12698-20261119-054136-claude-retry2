"""二进制离线候选源测试：魔数、校验和、压缩往返、损坏检测。"""

import hashlib
import tempfile
import unittest
from pathlib import Path

from solution.errors import E_REGISTRY, InputError
from solution.packages import AliasMap, PackageKey
from solution.registry import MAGIC, Registry, write_registry


class TestBinaryRegistry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.raw = {
            "packages": [
                {"package": "pypi:x",
                 "candidates": ["2.0.0", "1.0.0", "1.0.0", "1.1.0"]},
                {"package": "npm:x",
                 "candidates": ["0.9.0", "1.0.0"]},
            ]
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip_compressed_and_dedup_sorted(self):
        path = self.dir / "reg.odr"
        digest = write_registry(path, self.raw, AliasMap(None), compress=True)
        blob = path.read_bytes()
        self.assertEqual(blob[:4], MAGIC)
        reg = Registry.read(path, AliasMap(None))
        self.assertEqual(
            [str(v) for v in reg.candidates(PackageKey.parse("pypi:x"))],
            ["1.0.0", "1.1.0", "2.0.0"],  # 去重 + 升序
        )
        # sha256 声明校验通过
        self.assertEqual(
            Registry.read(path, AliasMap(None),
                          expected_sha256=digest).candidates(
                PackageKey.parse("npm:x"))[0].__str__(),
            "0.9.0",
        )

    def test_uncompressed_roundtrip(self):
        path = self.dir / "reg-plain.odr"
        write_registry(path, self.raw, AliasMap(None), compress=False)
        reg = Registry.read(path, AliasMap(None))
        self.assertTrue(reg.has_package(PackageKey.parse("pypi:x")))
        self.assertFalse(reg.has_package(PackageKey.parse("pypi:missing")))

    def test_bad_magic_rejected(self):
        path = self.dir / "bad.odr"
        path.write_bytes(b"XXXX" + b"\x00" * 40)
        with self.assertRaises(InputError) as cm:
            Registry.read(path, AliasMap(None))
        self.assertEqual(cm.exception.code, E_REGISTRY)

    def test_tampered_payload_checksum_fails(self):
        path = self.dir / "tamper.odr"
        write_registry(path, self.raw, AliasMap(None), compress=True)
        blob = bytearray(path.read_bytes())
        blob[-1] ^= 0xFF  # 翻转 payload 最后一个字节
        path.write_bytes(bytes(blob))
        with self.assertRaises(InputError) as cm:
            Registry.read(path, AliasMap(None))
        self.assertEqual(cm.exception.code, E_REGISTRY)

    def test_declared_sha256_mismatch_rejected(self):
        path = self.dir / "reg.odr"
        write_registry(path, self.raw, AliasMap(None))
        fake = hashlib.sha256(b"not-the-payload").hexdigest()
        with self.assertRaises(InputError) as cm:
            Registry.read(path, AliasMap(None), expected_sha256=fake)
        self.assertEqual(cm.exception.code, E_REGISTRY)

    def test_alias_merge_inside_registry(self):
        aliases = AliasMap([
            {"alias": "pypi:x_old", "canonical": "pypi:x"},
        ])
        raw = {"packages": [
            {"package": "pypi:x_old", "candidates": ["1.0.0"]},
            {"package": "pypi:x", "candidates": ["1.1.0"]},
        ]}
        path = self.dir / "alias.odr"
        write_registry(path, raw, aliases)
        reg = Registry.read(path, aliases)
        # 别名与规范包解析到同一候选集合
        self.assertEqual(
            [str(v) for v in reg.candidates(PackageKey.parse("pypi:x"))],
            ["1.0.0", "1.1.0"],
        )
        self.assertEqual(
            [str(v) for v in reg.candidates(PackageKey.parse("pypi:x_old"))],
            ["1.0.0", "1.1.0"],
        )


if __name__ == "__main__":
    unittest.main()
