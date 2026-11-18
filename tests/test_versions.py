"""版本号与版本区间代数测试：预发布边界、并/交/差、解析错误。"""

import unittest

from solution.errors import E_INVALID_RANGE, E_INVALID_VERSION, InputError
from solution.models import Interval, Version, VersionRange, parse_range


def V(text: str) -> Version:
    return Version.parse(text)


class TestVersionOrdering(unittest.TestCase):
    def test_numeric_triple_ordering(self):
        self.assertLess(V("1.2.3"), V("1.2.4"))
        self.assertLess(V("1.2.9"), V("1.3.0"))
        self.assertLess(V("1.9.9"), V("2.0.0"))
        self.assertGreater(V("10.0.0"), V("9.9.9"))  # 数字比较，非字典序

    def test_release_greater_than_any_prerelease_same_triple(self):
        self.assertLess(V("1.0.0-pre.1"), V("1.0.0"))
        self.assertLess(V("1.0.0-pre.99"), V("1.0.0"))
        self.assertGreater(V("1.0.0"), V("1.0.0-pre.1"))

    def test_prerelease_numeric_n_order(self):
        # N 按数值排序：pre.10 必须大于 pre.2（字符串排序会相反）
        self.assertLess(V("1.0.0-pre.2"), V("1.0.0-pre.10"))
        ordered = sorted(
            V(x) for x in
            ("1.0.0-pre.10", "1.0.0", "1.0.0-pre.2", "0.9.9")
        )
        self.assertEqual(
            [str(v) for v in ordered],
            ["0.9.9", "1.0.0-pre.2", "1.0.0-pre.10", "1.0.0"],
        )

    def test_invalid_versions(self):
        for bad in ("1.2", "1.2.3.4", "1.2.x", "v1.2.3",
                    "1.2.3-pre", "1.2.3-pre.x", "1.2.3-pre.",
                    "1.2.3-PRE.1", "1.2.3-pre.01"):
            with self.subTest(bad=bad):
                with self.assertRaises(InputError) as cm:
                    V(bad)
                self.assertEqual(cm.exception.code, E_INVALID_VERSION)

    def test_prerelease_boundary_membership(self):
        rng = parse_range(">=1.0.0-pre.2 <1.0.0")
        self.assertTrue(rng.contains(V("1.0.0-pre.2")))   # 下界闭
        self.assertTrue(rng.contains(V("1.0.0-pre.10")))
        self.assertFalse(rng.contains(V("1.0.0-pre.1")))
        self.assertFalse(rng.contains(V("1.0.0")))        # 上界开


class TestRangeAlgebra(unittest.TestCase):
    def test_caret_and_tilde(self):
        caret = parse_range("^1.2.3")
        self.assertTrue(caret.contains(V("1.2.3")))
        self.assertTrue(caret.contains(V("1.9.9")))
        self.assertFalse(caret.contains(V("1.2.2")))
        self.assertFalse(caret.contains(V("2.0.0")))

        caret0 = parse_range("^0.2.3")
        self.assertTrue(caret0.contains(V("0.2.9")))
        self.assertFalse(caret0.contains(V("0.3.0")))

        tilde = parse_range("~1.2.3")
        self.assertTrue(tilde.contains(V("1.2.9")))
        self.assertFalse(tilde.contains(V("1.3.0")))

    def test_or_and_intersection(self):
        rng = parse_range(">=1.0.0 || >=2.0.0 <3.0.0")
        self.assertTrue(rng.contains(V("1.0.0")))
        self.assertTrue(rng.contains(V("2.5.0")))
        # 第一段 >=1.0.0 无上界，3.0.0 属于第一段（OR 语义）
        self.assertTrue(rng.contains(V("3.0.0")))
        self.assertFalse(rng.contains(V("0.9.9")))

        both = rng.intersection(parse_range(">=2.0.0 <3.0.0"))
        self.assertFalse(both.contains(V("1.5.0")))
        self.assertTrue(both.contains(V("2.5.0")))
        self.assertFalse(both.contains(V("3.0.0")))

    def test_difference_carves_safe_island(self):
        # 回归漏洞：[1.0,4.0) 减去 [2.0,3.0)，留下两个安全区间
        base = parse_range(">=1.0.0 <4.0.0")
        diff = base.difference(parse_range(">=2.0.0 <3.0.0"))
        grid = ["1.0.0", "1.9.9", "2.0.0", "2.5.0",
                "2.9.9", "3.0.0", "3.9.9", "4.0.0"]
        inside = [g for g in grid if diff.contains(V(g))]
        self.assertEqual(inside, ["1.0.0", "1.9.9", "3.0.0", "3.9.9"])

    def test_open_endpoint_exclusion(self):
        rng = parse_range(">1.0.0 <=2.0.0")
        self.assertFalse(rng.contains(V("1.0.0")))
        self.assertTrue(rng.contains(V("1.0.1")))
        self.assertTrue(rng.contains(V("2.0.0")))
        self.assertFalse(rng.contains(V("2.0.1")))

    def test_structured_dict_and_list(self):
        rng = parse_range({
            "intervals": [
                {"lo": "1.0.0", "hi": "2.0.0",
                 "lo_inclusive": True, "hi_inclusive": False},
            ],
        })
        self.assertTrue(rng.contains(V("1.0.0")))
        self.assertFalse(rng.contains(V("2.0.0")))

        union = parse_range([
            {"lo": "1.0.0", "hi": "1.5.0"},
            {"lo": "3.0.0", "hi": None},
        ])
        self.assertTrue(union.contains(V("1.2.0")))
        self.assertFalse(union.contains(V("2.0.0")))
        self.assertTrue(union.contains(V("9.9.9")))

    def test_unbounded_and_empty(self):
        self.assertTrue(parse_range("*").contains(V("0.0.0-pre.1")))
        empty = parse_range(">=2.0.0").intersection(parse_range("<2.0.0"))
        self.assertTrue(empty.is_empty)
        self.assertEqual(empty.filter_versions([V("2.0.0")]), [])

    def test_disjoint(self):
        a = parse_range(">=1.0.0 <2.0.0")
        b = parse_range(">=2.0.0 <3.0.0")  # 一开一闭，端点不相交
        self.assertTrue(a.is_disjoint(b))
        c = parse_range(">=1.5.0 <2.5.0")
        self.assertFalse(a.is_disjoint(c))

    def test_invalid_syntax(self):
        for bad in ("1.2", ">=1.2.3 ||", "lol 1.0.0", "==1.2"):
            with self.subTest(bad=bad):
                with self.assertRaises(InputError) as cm:
                    parse_range(bad)
                self.assertEqual(cm.exception.code, E_INVALID_RANGE)

    def test_interval_difference_two_parts(self):
        whole = Interval(V("1.0.0"), True, V("5.0.0"), True)
        middle = Interval(V("2.0.0"), True, V("3.0.0"), True)
        parts = whole.difference(middle)
        self.assertEqual(len(parts), 2)
        self.assertTrue(parts[0].contains(V("1.5.0")))
        self.assertFalse(parts[0].contains(V("2.0.0")))
        self.assertTrue(parts[1].contains(V("3.1.0")))
        self.assertFalse(parts[1].contains(V("3.0.0")))

    def test_overlapping_union_is_normalized(self):
        # 两个重叠区间求并后规范化为单个连续区间，成员保持等价
        rng = parse_range(">=1.0.0 <3.0.0").union(
            parse_range(">=2.0.0 <=4.0.0")
        )
        self.assertEqual(len(rng.intervals), 1)
        grid = ["0.9.9", "1.0.0", "2.5.0", "3.0.0", "4.0.0", "4.0.1"]
        self.assertEqual(
            [g for g in grid if rng.contains(V(g))],
            ["1.0.0", "2.5.0", "3.0.0", "4.0.0"],
        )

    def test_unbounded_interval_sorts_first(self):
        rng = parse_range(">=2.0.0").union(parse_range("*"))
        # 与全集求并后就是全集，单区间且无界
        self.assertEqual(len(rng.intervals), 1)
        self.assertIsNone(rng.intervals[0].lo)
        self.assertIsNone(rng.intervals[0].hi)


if __name__ == "__main__":
    unittest.main()
