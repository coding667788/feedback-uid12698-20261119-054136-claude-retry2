"""版本号与版本区间。

版本规则（题面）：``major.minor.patch[-pre.N]``

* 先比较 major/minor/patch 数字三元组；
* 三元组相同时，正式版高于任何预发布版；
* 同为预发布版时，按预发布序号 ``N`` 的数值排序；
* 同一三元组下不允许两个预发布版拥有相同 N。

区间用若干 *闭/开有界或无界* 区间的并表示，支持并（OR）、交（AND）、
差（差集）三种集合运算以及成员判定。所有运算都是精确的，不做浮点处理。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .errors import E_INVALID_RANGE, E_INVALID_VERSION, InputError

_VERSION_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-pre\.(0|[1-9]\d*))?$"
)


@dataclass(frozen=True)
class Version:
    """不可变版本号。

    ``pre`` 为 ``None`` 表示正式版；否则为非负整数预发布序号。
    比较键设计使得同一三元组下正式版恒大于预发布版：
    ``(major, minor, patch, 1, 0)`` 对正式版，
    ``(major, minor, patch, 0, N)`` 对预发布版。
    """

    major: int
    minor: int
    patch: int
    pre: Optional[int] = None

    @staticmethod
    def parse(text: str) -> "Version":
        if not isinstance(text, str):
            raise InputError(
                E_INVALID_VERSION, f"版本号必须是字符串，得到 {type(text).__name__}"
            )
        m = _VERSION_RE.match(text.strip())
        if not m:
            raise InputError(
                E_INVALID_VERSION,
                f"版本号 {text!r} 不符合 major.minor.patch[-pre.N] 规则",
            )
        major, minor, patch, pre = m.groups()
        return Version(int(major), int(minor), int(patch),
                       None if pre is None else int(pre))

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None

    @property
    def _key(self) -> tuple:
        if self.pre is None:
            return (self.major, self.minor, self.patch, 1, 0)
        return (self.major, self.minor, self.patch, 0, self.pre)

    def __lt__(self, other: "Version") -> bool:
        return self._key < other._key

    def __le__(self, other: "Version") -> bool:
        return self._key <= other._key

    def __gt__(self, other: "Version") -> bool:
        return self._key > other._key

    def __ge__(self, other: "Version") -> bool:
        return self._key >= other._key

    def __str__(self) -> str:
        if self.pre is None:
            return f"{self.major}.{self.minor}.{self.patch}"
        return f"{self.major}.{self.minor}.{self.patch}-pre.{self.pre}"

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"Version({self})"


# 边界：(版本或 None, 是否包含该版本)；None 表示无界
Bound = tuple[Optional[Version], bool]


@dataclass(frozen=True)
class Interval:
    """单个版本区间 ``[lo, hi]`` 风格，端点可开可闭、可无界。"""

    lo: Optional[Version]
    lo_inclusive: bool
    hi: Optional[Version]
    hi_inclusive: bool

    @property
    def is_empty(self) -> bool:
        if self.lo is None or self.hi is None:
            return False
        if self.lo < self.hi:
            return False
        if self.lo > self.hi:
            return True
        # 两端点版本相同：只有双闭才非空
        return not (self.lo_inclusive and self.hi_inclusive)

    def contains(self, v: Version) -> bool:
        if self.lo is not None:
            if self.lo_inclusive:
                if v < self.lo:
                    return False
            elif v <= self.lo:
                return False
        if self.hi is not None:
            if self.hi_inclusive:
                if v > self.hi:
                    return False
            elif v >= self.hi:
                return False
        return True

    def intersect(self, other: "Interval") -> "Interval":
        # 取较大的下界
        if self.lo is None:
            lo, lo_inc = other.lo, other.lo_inclusive
        elif other.lo is None:
            lo, lo_inc = self.lo, self.lo_inclusive
        elif self.lo > other.lo:
            lo, lo_inc = self.lo, self.lo_inclusive
        elif self.lo < other.lo:
            lo, lo_inc = other.lo, other.lo_inclusive
        else:
            lo = self.lo
            lo_inc = self.lo_inclusive and other.lo_inclusive
        # 取较小的上界
        if self.hi is None:
            hi, hi_inc = other.hi, other.hi_inclusive
        elif other.hi is None:
            hi, hi_inc = self.hi, self.hi_inclusive
        elif self.hi < other.hi:
            hi, hi_inc = self.hi, self.hi_inclusive
        elif self.hi > other.hi:
            hi, hi_inc = other.hi, other.hi_inclusive
        else:
            hi = self.hi
            hi_inc = self.hi_inclusive and other.hi_inclusive
        result = Interval(lo, lo_inc, hi, hi_inc)
        return result

    def difference(self, other: "Interval") -> list["Interval"]:
        """``self - other``，返回 0/1/2 个区间。"""
        if self.intersect(other).is_empty:
            return [self]
        parts: list[Interval] = []
        # 左侧残段：self.lo .. other.lo
        if other.lo is not None:
            left = Interval(
                self.lo,
                self.lo_inclusive,
                other.lo,
                not other.lo_inclusive,  # 被减区间含端点则残段改为开
            )
            if not left.is_empty:
                parts.append(left)
        # 右侧残段：other.hi .. self.hi
        if other.hi is not None:
            right = Interval(
                other.hi,
                not other.hi_inclusive,
                self.hi,
                self.hi_inclusive,
            )
            if not right.is_empty:
                parts.append(right)
        return parts

    def __str__(self) -> str:
        l = ("-inf" if self.lo is None
             else f"{'[' if self.lo_inclusive else '('}{self.lo}")
        h = ("+inf" if self.hi is None
             else f"{self.hi}{']' if self.hi_inclusive else ')'}")
        if self.lo is None and self.hi is None:
            return "*"
        if self.lo is None:
            return f"<= {'(' if not self.hi_inclusive else ''}{h}"
        if self.hi is None:
            return f"{l} >="
        return f"{l}, {h}"


def _lower_sort_key(i: Interval):
    # 无下界（None）排在最前；其余按下界版本排序
    return (1, i.lo) if i.lo is not None else (0, Version(0, 0, 0))


def _merge_intervals(intervals: Iterable[Interval]) -> list[Interval]:
    """把重叠/相邻的区间合并为规范的不相交并，按下界排序。"""
    valid = [i for i in intervals if not i.is_empty]
    if not valid:
        return []
    valid.sort(key=_lower_sort_key)
    merged: list[Interval] = []
    for cur in valid:
        if not merged:
            merged.append(cur)
            continue
        last = merged[-1]
        # 排序后只有第一个区间可能无下界
        if cur.lo is None:  # pragma: no cover - 排序保证不会发生
            merged.insert(0, cur)
            continue
        if last.hi is None:
            # last 上界无界，cur 一定被包含
            continue
        if cur.lo < last.hi or (
            cur.lo == last.hi and (cur.lo_inclusive or last.hi_inclusive)
        ):
            # 重叠或闭端点相接：合并
            if cur.hi is None or cur.hi > last.hi:
                new_hi, new_hi_inc = cur.hi, cur.hi_inclusive
            elif cur.hi == last.hi:
                new_hi = last.hi
                new_hi_inc = last.hi_inclusive or cur.hi_inclusive
            else:
                new_hi, new_hi_inc = last.hi, last.hi_inclusive
            merged[-1] = Interval(
                last.lo, last.lo_inclusive, new_hi, new_hi_inc
            )
        else:
            merged.append(cur)
    return merged


class VersionRange:
    """版本集合：若干互不相交区间的并。

    支持成员判定、并集、交集、差集，以及从有限候选版本集合中过滤。
    """

    def __init__(self, intervals: Optional[Iterable[Interval]] = None):
        self._intervals = _merge_intervals(list(intervals or []))

    # ---- 构造便捷方法 ----
    @staticmethod
    def all_versions() -> "VersionRange":
        return VersionRange([Interval(None, True, None, True)])

    @staticmethod
    def point(v: Version) -> "VersionRange":
        return VersionRange([Interval(v, True, v, True)])

    @property
    def is_empty(self) -> bool:
        return not self._intervals

    @property
    def intervals(self) -> list[Interval]:
        return list(self._intervals)

    # ---- 集合运算 ----
    def contains(self, v: Version) -> bool:
        return any(i.contains(v) for i in self._intervals)

    def union(self, other: "VersionRange") -> "VersionRange":
        return VersionRange(self._intervals + other._intervals)

    def intersection(self, other: "VersionRange") -> "VersionRange":
        out: list[Interval] = []
        for a in self._intervals:
            for b in other._intervals:
                c = a.intersect(b)
                if not c.is_empty:
                    out.append(c)
        return VersionRange(out)

    def difference(self, other: "VersionRange") -> "VersionRange":
        current = list(self._intervals)
        for b in other._intervals:
            nxt: list[Interval] = []
            for a in current:
                nxt.extend(a.difference(b))
            current = nxt
        return VersionRange(current)

    def is_disjoint(self, other: "VersionRange") -> bool:
        return self.intersection(other).is_empty

    def filter_versions(self, versions: Iterable[Version]) -> list[Version]:
        """从有限候选集合中返回属于本区间的版本，按版本升序。"""
        return sorted(v for v in versions if self.contains(v))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, VersionRange)
            and self._intervals == other._intervals
        )

    def __hash__(self) -> int:
        return hash(tuple(self._intervals))

    def __str__(self) -> str:
        if not self._intervals:
            return "<empty>"
        return " OR ".join(str(i) for i in self._intervals)


# ---------------------------------------------------------------------------
# 区间表达式解析
# ---------------------------------------------------------------------------
# 支持两种书写形式（可混用）：
# 1. 字符串简写：
#    "*"                  全部版本
#    "1.2.3"              单点
#    ">=1.0.0 <2.0.0"     空格分隔 = 交集（AND）
#    ">=1.0.0 || >=3.0.0" 双竖线 = 并集（OR），优先级低于 AND
#    "^1.2.3"             兼容更新：>=1.2.3 <2.0.0（major=0 时 ^0.2.3 => >=0.2.3 <0.3.0）
#    "~1.2.3"             补丁级更新：>=1.2.3 <1.3.0
#    比较符：>= <= > < = ==
# 2. 结构化 dict/list（见 parse_range 文档与 README）
_ATOM_RE = re.compile(
    r"^\s*(>=|<=|==|=|>|<|\^|~)?\s*("
    r"\d+\.\d+\.\d+(?:-pre\.\d+)?|\*"
    r")\s*$"
)


def _atom_to_interval(token: str) -> Interval:
    m = _ATOM_RE.match(token)
    if not m:
        raise InputError(E_INVALID_RANGE, f"无法解析区间原子 {token!r}")
    op, raw = m.group(1), m.group(2)
    if raw == "*":
        if op is not None:
            raise InputError(E_INVALID_RANGE, f"通配符 * 不能带比较符：{token!r}")
        return Interval(None, True, None, True)
    v = Version.parse(raw)
    if op is None or op in ("=", "=="):
        return Interval(v, True, v, True)
    if op == ">=":
        return Interval(v, True, None, True)
    if op == ">":
        return Interval(v, False, None, True)
    if op == "<=":
        return Interval(None, True, v, True)
    if op == "<":
        return Interval(None, True, v, False)
    if op == "^":
        # ^0.y.z 锁定 minor；其余锁定 major
        if v.major == 0:
            upper = Version(0, v.minor + 1, 0)
        else:
            upper = Version(v.major + 1, 0, 0)
        return Interval(v, True, upper, False)
    if op == "~":
        upper = Version(v.major, v.minor + 1, 0)
        return Interval(v, True, upper, False)
    raise InputError(E_INVALID_RANGE, f"不支持的比较符 {op!r}")  # pragma: no cover


def _parse_string_range(text: str) -> VersionRange:
    or_parts = text.split("||")
    if any(not p.strip() for p in or_parts):
        raise InputError(
            E_INVALID_RANGE, f"区间表达式存在悬空的 || 段：{text!r}"
        )
    if not or_parts:
        raise InputError(E_INVALID_RANGE, "空区间表达式")
    result = VersionRange([])
    for part in or_parts:
        tokens = part.split()
        acc = VersionRange.all_versions()
        for token in tokens:
            acc = acc.intersection(
                VersionRange([_atom_to_interval(token)])
            )
        result = result.union(acc)
    return result


def _parse_dict_interval(d: dict) -> Interval:
    lo = Version.parse(d["lo"]) if d.get("lo") is not None else None
    hi = Version.parse(d["hi"]) if d.get("hi") is not None else None
    return Interval(lo, bool(d.get("lo_inclusive", True)),
                    hi, bool(d.get("hi_inclusive", True)))


def parse_range(spec) -> VersionRange:
    """把字符串 / dict / list 形式的区间规格解析为 :class:`VersionRange`。

    * 字符串：见模块 docstring 的简写语法；
    * dict：``{"intervals": [{"lo": ..., "hi": ..., "lo_inclusive": ...,
      "hi_inclusive": ...}]}``，端点为 ``null`` 表示无界；
    * list：每个元素是一个区间 dict，列表整体为并集。
    """
    if isinstance(spec, VersionRange):
        return spec
    if isinstance(spec, str):
        return _parse_string_range(spec)
    if isinstance(spec, dict):
        if "intervals" in spec:
            items = spec["intervals"]
        else:
            items = [spec]
    elif isinstance(spec, list):
        items = spec
    else:
        raise InputError(
            E_INVALID_RANGE,
            f"区间规格必须是字符串/dict/list，得到 {type(spec).__name__}",
        )
    intervals = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise InputError(
                E_INVALID_RANGE, f"区间 #{i} 必须是对象", context=f"intervals[{i}]"
            )
        intervals.append(_parse_dict_interval(item))
    return VersionRange(intervals)
