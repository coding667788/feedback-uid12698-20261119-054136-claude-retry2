"""本地漏洞公告匹配（完全离线，不访问任何在线漏洞库）。

公告模型支持：

* ``affected`` 为 *多个* 受影响版本区间的并集（OR）；
* 通过相邻区间天然表达“补丁回退再次引入”——例如先在 2.0.0 修复、
  又在 3.1.0 重新引入，则写成 ``[>=1.0.0 <2.0.0]`` 与 ``[>=3.1.0 <4.0.0]``
  两个区间，中间的安全版本不属于任何区间；
* 每条公告可携带平台条件，按三值逻辑求值：FALSE 表示平台不适用，
  UNKNOWN 表示条件未知（按 ``unknown_policy`` 决定是否视为风险）。

节点与公告的匹配结果与图可达状态组合为最终状态：

* ``affected_reachable``        命中且生产已知可达（附最短证据链）；
* ``affected_condition_unknown`` 命中但仅条件未知路径可达；
* ``affected_unreachable``      命中但生产不可达（锁文件存在≠生产可达）；
* ``platform_inapplicable``     公告条件明确为假；
* ``not_affected``              版本不属于任何受影响区间。
"""

from __future__ import annotations

from dataclasses import dataclass

from . import conditions
from .errors import E_SCHEMA, InputError
from .graph import Graph
from .models import VersionRange, parse_range
from .packages import AliasMap, PackageKey


@dataclass(frozen=True)
class Advisory:
    id: str
    key: PackageKey                 # 已做别名归并
    affected: VersionRange          # 多个受影响区间的并
    condition: object               # 平台条件（None = 无条件）
    title: str
    severity: str

    @staticmethod
    def parse(raw: dict, aliases: AliasMap, index: int) -> "Advisory":
        for field_name in ("id", "package", "affected"):
            if field_name not in raw:
                raise InputError(
                    E_SCHEMA,
                    f"公告缺少字段 {field_name!r}",
                    context=f"advisories[{index}].{field_name}",
                )
        if not isinstance(raw["affected"], list) or not raw["affected"]:
            raise InputError(
                E_SCHEMA,
                "公告 affected 必须是非空区间列表（多区间的并）",
                context=f"advisories[{index}].affected",
            )
        vr = VersionRange([])
        for j, piece in enumerate(raw["affected"]):
            vr = vr.union(parse_range(piece))
        return Advisory(
            id=str(raw["id"]),
            key=aliases.resolve(PackageKey.parse(raw["package"])),
            affected=vr,
            condition=raw.get("condition"),
            title=str(raw.get("title", "")),
            severity=str(raw.get("severity", "UNSPECIFIED")),
        )


def parse_advisories(raw_list: list, aliases: AliasMap) -> list[Advisory]:
    if not isinstance(raw_list, list):
        raise InputError(E_SCHEMA, "advisories 必须是列表")
    seen: set[str] = set()
    out: list[Advisory] = []
    for i, raw in enumerate(raw_list):
        adv = Advisory.parse(raw, aliases, i)
        if adv.id in seen:
            raise InputError(
                E_SCHEMA, f"公告 id {adv.id!r} 重复",
                context=f"advisories[{i}]",
            )
        seen.add(adv.id)
        out.append(adv)
    return out


def match_graph(
    graph: Graph,
    advisories: list[Advisory],
    context: dict[str, str],
    unknown_policy: str = "exclude",
) -> dict:
    """对整张图执行公告匹配。

    ``unknown_policy``：
    * ``exclude``（默认，保守安全口径）——公告平台条件未知时仍计入风险，
      状态落到 ``*_condition_unknown`` 或按已知可达计为受影响；
    * ``ignore``——条件未知的公告视为不适用。
    """
    if unknown_policy not in ("exclude", "ignore"):
        raise InputError(
            E_SCHEMA, f"unknown_policy 只能是 exclude/ignore，得到 {unknown_policy!r}"
        )

    index: dict[str, list[Advisory]] = {}
    for adv in advisories:
        index.setdefault(adv.key.canonical(), []).append(adv)

    findings: list[dict] = []
    platform_inapplicable: list[dict] = []
    reachability = graph.reachability_map(context)

    for node_id, node in graph.nodes.items():
        for adv in index.get(node.key.canonical(), ()):
            if not adv.affected.contains(node.version):
                findings.append(
                    _finding(adv, node, reachability[node_id], "not_affected")
                )
                continue
            tri = conditions.evaluate(adv.condition, context)
            if tri is conditions.FALSE:
                platform_inapplicable.append(
                    {
                        "advisory_id": adv.id,
                        "node_id": node_id,
                        "package": node.key.canonical(),
                        "version": str(node.version),
                        "status": "platform_inapplicable",
                        "condition_truth": "false",
                    }
                )
                continue
            if tri is conditions.UNKNOWN and unknown_policy == "ignore":
                platform_inapplicable.append(
                    {
                        "advisory_id": adv.id,
                        "node_id": node_id,
                        "package": node.key.canonical(),
                        "version": str(node.version),
                        "status": "platform_inapplicable",
                        "condition_truth": "unknown_ignored",
                    }
                )
                continue
            reach = reachability[node_id]
            status = _combine_status(reach["status"], tri)
            finding = _finding(adv, node, reach, status)
            finding["advisory_condition_truth"] = (
                "true" if tri is conditions.TRUE else "unknown"
            )
            findings.append(finding)

    counts = {
        "affected_reachable": 0,
        "affected_condition_unknown": 0,
        "affected_unreachable": 0,
        "not_affected": 0,
        "platform_inapplicable": len(platform_inapplicable),
    }
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1

    # 输出排序：风险优先，再按公告 id / 节点 id，保证可重放
    order = {
        "affected_reachable": 0,
        "affected_condition_unknown": 1,
        "affected_unreachable": 2,
        "not_affected": 3,
    }
    findings.sort(key=lambda f: (order.get(f["status"], 9), f["advisory_id"],
                                 f["node_id"]))
    platform_inapplicable.sort(key=lambda f: (f["advisory_id"], f["node_id"]))
    return {
        "findings": findings,
        "platform_inapplicable": platform_inapplicable,
        "counts": counts,
        "reachability": reachability,
    }


def _combine_status(reach_status: str, advisory_truth) -> str:
    if reach_status == "reachable":
        # 公告条件未知但节点确定生产可达：风险存在，只是平台适用性未知
        return (
            "affected_reachable"
            if advisory_truth is conditions.TRUE
            else "affected_condition_unknown"
        )
    if reach_status == "condition_unknown":
        return "affected_condition_unknown"
    return "affected_unreachable"


def _finding(adv: Advisory, node, reach: dict, status: str) -> dict:
    return {
        "advisory_id": adv.id,
        "title": adv.title,
        "severity": adv.severity,
        "node_id": node.id,
        "package": node.key.canonical(),
        "version": str(node.version),
        "status": status,
        "evidence": {
            "reachability": reach["status"],
            "hops": reach["hops"],
            "unknown_conditions": reach["unknown_conditions"],
            "path": reach["path"],
            **({"note": reach["note"],
                "non_production_path": reach["non_production_path"]}
               if "note" in reach else {}),
        },
    }
