"""依赖图、边解析与从根项目出发的最短可达证据。

锁文件被建模为有向图：

* 节点 = 一个被锁定的包版本（同一包的多个版本可同时存在，即“分叉依赖”）；
* 边 = 一条依赖声明，携带版本要求（区间）、scope 与平台条件；
* 根项目是虚拟节点 ``@root``，``from`` 为 ``null`` 的边从根出发。

可达性判定严格区分生产路径：只有 scope 属于 production/runtime 的边参与。
判定分两遍进行：

1. *已知可达* BFS：只走条件（边条件与目标节点条件）求值为 TRUE 的路径；
2. *任意非否* BFS：允许 TRUE/UNKNOWN，按 (跳数, 未知条件数) 字典序取最优路径。

于是节点状态为：已知可达 ``reachable``、仅条件未知可达 ``condition_unknown``、
生产不可达 ``unreachable``（另附 dev 路径备注，证明“锁文件里存在但生产不可达”）。
循环依赖由 visited/前驱表天然处理，不会死循环。
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Optional

from . import conditions
from .errors import E_EDGE_UNRESOLVED, E_SCHEMA, InputError
from .models import Version, VersionRange, parse_range
from .packages import AliasMap, PackageKey

ROOT_ID = "@root"
PRODUCTION_SCOPES = ("production", "runtime")


@dataclass(frozen=True)
class Node:
    id: str
    key: PackageKey
    version: Version
    condition: object = None  # 原始条件表达式，None 表示无条件


@dataclass(frozen=True)
class Edge:
    from_id: Optional[str]       # None 表示根
    to_id: str
    requirement: VersionRange
    requirement_raw: object
    scope: str
    condition: object
    index: int


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    # canonical 包字符串 -> 节点 id 列表（分叉时多个）
    by_canonical: dict[str, list[str]] = field(default_factory=dict)
    root_name: str = "root"

    # ---- 构造 ----
    @staticmethod
    def build(lockfile: dict, aliases: AliasMap) -> "Graph":
        if not isinstance(lockfile, dict):
            raise InputError(E_SCHEMA, "lockfile 必须是对象")
        graph = Graph(root_name=str(lockfile.get("root", {}).get("name", "root")))
        raw_nodes = lockfile.get("packages", [])
        if not isinstance(raw_nodes, list):
            raise InputError(E_SCHEMA, "lockfile.packages 必须是列表")
        for i, item in enumerate(raw_nodes):
            if not isinstance(item, dict):
                raise InputError(
                    E_SCHEMA, "packages 每项必须是对象",
                    context=f"lockfile.packages[{i}]",
                )
            if "package" not in item or "version" not in item:
                raise InputError(
                    E_SCHEMA,
                    "packages 每项需要 package 与 version 字段",
                    context=f"lockfile.packages[{i}]",
                )
            key = aliases.resolve(PackageKey.parse(item["package"]))
            version = Version.parse(item["version"])
            node_id = str(item.get("id") or f"{key.canonical()}@{version}")
            if node_id in graph.nodes:
                raise InputError(
                    E_SCHEMA,
                    f"节点 id {node_id!r} 重复（同一包多版本请显式指定不同 id）",
                    context=f"lockfile.packages[{i}]",
                )
            node = Node(node_id, key, version, item.get("condition"))
            graph.nodes[node_id] = node
            graph.by_canonical.setdefault(key.canonical(), []).append(node_id)

        raw_edges = lockfile.get("edges", [])
        if not isinstance(raw_edges, list):
            raise InputError(E_SCHEMA, "lockfile.edges 必须是列表")
        for i, item in enumerate(raw_edges):
            if not isinstance(item, dict) or "to" not in item:
                raise InputError(
                    E_SCHEMA,
                    "edges 每项需要 from(可空) 与 to 字段",
                    context=f"lockfile.edges[{i}]",
                )
            from_id = item.get("from")
            if from_id is not None and from_id not in graph.nodes:
                raise InputError(
                    E_SCHEMA,
                    f"边的起点节点 {from_id!r} 不存在",
                    context=f"lockfile.edges[{i}].from",
                )
            to_id = str(item["to"])
            if to_id not in graph.nodes:
                raise InputError(
                    E_SCHEMA,
                    f"边的终点节点 {to_id!r} 不存在",
                    context=f"lockfile.edges[{i}].to",
                )
            requirement = parse_range(item.get("requirement", "*"))
            target = graph.nodes[to_id]
            if not requirement.contains(target.version):
                raise InputError(
                    E_EDGE_UNRESOLVED,
                    f"边 {from_id or ROOT_ID} -> {to_id} 的要求 "
                    f"{item.get('requirement')!r} 不包含锁定版本 {target.version}",
                    context=f"lockfile.edges[{i}]",
                )
            scope = str(item.get("scope", "production"))
            graph.edges.append(
                Edge(
                    from_id=from_id,
                    to_id=to_id,
                    requirement=requirement,
                    requirement_raw=item.get("requirement", "*"),
                    scope=scope,
                    condition=item.get("condition"),
                    index=i,
                )
            )
        return graph

    # ---- 邻接 ----
    def adjacency(self, scopes: Optional[tuple[str, ...]] = None) -> dict:
        adj: dict[str, list[Edge]] = {}
        for edge in self.edges:
            if scopes is not None and edge.scope not in scopes:
                continue
            adj.setdefault(edge.from_id or ROOT_ID, []).append(edge)
        return adj

    def _shortest(
        self,
        target_id: str,
        context: dict[str, str],
        scopes: tuple[str, ...],
        known_only: bool,
    ) -> Optional[tuple[int, int, list[Edge]]]:
        """Dijkstra，代价 = (跳数, 未知条件数)。返回 (hops, unknowns, edges)。"""
        adj = self.adjacency(scopes)
        # (hops, unknowns, node_id)；堆中节点首次弹出即最优（字典序代价）
        heap: list[tuple[int, int, str]] = [(0, 0, ROOT_ID)]
        best: dict[str, tuple[int, int]] = {ROOT_ID: (0, 0)}
        pred: dict[str, Edge] = {}
        while heap:
            hops, unknowns, cur = heapq.heappop(heap)
            if best.get(cur) != (hops, unknowns):
                continue
            if cur == target_id:
                chain: list[Edge] = []
                back = cur
                while back != ROOT_ID:
                    edge = pred[back]
                    chain.append(edge)
                    back = edge.from_id or ROOT_ID
                chain.reverse()
                return hops, unknowns, chain
            for edge in adj.get(cur, ()):
                tri_edge = conditions.evaluate(edge.condition, context)
                if tri_edge is conditions.FALSE:
                    continue
                node = self.nodes[edge.to_id]
                tri_node = conditions.evaluate(node.condition, context)
                if tri_node is conditions.FALSE:
                    continue
                if known_only and (
                    tri_edge is not conditions.TRUE
                    or tri_node is not conditions.TRUE
                ):
                    continue
                add_unknown = int(tri_edge is conditions.UNKNOWN) + int(
                    tri_node is conditions.UNKNOWN
                )
                cand = (hops + 1, unknowns + add_unknown)
                if cand < best.get(edge.to_id, (10**9, 10**9)):
                    best[edge.to_id] = cand
                    pred[edge.to_id] = edge
                    heapq.heappush(heap, (*cand, edge.to_id))
        return None

    def _edge_truth(self, edge: Edge, context: dict[str, str]) -> str:
        tri = conditions.evaluate(edge.condition, context)
        return _truth_name(tri)

    def _node_truth(self, node: Node, context: dict[str, str]) -> str:
        return _truth_name(conditions.evaluate(node.condition, context))

    def evidence(
        self, node_id: str, context: dict[str, str]
    ) -> dict:
        """生成单个节点的可达状态与证据链。"""
        known = self._shortest(
            node_id, context, PRODUCTION_SCOPES, known_only=True
        )
        if known is not None:
            hops, unknowns, chain = known
            return {
                "status": "reachable",
                "hops": hops,
                "unknown_conditions": unknowns,
                "path": self._format_path(chain, context),
            }
        any_path = self._shortest(
            node_id, context, PRODUCTION_SCOPES, known_only=False
        )
        if any_path is not None:
            hops, unknowns, chain = any_path
            return {
                "status": "condition_unknown",
                "hops": hops,
                "unknown_conditions": unknowns,
                "path": self._format_path(chain, context),
            }
        result = {
            "status": "unreachable",
            "hops": None,
            "unknown_conditions": None,
            "path": [],
        }
        # 备注：是否仅能通过非生产 scope 到达（锁文件存在但生产不可达）
        all_scopes = tuple(sorted({e.scope for e in self.edges}))
        dev_path = self._shortest(
            node_id, context, all_scopes, known_only=False
        )
        if dev_path is not None:
            _, _, chain = dev_path
            result["note"] = "locked_but_not_production_reachable"
            result["non_production_path"] = self._format_path(chain, context)
        return result

    def _format_path(self, chain: list[Edge], context: dict[str, str]) -> list[dict]:
        out = []
        for edge in chain:
            node = self.nodes[edge.to_id]
            out.append(
                {
                    "from": edge.from_id or ROOT_ID,
                    "to": edge.to_id,
                    "package": node.key.canonical(),
                    "version": str(node.version),
                    "requirement": _stringify_raw(edge.requirement_raw),
                    "scope": edge.scope,
                    "edge_condition_truth": self._edge_truth(edge, context),
                    "node_condition_truth": self._node_truth(node, context),
                }
            )
        return out

    def reachability_map(self, context: dict[str, str]) -> dict[str, dict]:
        return {nid: self.evidence(nid, context) for nid in self.nodes}


def _truth_name(tri) -> str:
    if tri is conditions.TRUE:
        return "true"
    if tri is conditions.FALSE:
        return "false"
    return "unknown"


def _stringify_raw(raw) -> str:
    if isinstance(raw, str):
        return raw
    import json

    return json.dumps(raw, sort_keys=True, ensure_ascii=False)
