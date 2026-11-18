"""受约束的最小变更升级求解器与不可解反例。

求解目标（按优先级）：

1. 可行性：每个变量取 *输入有限候选集合* 中的一个版本，且
   - 默认 ``fork_policy=unify``：同一规范包全图只能选择一个版本；
     ``fork_policy=keep_fork`` 时，锁文件中已分叉的包允许按节点保留多版本；
   - 满足所有生效的传递版本约束（根依赖、边约束、用例显式 allowed）；
   - 避开全部已知受影响区间（平台条件未知按 ``unknown_policy`` 处理）。
2. 最小化 *变更包数量*（选中版本 != 唯一锁定版本即记一次变更；
   新增包与同一包锁定了多个版本的情况一律计入变更）。
3. 平局按 (包名字典序, 版本字符串字典序) 的有序序列打破。

实现采用小规模完整枚举（MRV 排序 + 前向检查 + 状态记忆），“最优”是穷举
验证的；访问状态数受 ``VISITED_NODE_CAP`` 保护，超出会在结果中显式报告，
绝不静默截断。无解时通过删除过滤给出 *极小不可满足约束子集*（MUS）：
移除其中任意一条可移除约束后，剩余约束恢复可满足。
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from . import conditions
from .errors import E_NO_CANDIDATES, E_SCHEMA, InputError
from .graph import PRODUCTION_SCOPES, Graph, ROOT_ID
from .models import Version, VersionRange, parse_range
from .packages import PackageKey
from .registry import Registry

VISITED_NODE_CAP = 200_000


@dataclass(frozen=True)
class Constraint:
    id: str
    variable: str               # 约束作用的求解变量
    package: str                # 变量对应的规范包字符串
    range: VersionRange
    kind: str                   # root | edge | upgrade | advisory
    removable: bool
    description: str
    source: dict


@dataclass
class _Problem:
    required: list[str]                                 # 规范包列表
    variables: list[str]                                # 求解变量列表
    domains: dict[str, list[Version]]
    constraints: list[Constraint]
    locked: dict[str, Version]                          # 唯一定版包 -> 版本
    multi_locked: set[str]
    new_packages: set[str]
    node_vars: dict[str, str]                           # node_id -> 变量
    var_nodes: dict[str, list[str]]                     # 变量 -> node_id
    var_locked: dict[str, Version]                      # 变量 -> 唯一锁定版本
    var_change_kind: dict[str, str]                     # 变量 -> 变更类型
    fork_policy: str


def _production_required(graph: Graph, context: dict[str, str]) -> set[str]:
    """生产可达（含条件未知）的包集合；dev-only 节点不算生产可达。"""
    required: set[str] = set()
    for node_id, node in graph.nodes.items():
        ev = graph.evidence(node_id, context)
        if ev["status"] in ("reachable", "condition_unknown"):
            required.add(node.key.canonical())
    return required


def _advisory_forbidden(advisories, context: dict[str, str],
                        unknown_policy: str) -> dict[str, VersionRange]:
    forbidden: dict[str, VersionRange] = {}
    for adv in advisories:
        tri = conditions.evaluate(adv.condition, context)
        if tri is conditions.FALSE:
            continue
        if tri is conditions.UNKNOWN and unknown_policy == "ignore":
            continue
        bucket = forbidden.setdefault(adv.key.canonical(), VersionRange([]))
        forbidden[adv.key.canonical()] = bucket.union(adv.affected)
    return forbidden


def build_problem(
    graph: Graph,
    advisories,
    registry: Registry,
    context: dict[str, str],
    upgrade: Optional[dict],
    unknown_policy: str = "exclude",
) -> _Problem:
    upgrade = upgrade or {}
    fork_policy = str(upgrade.get("fork_policy", "unify"))
    if fork_policy not in ("unify", "keep_fork"):
        raise InputError(
            E_SCHEMA,
            "upgrade.fork_policy 只能是 unify（默认，全图单版本）"
            "或 keep_fork（允许已分叉包多版本共存）",
        )
    explicit_allowed = _parse_explicit(upgrade.get("allowed", []))
    includes = {PackageKey.parse(p).canonical()
                for p in upgrade.get("include", [])}
    excludes = {PackageKey.parse(p).canonical()
                for p in upgrade.get("exclude", [])}
    if includes & excludes:
        raise InputError(
            E_SCHEMA,
            f"同一包不能同时出现在 include 与 exclude：{sorted(includes & excludes)}",
        )

    required = (_production_required(graph, context) | includes) - excludes
    if not required:
        raise InputError(
            E_SCHEMA, "升级问题为空：没有任何生产可达包且 include 为空"
        )

    # 锁定版本表
    locked_versions: dict[str, set[Version]] = {}
    for node in graph.nodes.values():
        locked_versions.setdefault(node.key.canonical(), set()).add(node.version)
    locked = {k: next(iter(v)) for k, v in locked_versions.items() if len(v) == 1}
    multi_locked = {k for k, v in locked_versions.items() if len(v) > 1}
    new_packages = {p for p in required if p not in locked_versions}

    # 变量划分：keep_fork 下已分叉包按节点 id 拆成独立变量
    node_vars: dict[str, str] = {}
    var_nodes: dict[str, list[str]] = {}
    for node_id, node in graph.nodes.items():
        canon = node.key.canonical()
        if canon not in required:
            continue
        if fork_policy == "keep_fork" and canon in multi_locked:
            var = f"{canon}#{node_id}"
            node_vars[node_id] = var
            var_nodes.setdefault(var, []).append(node_id)
        else:
            node_vars[node_id] = canon
            var_nodes.setdefault(canon, []).append(node_id)
    # include 引入但锁文件没有节点的新增包：建立规范包变量
    for canon in required:
        if canon not in {n.key.canonical() for n in graph.nodes.values()}:
            var_nodes.setdefault(canon, [])
    variables = sorted(var_nodes)

    def var_of_node(node_id: str) -> str:
        return node_vars[node_id]

    constraints: list[Constraint] = []
    # 1) 根依赖约束（生产 scope、条件非 False）
    for edge in graph.edges:
        if edge.from_id is not None or edge.scope not in PRODUCTION_SCOPES:
            continue
        target_canon = graph.nodes[edge.to_id].key.canonical()
        if target_canon not in required:
            continue
        if conditions.evaluate(edge.condition, context) is conditions.FALSE:
            continue
        var = var_of_node(edge.to_id)
        constraints.append(Constraint(
            id=f"C_ROOT_{edge.index}",
            variable=var,
            package=target_canon,
            range=edge.requirement,
            kind="root",
            removable=True,
            description=(
                f"根项目生产依赖 {target_canon} 要求 {_raw(edge.requirement_raw)}"
            ),
            source={"edge_index": edge.index, "from": ROOT_ID,
                    "to": edge.to_id},
        ))
    # 2) 传递边约束（源/目标包都在 required 中，条件非 False）
    for edge in graph.edges:
        if edge.from_id is None:
            continue
        src = graph.nodes[edge.from_id].key.canonical()
        dst = graph.nodes[edge.to_id].key.canonical()
        if src not in required or dst not in required:
            continue
        if conditions.evaluate(edge.condition, context) is conditions.FALSE:
            continue
        var = var_of_node(edge.to_id)
        constraints.append(Constraint(
            id=f"C_EDGE_{edge.index}",
            variable=var,
            package=dst,
            range=edge.requirement,
            kind="edge",
            removable=True,
            description=(
                f"{src} 传递依赖 {dst} 要求 {_raw(edge.requirement_raw)}"
            ),
            source={"edge_index": edge.index,
                    "from": edge.from_id, "to": edge.to_id},
        ))
    # 3) 用例显式 allowed：每条作为独立约束保留（不能提前求交，
    # 否则冲突约束会塌缩成一个空区间，丢失反例结构）
    upgrade_idx = 0
    for i, entry in enumerate(explicit_allowed):
        canon, vr = entry
        if canon not in required:
            continue
        for var in (v for v in variables
                    if v == canon or v.startswith(canon + "#")):
            constraints.append(Constraint(
                id=f"C_UPGRADE_{upgrade_idx}",
                variable=var,
                package=canon,
                range=vr,
                kind="upgrade",
                removable=True,
                description=f"升级请求显式约束 {canon} ∈ {vr}",
                source={"allowed_index": i},
            ))
            upgrade_idx += 1
    # 4) 公告禁用区间（不可作为 MUS 的删除对象——它是客观风险事实）
    forbidden = _advisory_forbidden(advisories, context, unknown_policy)
    adv_idx = 0
    for canon in sorted(forbidden):
        if canon not in required or forbidden[canon].is_empty:
            continue
        for var in (v for v in variables
                    if v == canon or v.startswith(canon + "#")):
            constraints.append(Constraint(
                id=f"C_ADV_{adv_idx}",
                variable=var,
                package=canon,
                range=forbidden[canon],
                kind="advisory",
                removable=False,
                description=f"{canon} 的已知受影响区间 {forbidden[canon]}（需避开）",
                source={"forbidden": True},
            ))
            adv_idx += 1

    # 变量级锁定版本与变更类型
    var_locked: dict[str, Version] = {}
    var_change_kind: dict[str, str] = {}
    for var in variables:
        canon = var.split("#", 1)[0]
        node_ids = var_nodes[var]
        node_versions = {graph.nodes[n].version for n in node_ids} if node_ids \
            else set()
        if len(node_versions) == 1:
            var_locked[var] = next(iter(node_versions))
        if canon in new_packages:
            var_change_kind[var] = "added"
        elif canon in multi_locked:
            var_change_kind[var] = (
                "deduplicated" if fork_policy == "unify" else "kept_fork"
            )
        else:
            var_change_kind[var] = "upgraded"

    problem = _Problem(
        required=sorted(required),
        variables=variables,
        domains={},
        constraints=constraints,
        locked=locked,
        multi_locked=multi_locked,
        new_packages=new_packages,
        node_vars=node_vars,
        var_nodes=var_nodes,
        var_locked=var_locked,
        var_change_kind=var_change_kind,
        fork_policy=fork_policy,
    )
    problem.domains = _compute_domains(problem, registry, set())
    return problem


def _parse_explicit(raw: list) -> list[tuple[str, VersionRange]]:
    """逐条解析 allowed，保留为独立 (包, 区间) 约束，不做提前合并。"""
    out: list[tuple[str, VersionRange]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or "package" not in item or "range" not in item:
            raise InputError(
                E_SCHEMA,
                "upgrade.allowed 每项需要 package 与 range",
                context=f"upgrade.allowed[{i}]",
            )
        canon = PackageKey.parse(item["package"]).canonical()
        out.append((canon, parse_range(item["range"])))
    return out


def _compute_domains(
    problem: _Problem, registry: Registry, disabled: set[str]
) -> dict[str, list[Version]]:
    domains: dict[str, list[Version]] = {}
    for var in problem.variables:
        canon = var.split("#", 1)[0]
        key = PackageKey.parse(canon)
        candidates = registry.candidates(key)
        if not candidates:
            raise InputError(
                E_NO_CANDIDATES,
                f"包 {canon} 在候选源中没有任何版本，无法求解",
            )
        allowed = VersionRange.all_versions()
        forbidden = VersionRange([])
        for c in problem.constraints:
            if c.variable != var or c.id in disabled:
                continue
            if c.kind == "advisory":
                forbidden = forbidden.union(c.range)
            else:
                allowed = allowed.intersection(c.range)
        domains[var] = allowed.difference(forbidden).filter_versions(candidates)
    return domains


# ---------------------------------------------------------------------------
# 枚举求解
# ---------------------------------------------------------------------------
def solve(
    problem: _Problem,
    registry: Registry,
    seed: Optional[int] = None,
) -> dict:
    domains = problem.domains
    empty = sorted(p for p in problem.variables if not domains[p])
    if empty:
        return _unsat_result(problem, registry, domains,
                             reason="empty_domain", empty_packages=empty)

    best: Optional[dict] = None
    best_key: Optional[tuple] = None
    visited: set[tuple] = set()
    stats = {"visited_states": 0, "cap_hit": False}
    order_rng = random.Random(None if seed is None else seed + 1)

    def viable_versions(var: str, assignment: dict) -> list[Version]:
        return [v for v in domains[var]
                if _consistent(var, v, assignment, problem)]

    def order_variables(remaining: list[str], assignment: dict) -> list[str]:
        scored = sorted(
            remaining, key=lambda p: (len(viable_versions(p, assignment)), p)
        )
        if seed is not None and len(scored) > 1:
            groups: dict[int, list[str]] = {}
            for p in scored:
                groups.setdefault(len(viable_versions(p, assignment)),
                                  []).append(p)
            result = []
            for size in sorted(groups):
                grp = groups[size]
                order_rng.shuffle(grp)
                result.extend(grp)
            scored = result
        return scored

    def dfs(assignment: dict[str, Version]) -> None:
        nonlocal best, best_key
        if stats["visited_states"] >= VISITED_NODE_CAP:
            stats["cap_hit"] = True
            return
        state = tuple(sorted((p, str(v)) for p, v in assignment.items()))
        if state in visited:
            return
        visited.add(state)
        stats["visited_states"] += 1

        remaining = [p for p in problem.variables if p not in assignment]
        if not remaining:
            key = _objective(assignment, problem)
            if best_key is None or key < best_key:
                best_key, best = key, dict(assignment)
            return
        if best_key is not None and _change_count(assignment, problem) > best_key[0]:
            return
        var = order_variables(remaining, assignment)[0]
        versions = viable_versions(var, assignment)
        if seed is not None:
            order_rng.shuffle(versions)
        for v in versions:
            assignment[var] = v
            if _forward_check(remaining[1:], assignment, problem, domains):
                dfs(assignment)
            del assignment[var]

    dfs({})

    if best is not None:
        return _optimal_result(problem, best, best_key, stats, len(visited))
    if stats["cap_hit"]:
        return {
            "status": "incomplete",
            "message": "枚举访问状态数达到上限，未取得可证明最优解",
            "stats": stats,
        }
    return _unsat_result(problem, registry, domains,
                         reason="constraint_conflict")


def _optimal_result(problem: _Problem, best: dict, best_key: tuple,
                    stats: dict, enumerated: int) -> dict:
    selection = []
    for canon in problem.required:
        vars_of = [v for v in problem.variables
                   if v == canon or v.startswith(canon + "#")]
        for var in vars_of:
            version = best[var]
            selection.append({
                "package": canon,
                "variable": var,
                "node_ids": problem.var_nodes.get(var, []),
                "version": str(version),
                "changed": _is_changed(var, version, problem),
                "change_kind": problem.var_change_kind.get(var, "upgraded"),
            })
    return {
        "status": "optimal",
        "fork_policy": problem.fork_policy,
        "selection": selection,
        "objective": {
            "changed_packages": best_key[0],
            "tie_breaker": [
                f"{item['package']}@{item['version']}"
                for item in selection if item["changed"]
            ],
        },
        "stats": {**stats, "enumerated_assignments": enumerated,
                  "complete": not stats["cap_hit"]},
    }


def _consistent(var: str, version: Version, assignment: dict,
                problem: _Problem) -> bool:
    for c in problem.constraints:
        if c.variable != var:
            continue
        if c.kind == "advisory":
            if c.range.contains(version):
                return False
        elif not c.range.contains(version):
            return False
    return True


def _forward_check(remaining: list[str], assignment: dict,
                   problem: _Problem, domains: dict) -> bool:
    return all(
        any(_consistent(o, v, assignment, problem) for v in domains[o])
        for o in remaining
    )


def _is_changed(var: str, version: Version, problem: _Problem) -> bool:
    # keep_fork 的分叉变量与各自节点的锁定版本比较；
    # 其余变量与唯一锁定版本比较；没有锁定版本（新增包）恒为变更
    locked = problem.var_locked.get(var)
    if locked is None:
        return True
    return locked != version


def _change_count(assignment: dict, problem: _Problem) -> int:
    return sum(1 for var, v in assignment.items()
               if _is_changed(var, v, problem))


def _objective(assignment: dict, problem: _Problem) -> tuple:
    changed = _change_count(assignment, problem)
    full_signature = tuple(
        sorted((var.split("#", 1)[0], str(assignment[var]))
               for var in problem.variables)
    )
    return (changed, full_signature)


def _raw(raw) -> str:
    import json

    return raw if isinstance(raw, str) else json.dumps(
        raw, sort_keys=True, ensure_ascii=False
    )


# ---------------------------------------------------------------------------
# 不可解反例：极小不可满足约束子集（删除过滤）
# ---------------------------------------------------------------------------
def _unsat_result(problem: _Problem, registry: Registry,
                  domains: dict, reason: str,
                  empty_packages: Optional[list[str]] = None) -> dict:
    removable = [c for c in problem.constraints if c.removable]

    def feasible_without(disabled: set[str]) -> bool:
        try:
            dom = _compute_domains(problem, registry, disabled)
        except InputError:
            return False
        if any(not v for v in dom.values()):
            return False
        # 域已按剩余约束重算，回溯只需在域内取值
        return _backtrack_feasible_domains(problem, dom)

    all_ids = {c.id for c in problem.constraints}

    def feasible_keeping(kept: set[str]) -> bool:
        """只保留 kept 中的约束时是否可满足。"""
        return feasible_without(all_ids - kept)

    # 删除过滤（deletion-based）+ 迭代最小化，保证得到 *极小* 不可满足子集：
    # 反复扫描当前保留集合，凡移除后仍不可满足的约束一律删除，
    # 直到一轮扫描没有任何删除为止（规模小，成本可接受）。
    kept = set(all_ids)
    changed = True
    while changed:
        changed = False
        for c in problem.constraints:
            if c.id not in kept or not c.removable:
                continue
            trial = kept - {c.id}
            if not feasible_keeping(trial):
                kept = trial
                changed = True
    mus_constraints = [c for c in problem.constraints if c.id in kept]

    # 极小性自检：MUS 中任意可移除约束被单独移除后必须恢复可满足
    for c in mus_constraints:
        if not c.removable:
            continue
        if not feasible_keeping(kept - {c.id}):
            raise RuntimeError(  # pragma: no cover
                f"MUS 极小性自检失败：{c.id}"
            )

    return {
        "status": "unsat",
        "reason": reason,
        "fork_policy": problem.fork_policy,
        "empty_domain_packages": empty_packages or [],
        "unsatisfiable_constraints": [
            {
                "id": c.id,
                "kind": c.kind,
                "package": c.package,
                "variable": c.variable,
                "description": c.description,
                "removable": c.removable,
            }
            for c in sorted(mus_constraints, key=lambda c: c.id)
        ],
        "domains": {
            var: [str(v) for v in domains[var]] for var in problem.variables
        },
        "stats": {"complete": True,
                  "mus_minimality_checked": True},
    }


def _backtrack_feasible_domains(problem: _Problem,
                                domains: dict[str, list[Version]]) -> bool:
    """只判定可满足性：域已包含全部生效约束，回溯只做域内取值。"""
    assignment: dict[str, Version] = {}

    def dfs() -> bool:
        remaining = [p for p in problem.variables if p not in assignment]
        if not remaining:
            return True
        # MRV：当前域最小的变量优先
        var = min(remaining, key=lambda p: (len(domains[p]), p))
        if not domains[var]:
            return False
        for v in domains[var]:
            assignment[var] = v
            if dfs():
                return True
            del assignment[var]
        return False

    return dfs()
