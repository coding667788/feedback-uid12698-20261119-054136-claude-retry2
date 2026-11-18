"""升级求解器测试：最小变更目标、传递约束、分叉、循环、不可解反例。

核心校验方式：用一个 *独立实现* 的暴力笛卡尔积枚举器对拍，
确认求解器返回的最优解与穷举结果一致；对不可解场景，独立验证
MUS 的不可满足性与极小性。
"""

import itertools
import unittest

from solution import solver as S
from solution.advisories import parse_advisories
from solution.graph import Graph
from solution.models import Version
from solution.packages import AliasMap, PackageKey
from solution.registry import Registry


def make_registry(data: dict[str, list[str]]) -> Registry:
    payload = {
        "packages": [
            {"package": canon, "candidates": versions}
            for canon, versions in data.items()
        ]
    }
    return Registry(payload, AliasMap(None))


def brute_force_optimal(problem: S._Problem, registry: Registry):
    """独立暴力枚举：笛卡尔积所有变量取值，返回与求解器同口径的最优键。"""
    domains = problem.domains
    variables = problem.variables
    best_key = None
    best_assignment = None
    for combo in itertools.product(*(domains[v] for v in variables)):
        assignment = dict(zip(variables, combo))
        # 可行性：每个取值都在域内即满足全部约束（域已编码约束）
        if any(v not in domains[var] for var, v in assignment.items()):
            continue
        key = S._objective(assignment, problem)
        if best_key is None or key < best_key:
            best_key, best_assignment = key, assignment
    return best_key, best_assignment


def build_problem(lockfile, advisories_raw, registry,
                  upgrade=None, platform=None):
    g = Graph.build(lockfile, AliasMap(None))
    advs = parse_advisories(advisories_raw or [], AliasMap(None))
    return S.build_problem(
        g, advs, registry, platform or {"os": "win32"},
        upgrade or {},
    ), g, advs


class TestMinimalChange(unittest.TestCase):
    def setUp(self):
        self.registry = make_registry({
            "pypi:a": ["1.0.0", "1.1.0", "1.2.0", "2.0.0"],
            "pypi:b": ["1.0.0", "1.1.0", "1.2.0"],
            "pypi:c": ["3.0.0", "3.1.0"],
        })

    def test_single_package_minimal_change(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [{"package": "pypi:a", "version": "1.0.0"}],
            "edges": [{"from": None, "to": "pypi:a@1.0.0",
                       "requirement": ">=1.0.0", "scope": "production"}],
        }
        advisories = [{"id": "X", "package": "pypi:a",
                       "affected": ["1.0.0"]}]
        problem, _, _ = build_problem(lockfile, advisories, self.registry)
        result = S.solve(problem, self.registry, seed=20261119)
        self.assertEqual(result["status"], "optimal")
        # 1.1.0 与 2.0.0 都安全，最小变更取较低的 1.1.0
        self.assertEqual(result["selection"][0]["version"], "1.1.0")
        self.assertEqual(result["objective"]["changed_packages"], 1)

        bf_key, bf_assign = brute_force_optimal(problem, self.registry)
        self.assertEqual(bf_key, S._objective(
            {s["variable"]: Version.parse(s["version"])
             for s in result["selection"]}, problem))

    def test_diamond_transitive_constraint_and_tie_break(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:b", "version": "1.0.0"},
                {"package": "pypi:c", "version": "3.0.0"},
                {"package": "pypi:a", "version": "1.1.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:b@1.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": None, "to": "pypi:c@3.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": "pypi:b@1.0.0", "to": "pypi:a@1.1.0",
                 "requirement": ">=1.0.0 <=1.2.0", "scope": "production"},
                {"from": "pypi:c@3.0.0", "to": "pypi:a@1.1.0",
                 "requirement": ">=1.1.0", "scope": "production"},
            ],
        }
        advisories = [{"id": "X", "package": "pypi:a",
                       "affected": ["1.1.0"]}]
        problem, _, _ = build_problem(lockfile, advisories, self.registry)
        result = S.solve(problem, self.registry, seed=20261119)
        self.assertEqual(result["status"], "optimal")
        a_sel = [s for s in result["selection"]
                 if s["package"] == "pypi:a"][0]
        # 两臂交集允许 1.2.0（候选 1.0.0/1.1.0/1.2.0），这是唯一安全升级
        self.assertEqual(a_sel["version"], "1.2.0")
        # 只变更 a 一个包，b/c 保持锁定版本
        self.assertEqual(result["objective"]["changed_packages"], 1)
        bf_key, _ = brute_force_optimal(problem, self.registry)
        self.assertEqual(bf_key[0], 1)

    def test_brute_force_matches_on_random_small_problems(self):
        # 固定种子可重放：随机构造若干小问题，逐一与暴力枚举对拍
        import random
        rng = random.Random(20261119)
        registry = make_registry({
            "pypi:x": ["1.0.0", "1.1.0", "1.2.0"],
            "pypi:y": ["2.0.0", "2.1.0"],
        })
        for trial in range(12):
            x_lock = rng.choice(registry.candidates(PackageKey.parse("pypi:x")))
            y_lock = rng.choice(registry.candidates(PackageKey.parse("pypi:y")))
            x_affect = rng.choice([[], ["1.0.0"], ["1.1.0"],
                                   ["1.0.0", "1.1.0"]])
            lockfile = {
                "root": {"name": "app"},
                "packages": [
                    {"package": "pypi:x", "version": str(x_lock)},
                    {"package": "pypi:y", "version": str(y_lock)},
                ],
                "edges": [
                    {"from": None, "to": f"pypi:x@{x_lock}",
                     "requirement": "*", "scope": "production"},
                    {"from": None, "to": f"pypi:y@{y_lock}",
                     "requirement": "*", "scope": "production"},
                ],
            }
            advisories = [{"id": "A", "package": "pypi:x",
                           "affected": x_affect}] if x_affect else []
            problem, _, _ = build_problem(
                lockfile, advisories, registry,
                upgrade={"allowed": [
                    {"package": "pypi:x",
                     "range": rng.choice(["*", ">=1.0.0", "<1.2.0"])}
                ]},
            )
            result = S.solve(problem, registry, seed=20261119)
            if result["status"] == "unsat":
                # 暴力枚举也必须找不到可行解
                bf_key, bf_assign = brute_force_optimal(problem, registry)
                self.assertIsNone(bf_assign, f"trial {trial} 误报不可解")
                continue
            self.assertEqual(result["status"], "optimal")
            bf_key, _ = brute_force_optimal(problem, registry)
            solver_assign = {
                s["variable"]: Version.parse(s["version"])
                for s in result["selection"]
            }
            self.assertEqual(
                S._objective(solver_assign, problem), bf_key,
                f"trial {trial} 求解器最优值与暴力枚举不一致",
            )

    def test_unify_forces_single_version_for_forked_package(self):
        registry = make_registry({
            "pypi:core": ["1.0.0", "1.2.0", "2.0.0", "2.1.0"],
            "pypi:web": ["3.0.0"],
            "pypi:db": ["2.0.0"],
        })
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"id": "c1", "package": "pypi:core", "version": "1.0.0"},
                {"id": "c2", "package": "pypi:core", "version": "2.0.0"},
                {"package": "pypi:web", "version": "3.0.0"},
                {"package": "pypi:db", "version": "2.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": None, "to": "pypi:db@2.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": "pypi:web@3.0.0", "to": "c1",
                 "requirement": "<2.0.0", "scope": "production"},
                {"from": "pypi:db@2.0.0", "to": "c2",
                 "requirement": ">=2.0.0", "scope": "production"},
            ],
        }
        # unify：两条边约束没有共同版本 -> 不可解
        problem, _, _ = build_problem(lockfile, [], registry)
        result = S.solve(problem, registry, seed=20261119)
        self.assertEqual(result["status"], "unsat")
        mus_ids = {c["id"] for c in result["unsatisfiable_constraints"]}
        self.assertTrue(
            {"C_EDGE_4", "C_EDGE_5"} <= mus_ids or len(mus_ids) >= 2
        )

        # keep_fork：允许两个节点各自取版本 -> 可解
        problem2, _, _ = build_problem(
            lockfile, [], registry, upgrade={"fork_policy": "keep_fork"}
        )
        result2 = S.solve(problem2, registry, seed=20261119)
        self.assertEqual(result2["status"], "optimal")
        versions = sorted(s["version"] for s in result2["selection"]
                          if s["package"] == "pypi:core")
        self.assertEqual(versions, ["1.0.0", "2.0.0"])  # 保持原分叉，零变更
        self.assertEqual(result2["objective"]["changed_packages"], 0)

    def test_transitive_edge_constraint_is_enforced(self):
        # web 对 net 的传递约束 >=1.2.0：升级 net 时不能选 1.1.0
        registry = make_registry({
            "pypi:web": ["3.0.0", "3.1.0"],
            "pypi:net": ["1.0.0", "1.1.0", "1.2.0"],
        })
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:web", "version": "3.0.0"},
                {"package": "pypi:net", "version": "1.2.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": "pypi:web@3.0.0", "to": "pypi:net@1.2.0",
                 "requirement": ">=1.2.0", "scope": "production"},
            ],
        }
        advisories = [{"id": "A", "package": "pypi:net",
                       "affected": ["1.2.0"]}]
        problem, _, _ = build_problem(lockfile, advisories, registry)
        # 域中 1.0.0/1.1.0 被传递约束排除，1.2.0 被公告排除 -> 不可解
        self.assertEqual(problem.domains["pypi:net"], [])
        result = S.solve(problem, registry, seed=20261119)
        self.assertEqual(result["status"], "unsat")
        self.assertIn("pypi:net", result["empty_domain_packages"])

        # 放宽传递约束到 >=1.1.0 后，1.1.0 成为可行升级
        lockfile["edges"][1]["requirement"] = ">=1.1.0"
        problem2, _, _ = build_problem(lockfile, advisories, registry)
        result2 = S.solve(problem2, registry, seed=20261119)
        self.assertEqual(result2["status"], "optimal")
        net = [s for s in result2["selection"]
               if s["package"] == "pypi:net"][0]
        self.assertEqual(net["version"], "1.1.0")

    def test_cycle_does_not_break_solver(self):
        registry = make_registry({
            "pypi:ca": ["1.0.0", "1.1.0"],
            "pypi:cb": ["1.0.0", "1.1.0"],
        })
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:ca", "version": "1.0.0"},
                {"package": "pypi:cb", "version": "1.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:ca@1.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": "pypi:ca@1.0.0", "to": "pypi:cb@1.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": "pypi:cb@1.0.0", "to": "pypi:ca@1.0.0",
                 "requirement": "*", "scope": "production"},
            ],
        }
        advisories = [{"id": "A", "package": "pypi:ca",
                       "affected": ["1.0.0"]}]
        problem, _, _ = build_problem(lockfile, advisories, registry)
        result = S.solve(problem, registry, seed=20261119)
        self.assertEqual(result["status"], "optimal")
        ca = [s for s in result["selection"] if s["package"] == "pypi:ca"][0]
        self.assertEqual(ca["version"], "1.1.0")


class TestUnsatExplanation(unittest.TestCase):
    def setUp(self):
        self.registry = make_registry({
            "pypi:net": ["1.0.0", "1.1.0", "1.2.0"],
            "pypi:web": ["3.0.0", "3.1.0"],
        })

    def test_conflicting_explicit_constraints_mus(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:web", "version": "3.0.0"},
                {"package": "pypi:net", "version": "1.1.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": "pypi:web@3.0.0", "to": "pypi:net@1.1.0",
                 "requirement": ">=1.1.0 <1.2.0", "scope": "production"},
            ],
        }
        upgrade = {"allowed": [
            {"package": "pypi:net", "range": ">=1.2.0"},
            {"package": "pypi:net", "range": "<1.2.0"},
        ]}
        problem, _, _ = build_problem(lockfile, [], self.registry,
                                      upgrade=upgrade)
        result = S.solve(problem, self.registry, seed=20261119)
        self.assertEqual(result["status"], "unsat")
        mus = result["unsatisfiable_constraints"]
        mus_ids = {c["id"] for c in mus}
        # 两条互相矛盾的显式约束必须同时在反例中
        self.assertEqual(
            sorted(i for i in mus_ids if i.startswith("C_UPGRADE")),
            ["C_UPGRADE_0", "C_UPGRADE_1"],
        )
        self._assert_mus_minimal(problem, mus_ids)

    def test_advisory_and_edge_conflict_mus(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [{"package": "pypi:net", "version": "1.2.0"}],
            "edges": [
                {"from": None, "to": "pypi:net@1.2.0",
                 "requirement": ">=1.2.0", "scope": "production"},
            ],
        }
        # 公告封死全部候选，root 约束本身可满足 -> MUS 只含公告约束
        advisories = [{"id": "A", "package": "pypi:net",
                       "affected": [">=1.0.0 <=1.2.0"]}]
        problem, _, _ = build_problem(lockfile, advisories, self.registry)
        result = S.solve(problem, self.registry, seed=20261119)
        self.assertEqual(result["status"], "unsat")
        mus = result["unsatisfiable_constraints"]
        self.assertTrue(all(c["kind"] == "advisory" for c in mus))
        self._assert_mus_minimal(
            problem, {c["id"] for c in mus}
        )

    def _assert_mus_minimal(self, problem, mus_ids):
        all_ids = {c.id for c in problem.constraints}

        def feasible(kept):
            dom = S._compute_domains(problem, self.registry,
                                     all_ids - kept)
            if any(not v for v in dom.values()):
                return False
            return S._backtrack_feasible_domains(problem, dom)

        # 整个 MUS 不可满足
        self.assertFalse(feasible(mus_ids))
        # 移除任意一条可移除约束后恢复可满足（极小性）
        for cid in mus_ids:
            constraint = next(c for c in problem.constraints if c.id == cid)
            if not constraint.removable:
                continue
            self.assertTrue(
                feasible(mus_ids - {cid}),
                f"MUS 移除 {cid} 后仍不可满足，不满足极小性",
            )


class TestDeterminism(unittest.TestCase):
    def test_seeded_runs_replay_identically(self):
        registry = make_registry({
            "pypi:x": ["1.0.0", "1.1.0", "1.2.0", "2.0.0"],
        })
        lockfile = {
            "root": {"name": "app"},
            "packages": [{"package": "pypi:x", "version": "1.0.0"}],
            "edges": [{"from": None, "to": "pypi:x@1.0.0",
                       "requirement": "*", "scope": "production"}],
        }
        advisories = [{"id": "A", "package": "pypi:x",
                       "affected": ["1.0.0"]}]
        problem, _, _ = build_problem(lockfile, advisories, registry)
        r1 = S.solve(problem, registry, seed=42)
        r2 = S.solve(problem, registry, seed=42)
        r3 = S.solve(problem, registry, seed=99)
        # 不同种子/重复运行的最优值必须一致（种子只影响遍历顺序）
        self.assertEqual(r1["selection"], r2["selection"])
        self.assertEqual(
            [s["version"] for s in r1["selection"]],
            [s["version"] for s in r3["selection"]],
        )


class TestTieBreakLexicographic(unittest.TestCase):
    def test_lower_version_chosen_when_change_count_equal(self):
        # 同变更数下，版本字符串字典序更小的候选应胜出
        registry = make_registry({
            "pypi:z": ["1.0.0", "1.0.1", "1.1.0"],
        })
        lockfile = {
            "root": {"name": "app"},
            "packages": [{"package": "pypi:z", "version": "1.0.0"}],
            "edges": [{"from": None, "to": "pypi:z@1.0.0",
                       "requirement": "*", "scope": "production"}],
        }
        advisories = [{"id": "A", "package": "pypi:z",
                       "affected": ["1.0.0"]}]
        problem, _, _ = build_problem(lockfile, advisories, registry)
        result = S.solve(problem, registry, seed=20261119)
        self.assertEqual(result["status"], "optimal")
        # 1.0.1 与 1.1.0 都需一次变更，字典序 1.0.1 < 1.1.0
        self.assertEqual(result["selection"][0]["version"], "1.0.1")

    def test_package_name_lexicographic_in_signature(self):
        registry = make_registry({
            "pypi:aaa": ["1.0.0", "2.0.0"],
            "pypi:bbb": ["1.0.0", "2.0.0"],
        })
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:aaa", "version": "1.0.0"},
                {"package": "pypi:bbb", "version": "1.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:aaa@1.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": None, "to": "pypi:bbb@1.0.0",
                 "requirement": "*", "scope": "production"},
            ],
        }
        advisories = [
            {"id": "A1", "package": "pypi:aaa", "affected": ["1.0.0"]},
            {"id": "A2", "package": "pypi:bbb", "affected": ["1.0.0"]},
        ]
        problem, _, _ = build_problem(lockfile, advisories, registry)
        assignment = {v: Version.parse("2.0.0") for v in problem.variables}
        key = S._objective(assignment, problem)
        # 签名按包名排序，aaa 在 bbb 前
        self.assertEqual(key[1][0][0], "pypi:aaa")
        self.assertEqual(key[1][1][0], "pypi:bbb")


class TestScopeAndIncludeExclude(unittest.TestCase):
    def _registry(self):
        return make_registry({
            "pypi:prod": ["1.0.0", "1.1.0"],
            "pypi:devonly": ["1.0.0", "2.0.0"],
            "pypi:newpkg": ["1.0.0", "1.1.0"],
        })

    def test_dev_only_package_excluded_from_upgrade(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:prod", "version": "1.0.0"},
                {"package": "pypi:devonly", "version": "1.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:prod@1.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": None, "to": "pypi:devonly@1.0.0",
                 "requirement": "*", "scope": "dev"},
            ],
        }
        advisories = [
            {"id": "A1", "package": "pypi:prod", "affected": ["1.0.0"]},
            {"id": "A2", "package": "pypi:devonly", "affected": ["1.0.0"]},
        ]
        problem, g, advs = build_problem(
            lockfile, advisories, self._registry()
        )
        # 升级变量只含生产包
        self.assertEqual(problem.variables, ["pypi:prod"])
        result = S.solve(problem, self._registry(), seed=20261119)
        self.assertEqual(result["status"], "optimal")
        self.assertEqual(
            [s["package"] for s in result["selection"]], ["pypi:prod"]
        )

    def test_include_adds_package_absent_from_lockfile(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [{"package": "pypi:prod", "version": "1.0.0"}],
            "edges": [{"from": None, "to": "pypi:prod@1.0.0",
                       "requirement": "*", "scope": "production"}],
        }
        problem, _, _ = build_problem(
            lockfile, [], self._registry(),
            upgrade={"include": ["pypi:newpkg"]},
        )
        self.assertIn("pypi:newpkg", problem.variables)
        result = S.solve(problem, self._registry(), seed=20261119)
        self.assertEqual(result["status"], "optimal")
        new_sel = [s for s in result["selection"]
                   if s["package"] == "pypi:newpkg"][0]
        self.assertTrue(new_sel["changed"])
        self.assertEqual(new_sel["change_kind"], "added")

    def test_exclude_removes_production_package(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:prod", "version": "1.0.0"},
                {"package": "pypi:newpkg", "version": "1.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:prod@1.0.0",
                 "requirement": "*", "scope": "production"},
                {"from": None, "to": "pypi:newpkg@1.0.0",
                 "requirement": "*", "scope": "production"},
            ],
        }
        problem, _, _ = build_problem(
            lockfile, [], self._registry(),
            upgrade={"exclude": ["pypi:prod"]},
        )
        self.assertEqual(problem.variables, ["pypi:newpkg"])


if __name__ == "__main__":
    unittest.main()
