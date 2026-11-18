"""依赖图可达性与公告匹配测试。

覆盖：循环依赖不死循环、最短证据链、生产/dev 区分、条件三态、
多受影响区间（补丁回退再次引入）、平台不适用公告。
"""

import unittest

from solution.advisories import parse_advisories, match_graph
from solution.graph import Graph
from solution.packages import AliasMap


def edge(**kw):
    kw.setdefault("scope", "production")
    return kw


class TestGraphReachability(unittest.TestCase):
    def _build_cycle_graph(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:a", "version": "1.0.0"},
                {"package": "pypi:b", "version": "1.0.0"},
                {"package": "pypi:c", "version": "1.0.0"},
            ],
            "edges": [
                edge(**{"from": None, "to": "pypi:a@1.0.0",
                        "requirement": "^1.0.0"}),
                edge(**{"from": "pypi:a@1.0.0", "to": "pypi:b@1.0.0",
                        "requirement": ">=1.0.0"}),
                # 回边形成环
                edge(**{"from": "pypi:b@1.0.0", "to": "pypi:a@1.0.0",
                        "requirement": ">=1.0.0"}),
                edge(**{"from": "pypi:b@1.0.0", "to": "pypi:c@1.0.0",
                        "requirement": "^1.0.0"}),
            ],
        }
        return Graph.build(lockfile, AliasMap(None))

    def test_cycle_terminates_and_reaches(self):
        g = self._build_cycle_graph()
        ev_c = g.evidence("pypi:c@1.0.0", {"os": "win32"})
        self.assertEqual(ev_c["status"], "reachable")
        # 最短路径 root -> a -> b -> c，恰好 3 跳，绕环的更长路径不被选中
        self.assertEqual(ev_c["hops"], 3)
        self.assertEqual(
            [step["to"] for step in ev_c["path"]],
            ["pypi:a@1.0.0", "pypi:b@1.0.0", "pypi:c@1.0.0"],
        )

    def test_three_reachability_states(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:ok", "version": "1.0.0"},
                {"package": "pypi:maybe", "version": "1.0.0"},
                {"package": "pypi:no", "version": "1.0.0"},
                {"package": "pypi:devonly", "version": "1.0.0"},
            ],
            "edges": [
                edge(**{"from": None, "to": "pypi:ok@1.0.0",
                        "requirement": "*"}),
                edge(**{"from": "pypi:ok@1.0.0", "to": "pypi:maybe@1.0.0",
                        "requirement": "*",
                        "condition": {"attribute": "libc",
                                      "op": "==", "value": "glibc"}}),
                edge(**{"from": "pypi:ok@1.0.0", "to": "pypi:no@1.0.0",
                        "requirement": "*",
                        "condition": {"attribute": "os",
                                      "op": "==", "value": "linux"}}),
                edge(**{"from": None, "to": "pypi:devonly@1.0.0",
                        "requirement": "*", "scope": "dev"}),
            ],
        }
        g = Graph.build(lockfile, AliasMap(None))
        ctx = {"os": "win32"}
        self.assertEqual(g.evidence("pypi:ok@1.0.0", ctx)["status"],
                         "reachable")
        maybe = g.evidence("pypi:maybe@1.0.0", ctx)
        self.assertEqual(maybe["status"], "condition_unknown")
        self.assertEqual(maybe["unknown_conditions"], 1)
        self.assertEqual(maybe["hops"], 2)
        no = g.evidence("pypi:no@1.0.0", ctx)
        self.assertEqual(no["status"], "unreachable")
        dev = g.evidence("pypi:devonly@1.0.0", ctx)
        self.assertEqual(dev["status"], "unreachable")
        # 锁文件存在但生产不可达，必须有备注与 dev 证据，而不是当作生产可达
        self.assertEqual(dev["note"],
                         "locked_but_not_production_reachable")
        self.assertTrue(dev["non_production_path"])

    def test_false_condition_prunes_even_with_unknown_elsewhere(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:mid", "version": "1.0.0"},
                {"package": "pypi:leaf", "version": "1.0.0"},
            ],
            "edges": [
                edge(**{"from": None, "to": "pypi:mid@1.0.0",
                        "requirement": "*"}),
                edge(**{"from": "pypi:mid@1.0.0", "to": "pypi:leaf@1.0.0",
                        "requirement": "*",
                        "condition": {"all": [
                            {"attribute": "os", "op": "==",
                             "value": "linux"},
                            {"attribute": "libc", "op": "==",
                             "value": "glibc"},
                        ]}}),
            ],
        }
        g = Graph.build(lockfile, AliasMap(None))
        # 含 FALSE 的 all 整体为 FALSE，未知属性不能“救回”被否定的路径
        ev = g.evidence("pypi:leaf@1.0.0", {"os": "win32"})
        self.assertEqual(ev["status"], "unreachable")

    def test_shortest_path_prefers_fewer_unknowns_on_equal_hops(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"id": "x1", "package": "pypi:x", "version": "1.0.0"},
                {"id": "x2", "package": "pypi:x", "version": "1.1.0"},
            ],
            "edges": [
                # 直达但条件未知
                edge(**{"from": None, "to": "x1", "requirement": "*",
                        "condition": {"attribute": "libc", "op": "==",
                                      "value": "glibc"}}),
                # 同样一跳、条件确定
                edge(**{"from": None, "to": "x2", "requirement": "*"}),
            ],
        }
        g = Graph.build(lockfile, AliasMap(None))
        ev1 = g.evidence("x1", {"os": "win32"})
        ev2 = g.evidence("x2", {"os": "win32"})
        self.assertEqual(ev1["status"], "condition_unknown")
        self.assertEqual(ev2["status"], "reachable")
        self.assertEqual(ev1["hops"], ev2["hops"], 1)


class TestAdvisoryMatching(unittest.TestCase):
    def test_multi_interval_regression(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:leg", "version": "1.2.0"},
                {"package": "pypi:leg", "version": "1.3.0", "id": "leg-safe"},
            ],
            "edges": [
                edge(**{"from": None, "to": "pypi:leg@1.2.0",
                        "requirement": "*"}),
                edge(**{"from": None, "to": "leg-safe", "requirement": "*"}),
            ],
        }
        advisories = parse_advisories([
            {"id": "ADV-REG", "package": "pypi:leg",
             "affected": [">=1.0.0 <1.3.0", ">=2.0.0"]},
        ], AliasMap(None))
        g = Graph.build(lockfile, AliasMap(None))
        report = match_graph(g, advisories, {"os": "win32"})
        status = {f["node_id"]: f["status"] for f in report["findings"]}
        # 1.2.0 落在第一受影响区间；1.3.0 是两个区间之间的安全岛
        self.assertEqual(status["pypi:leg@1.2.0"], "affected_reachable")
        self.assertEqual(status["leg-safe"], "not_affected")

    def test_platform_conditional_advisory(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [{"package": "pypi:x", "version": "1.0.0"}],
            "edges": [edge(**{"from": None, "to": "pypi:x@1.0.0",
                              "requirement": "*"})],
        }
        advisories = parse_advisories([
            {"id": "ADV-LINUX", "package": "pypi:x",
             "affected": ["1.0.0"],
             "condition": {"attribute": "os", "op": "==",
                           "value": "linux"}},
            {"id": "ADV-UNKNOWN", "package": "pypi:x",
             "affected": ["1.0.0"],
             "condition": {"attribute": "libc", "op": "==",
                           "value": "glibc"}},
        ], AliasMap(None))
        g = Graph.build(lockfile, AliasMap(None))
        report = match_graph(g, advisories, {"os": "win32"})
        # 明确不适用
        self.assertEqual(
            report["platform_inapplicable"][0]["advisory_id"], "ADV-LINUX"
        )
        # 条件未知（默认 exclude 保守口径）仍计入受影响
        unknown = [f for f in report["findings"]
                   if f["advisory_id"] == "ADV-UNKNOWN"][0]
        self.assertEqual(unknown["status"], "affected_condition_unknown")

        # ignore 口径下条件未知公告被排除
        report_ignore = match_graph(
            g, advisories, {"os": "win32"}, unknown_policy="ignore"
        )
        self.assertEqual(
            [p["advisory_id"] for p in
             report_ignore["platform_inapplicable"]],
            ["ADV-LINUX", "ADV-UNKNOWN"],
        )

    def test_unreachable_vulnerability_not_counted_as_reachable(self):
        lockfile = {
            "root": {"name": "app"},
            "packages": [
                {"package": "pypi:prod", "version": "1.0.0"},
                {"package": "pypi:devonly", "version": "1.0.0"},
            ],
            "edges": [
                edge(**{"from": None, "to": "pypi:prod@1.0.0",
                        "requirement": "*"}),
                edge(**{"from": None, "to": "pypi:devonly@1.0.0",
                        "requirement": "*", "scope": "dev"}),
            ],
        }
        advisories = parse_advisories([
            {"id": "ADV-1", "package": "pypi:devonly",
             "affected": ["1.0.0"]},
        ], AliasMap(None))
        g = Graph.build(lockfile, AliasMap(None))
        report = match_graph(g, advisories, {"os": "win32"})
        finding = report["findings"][0]
        self.assertEqual(finding["status"], "affected_unreachable")
        self.assertEqual(finding["evidence"]["reachability"], "unreachable")
        self.assertEqual(report["counts"]["affected_reachable"], 0)
        self.assertEqual(report["counts"]["affected_unreachable"], 1)


if __name__ == "__main__":
    unittest.main()
