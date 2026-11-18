"""CLI 端到端测试：两个规定入口、退出码、错误处理与样例集断言。

所有临时文件都写在项目 .runtime-tmp/ 下，不访问网络。
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
TMP = ROOT / ".runtime-tmp" / "cli-tests"


class TestCliEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TMP.mkdir(parents=True, exist_ok=True)
        # 确保样例为最新
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "build_examples.py")],
            cwd=ROOT, check=True,
            capture_output=True, text=True,
        )

    def _run_cli(self, input_path: Path, output_path: Path):
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", str(input_path), "--output", str(output_path)],
            cwd=ROOT, capture_output=True, text=True,
        )
        return proc

    def test_full_examples_pipeline_and_concrete_assertions(self):
        out = TMP / "result.json"
        proc = self._run_cli(EXAMPLES / "cases.json", out)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["case_count"], 9)
        by_id = {r["id"]: r for r in data["results"]}

        # 01 预发布边界：受影响且升级到 pre.1（正式版 1.0.0 被 <1.0.0 约束挡住）
        c1 = by_id["01-prerelease-boundary"]
        self.assertEqual(
            c1["vulnerability_report"]["counts"]["affected_reachable"], 1
        )
        up1 = c1["upgrade"]
        self.assertEqual(up1["status"], "optimal")
        self.assertEqual(up1["selection"][0]["version"], "1.0.0-pre.1")

        # 02 分叉：keep_fork 下两个节点独立升级，恰好 2 次变更
        c2 = by_id["02-forked-versions"]
        self.assertEqual(c2["upgrade"]["objective"]["changed_packages"], 2)
        self.assertEqual(
            sorted(s["version"] for s in c2["upgrade"]["selection"]
                   if s["package"] == "pypi:core"),
            ["1.0.0", "2.1.0"],
        )

        # 03 菱形：只升级 net 一个包
        c3 = by_id["03-diamond-minimal-change"]
        self.assertEqual(c3["upgrade"]["objective"]["changed_packages"], 1)
        self.assertEqual(
            [s["version"] for s in c3["upgrade"]["selection"]
             if s["changed"]][0],
            "1.2.0",
        )

        # 04 循环：证据链可达，升级成功
        c4 = by_id["04-cycle"]
        crypto = [s for s in c4["upgrade"]["selection"]
                  if s["package"] == "pypi:crypto"][0]
        self.assertEqual(crypto["version"], "1.1.0")

        # 05 回归：安全岛 1.3.0
        c5 = by_id["05-regression-reintroduced"]
        leg = [s for s in c5["upgrade"]["selection"]
               if s["package"] == "pypi:legacy"][0]
        self.assertEqual(leg["version"], "1.3.0")

        # 06 不可解：给出反例约束
        c6 = by_id["06-unsat-upgrade"]
        self.assertEqual(c6["upgrade"]["status"], "unsat")
        self.assertTrue(c6["upgrade"]["unsatisfiable_constraints"])
        self.assertTrue(c6["upgrade"]["stats"]["mus_minimality_checked"])

        # 07 三态计数
        c7 = by_id["07-reachability-states"]
        counts = c7["vulnerability_report"]["counts"]
        self.assertEqual(counts["affected_reachable"], 1)
        self.assertEqual(counts["affected_condition_unknown"], 1)
        self.assertEqual(counts["affected_unreachable"], 2)
        self.assertEqual(counts["platform_inapplicable"], 1)
        # dev-only 节点的证据必须显式标注生产不可达
        dev_ev = c7["reachability"]["pypi:devtool@1.0.0"]
        self.assertEqual(dev_ev["status"], "unreachable")
        self.assertEqual(dev_ev["note"],
                         "locked_but_not_production_reachable")

        # 08 别名归并 + 生态隔离：两个生态分别可升级，不混合
        c8 = by_id["08-alias-and-ecosystem-isolation"]
        self.assertEqual(c8["aliases"]["pypi:json_utils"],
                         "pypi:json-utils")
        sel8 = {s["package"]: s["version"]
                for s in c8["upgrade"]["selection"]}
        self.assertEqual(sel8["npm:utils"], "2.0.0")
        self.assertEqual(sel8["pypi:json-utils"], "1.0.0")
        self.assertNotIn("npm:json-utils", sel8)  # 生态不同没有被归并

        # 09 纯约束冲突：MUS 恰为两条互相矛盾的显式约束
        c9 = by_id["09-unsat-constraint-conflict"]
        mus9 = {c["id"] for c in c9["upgrade"]["unsatisfiable_constraints"]}
        self.assertEqual(mus9, {"C_UPGRADE_0", "C_UPGRADE_1"})

    def test_missing_input_returns_exit_code_2(self):
        out = TMP / "missing-out.json"
        proc = self._run_cli(TMP / "no-such-file.json", out)
        self.assertEqual(proc.returncode, 2)
        err = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(err["error"]["error_code"], "E1001")

    def test_invalid_json_returns_exit_code_2(self):
        bad = TMP / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        out = TMP / "bad-out.json"
        proc = self._run_cli(bad, out)
        self.assertEqual(proc.returncode, 2)
        err = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(err["error"]["error_code"], "E1002")

    def test_per_case_error_does_not_abort_batch(self):
        batch = {
            "cases": [
                {"id": "good",
                 "registry": {"inline": {"packages": [
                     {"package": "pypi:x", "candidates": ["1.0.0"]}]}},
                 "lockfile": {
                     "root": {"name": "r"},
                     "packages": [{"package": "pypi:x",
                                   "version": "1.0.0"}],
                     "edges": [{"from": None, "to": "pypi:x@1.0.0",
                                "requirement": "*",
                                "scope": "production"}]},
                 "advisories": [], "upgrade": {}},
                {"id": "broken",
                 "lockfile": {"root": {"name": "r"},
                              "packages": [{"package": "pypi:y",
                                            "version": "bad-version"}],
                              "edges": []}},
            ]
        }
        in_path = TMP / "batch.json"
        in_path.write_text(json.dumps(batch), encoding="utf-8")
        out = TMP / "batch-out.json"
        proc = self._run_cli(in_path, out)
        self.assertEqual(proc.returncode, 0)  # 批处理整体成功
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["results"][0]["id"], "good")
        self.assertEqual(data["results"][1]["status"], "error")
        self.assertEqual(data["results"][1]["error"]["error_code"],
                         "E1004")

    def test_unittest_discover_collects_all_modules(self):
        # 用 TestLoader.discover 只收集不执行，验证题目规定的
        # ``unittest discover -s tests`` 入口能发现全部测试模块（避免递归执行）
        proc = subprocess.run(
            [sys.executable, "-c",
             "import unittest,json;"
             "s=unittest.TestLoader().discover('tests');"
             "print(json.dumps(s.countTestCases()))"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertGreaterEqual(int(proc.stdout.strip()), 30)
        # 再显式校验六个测试模块都能被独立加载
        proc2 = subprocess.run(
            [sys.executable, "-c",
             "import unittest;"
             "names=['test_versions','test_packages_conditions',"
             "'test_graph_advisories','test_solver','test_registry',"
             "'test_cli'];"
             "[unittest.TestLoader().loadTestsFromName('tests.'+n) "
             "for n in names];print('LOADED')"],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc2.returncode, 0, proc2.stderr)
        self.assertIn("LOADED", proc2.stdout)


if __name__ == "__main__":
    unittest.main()
