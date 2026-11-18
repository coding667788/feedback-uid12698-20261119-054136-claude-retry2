"""输入校验与错误码回归测试。"""

import unittest
from pathlib import Path

from solution.engine import run_case
from solution.errors import (
    E_ALIAS_CONFLICT,
    E_EDGE_UNRESOLVED,
    E_NO_CANDIDATES,
    E_SCHEMA,
    InputError,
)

BASE = Path(__file__).resolve().parent.parent


def minimal_case(**overrides):
    case = {
        "registry": {"inline": {"packages": [
            {"package": "pypi:x", "candidates": ["1.0.0", "1.1.0"]}]}},
        "lockfile": {
            "root": {"name": "app"},
            "packages": [{"package": "pypi:x", "version": "1.0.0"}],
            "edges": [{"from": None, "to": "pypi:x@1.0.0",
                       "requirement": "*", "scope": "production"}],
        },
        "advisories": [],
        "upgrade": {},
    }
    case.update(overrides)
    return case


class TestInputValidation(unittest.TestCase):
    def test_alias_cycle_error_code(self):
        case = minimal_case(alias_mappings=[
            {"alias": "pypi:a", "canonical": "pypi:b"},
            {"alias": "pypi:b", "canonical": "pypi:a"},
        ])
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, E_ALIAS_CONFLICT)

    def test_edge_requirement_excluding_locked_version(self):
        case = minimal_case()
        case["lockfile"]["edges"][0]["requirement"] = ">=2.0.0"
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, E_EDGE_UNRESOLVED)

    def test_missing_candidate_version(self):
        case = minimal_case()
        case["lockfile"]["packages"][0]["package"] = "pypi:absent"
        case["lockfile"]["edges"][0]["to"] = "pypi:absent@1.0.0"
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, E_NO_CANDIDATES)

    def test_include_exclude_conflict(self):
        case = minimal_case()
        case["upgrade"] = {"include": ["pypi:x"], "exclude": ["pypi:x"]}
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, E_SCHEMA)

    def test_bad_fork_policy(self):
        case = minimal_case()
        case["upgrade"] = {"fork_policy": "nope"}
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, E_SCHEMA)

    def test_unknown_policy_validation(self):
        case = minimal_case()
        case["options"] = {"unknown_policy": "bogus"}
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, E_SCHEMA)

    def test_duplicate_node_id_rejected(self):
        case = minimal_case()
        case["lockfile"]["packages"] = [
            {"id": "dup", "package": "pypi:x", "version": "1.0.0"},
            {"id": "dup", "package": "pypi:y", "version": "1.0.0"},
        ]
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, E_SCHEMA)

    def test_missing_registry_file_error_code(self):
        case = minimal_case()
        case["registry"] = {"path": "does-not-exist.odr"}
        with self.assertRaises(InputError) as cm:
            run_case(case, BASE)
        self.assertEqual(cm.exception.code, "E1001")


if __name__ == "__main__":
    unittest.main()
