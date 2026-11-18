"""包标识、别名归并、生态/命名空间隔离与平台三值条件测试。"""

import unittest

from solution.conditions import FALSE, TRUE, UNKNOWN, evaluate
from solution.errors import E_ALIAS_CONFLICT, E_SCHEMA, InputError
from solution.packages import AliasMap, PackageKey


class TestPackageKey(unittest.TestCase):
    def test_string_and_dict_forms_equivalent(self):
        a = PackageKey.parse("pypi:requests")
        b = PackageKey.parse({"ecosystem": "pypi", "name": "requests"})
        self.assertEqual(a, b)
        self.assertEqual(a.canonical(), "pypi:requests")

    def test_namespace_forms(self):
        k = PackageKey.parse("npm:@scope/pkg")
        self.assertEqual((k.ecosystem, k.namespace, k.name),
                         ("npm", "@scope", "pkg"))
        k2 = PackageKey.parse(
            {"ecosystem": "npm", "namespace": "@scope", "name": "pkg"}
        )
        self.assertEqual(k, k2)

    def test_same_name_different_ecosystem_not_equal(self):
        self.assertNotEqual(
            PackageKey.parse("pypi:utils"),
            PackageKey.parse("npm:utils"),
        )

    def test_same_ecosystem_different_namespace_not_equal(self):
        self.assertNotEqual(
            PackageKey.parse("npm:@a/x"),
            PackageKey.parse("npm:@b/x"),
        )

    def test_missing_ecosystem_prefix_rejected(self):
        with self.assertRaises(InputError) as cm:
            PackageKey.parse("requests")
        self.assertEqual(cm.exception.code, E_SCHEMA)


class TestAliasMap(unittest.TestCase):
    def test_transitive_resolution(self):
        am = AliasMap([
            {"alias": "pypi:old-name", "canonical": "pypi:mid-name"},
            {"alias": "pypi:mid-name", "canonical": "pypi:new-name"},
        ])
        self.assertEqual(
            am.resolve(PackageKey.parse("pypi:old-name")).canonical(),
            "pypi:new-name",
        )
        self.assertEqual(
            am.resolve(PackageKey.parse("pypi:new-name")).canonical(),
            "pypi:new-name",
        )

    def test_conflicting_alias_rejected(self):
        with self.assertRaises(InputError) as cm:
            AliasMap([
                {"alias": "pypi:x", "canonical": "pypi:y"},
                {"alias": "pypi:x", "canonical": "pypi:z"},
            ])
        self.assertEqual(cm.exception.code, E_ALIAS_CONFLICT)

    def test_alias_cycle_rejected(self):
        with self.assertRaises(InputError) as cm:
            AliasMap([
                {"alias": "pypi:a", "canonical": "pypi:b"},
                {"alias": "pypi:b", "canonical": "pypi:a"},
            ])
        self.assertEqual(cm.exception.code, E_ALIAS_CONFLICT)

    def test_alias_does_not_merge_across_ecosystems(self):
        am = AliasMap([
            {"alias": "pypi:json_utils",
             "canonical": "pypi:json-utils"},
        ])
        # npm 同名包不受 pypi 别名影响
        self.assertEqual(
            am.resolve(PackageKey.parse("npm:json-utils")).canonical(),
            "npm:json-utils",
        )
        self.assertEqual(
            am.resolve(PackageKey.parse("pypi:json_utils")).canonical(),
            "pypi:json-utils",
        )


class TestConditions(unittest.TestCase):
    CTX = {"os": "win32", "arch": "x86_64"}

    def test_leaf_three_values(self):
        self.assertEqual(
            evaluate({"attribute": "os", "op": "==", "value": "win32"},
                     self.CTX),
            TRUE,
        )
        self.assertEqual(
            evaluate({"attribute": "os", "op": "==", "value": "linux"},
                     self.CTX),
            FALSE,
        )
        self.assertEqual(
            evaluate({"attribute": "libc", "op": "==", "value": "glibc"},
                     self.CTX),
            UNKNOWN,
        )

    def test_in_and_not_in(self):
        self.assertEqual(
            evaluate({"attribute": "os", "op": "in",
                      "value": ["win32", "linux"]}, self.CTX),
            TRUE,
        )
        self.assertEqual(
            evaluate({"attribute": "os", "op": "not_in",
                      "value": ["linux"]}, self.CTX),
            TRUE,
        )

    def test_kleene_all_any_not(self):
        unknown_leaf = {"attribute": "libc", "op": "==", "value": "glibc"}
        true_leaf = {"attribute": "os", "op": "==", "value": "win32"}
        false_leaf = {"attribute": "os", "op": "==", "value": "linux"}

        self.assertEqual(evaluate({"all": [true_leaf, unknown_leaf]},
                                  self.CTX), UNKNOWN)
        self.assertEqual(evaluate({"all": [true_leaf, false_leaf]},
                                  self.CTX), FALSE)
        self.assertEqual(evaluate({"any": [false_leaf, unknown_leaf]},
                                  self.CTX), UNKNOWN)
        self.assertEqual(evaluate({"any": [false_leaf, true_leaf]},
                                  self.CTX), TRUE)
        self.assertEqual(evaluate({"not": unknown_leaf}, self.CTX), UNKNOWN)
        self.assertEqual(evaluate({"not": true_leaf}, self.CTX), FALSE)
        # 无条件（None）按 TRUE 处理
        self.assertEqual(evaluate(None, self.CTX), TRUE)


if __name__ == "__main__":
    unittest.main()
