"""生成 examples/ 下的二进制离线候选源与 cases.json。

运行：``python tools/build_examples.py``（项目根目录下）。
全部数据为虚构的本地模拟数据，不代表任何真实包或真实公告。
覆盖验收场景：预发布边界、分叉依赖、菱形图、循环依赖、
回归版本（补丁回退再次引入）、不可解升级，外加可达性三态与
别名/生态隔离两个补充场景。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from solution.packages import AliasMap
from solution.registry import write_registry

EXAMPLES = ROOT / "examples"

# ---------------------------------------------------------------------------
# 离线候选源（候选版本均为有限集合，求解器只能从中选择）
# ---------------------------------------------------------------------------
REGISTRY_RAW = {
    "packages": [
        {"package": "pypi:utils",
         "candidates": ["1.0.0-pre.1", "1.0.0-pre.2", "1.0.0-pre.10",
                        "1.0.0", "1.1.0", "2.0.0"]},
        # 与 pypi:utils 同名但生态不同，禁止混合
        {"package": "npm:utils",
         "candidates": ["0.9.0", "1.0.0", "2.0.0"]},
        {"package": "pypi:core",
         "candidates": ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"]},
        {"package": "pypi:web",
         "candidates": ["3.0.0", "3.1.0", "4.0.0", "4.1.0"]},
        {"package": "pypi:db",
         "candidates": ["2.0.0", "2.1.0", "2.2.0", "3.0.0"]},
        {"package": "pypi:net",
         "candidates": ["1.0.0", "1.1.0", "1.2.0"]},
        {"package": "pypi:crypto",
         "candidates": ["1.0.0", "1.1.0", "2.0.0"]},
        {"package": "pypi:legacy",
         "candidates": ["1.0.0", "1.1.0", "1.2.0", "1.3.0"]},
        {"package": "pypi:cycle-a",
         "candidates": ["1.0.0", "1.1.0", "2.0.0"]},
        {"package": "pypi:cycle-b",
         "candidates": ["1.0.0", "1.1.0", "2.0.0"]},
        {"package": "pypi:devtool",
         "candidates": ["1.0.0", "2.0.0"]},
        # 别名归并目标
        {"package": "pypi:json-utils",
         "candidates": ["1.0.0", "1.1.0", "1.2.0"]},
        {"package": "pypi:json_utils",
         "candidates": ["1.0.0", "1.1.0", "1.2.0"]},
        {"package": "npm:@ns/json-utils",
         "candidates": ["1.0.0", "2.0.0"]},
    ]
}


def pkg(ecosystem: str, name: str, namespace: str = "") -> dict:
    d = {"ecosystem": ecosystem, "name": name}
    if namespace:
        d["namespace"] = namespace
    return d


def build() -> list[dict]:
    EXAMPLES.mkdir(exist_ok=True)
    aliases = AliasMap([
        {"alias": pkg("pypi", "json_utils"),
         "canonical": pkg("pypi", "json-utils")},
    ])
    digest = write_registry(
        EXAMPLES / "registry.odr", REGISTRY_RAW, aliases, compress=True
    )
    registry_ref = {"path": "registry.odr", "sha256": digest}

    cases: list[dict] = []

    # 1) 预发布边界 --------------------------------------------------------
    cases.append({
        "id": "01-prerelease-boundary",
        "platform": {"os": "win32", "arch": "x86_64"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-pre"},
            "packages": [
                {"package": "pypi:utils", "version": "1.0.0-pre.2"},
            ],
            "edges": [
                {"from": None, "to": "pypi:utils@1.0.0-pre.2",
                 "requirement": ">=1.0.0-pre.1 <1.0.0", "scope": "production"},
            ],
        },
        "advisories": [
            {
                "id": "ADV-PRE-1",
                "package": "pypi:utils",
                "title": "预发布版信息泄露",
                "severity": "HIGH",
                "affected": [">=1.0.0-pre.2 <1.0.0"],
            },
        ],
        "upgrade": {
            "allowed": [
                {"package": "pypi:utils",
                 "range": ">=1.0.0-pre.1 <2.0.0"},
            ],
        },
        "options": {"seed": 20261119},
    })

    # 2) 分叉依赖：同一包两个锁定版本 -------------------------------------
    cases.append({
        "id": "02-forked-versions",
        "platform": {"os": "win32"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-fork"},
            "packages": [
                {"id": "core-1", "package": "pypi:core", "version": "1.1.0"},
                {"id": "core-2", "package": "pypi:core", "version": "2.0.0"},
                {"package": "pypi:web", "version": "3.1.0"},
                {"package": "pypi:db", "version": "2.1.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.1.0",
                 "requirement": "^3.0.0", "scope": "production"},
                {"from": None, "to": "pypi:db@2.1.0",
                 "requirement": "~2.1.0", "scope": "production"},
                {"from": "pypi:web@3.1.0", "to": "core-1",
                 "requirement": ">=1.0.0 <2.0.0", "scope": "production"},
                {"from": "pypi:db@2.1.0", "to": "core-2",
                 "requirement": ">=2.0.0", "scope": "production"},
            ],
        },
        "advisories": [
            {"id": "ADV-CORE-1X", "package": "pypi:core",
             "title": "core 1.1.0 反序列化漏洞", "severity": "CRITICAL",
             "affected": ["1.1.0"]},
            {"id": "ADV-CORE-20", "package": "pypi:core",
             "title": "core 2.0.0 回归缺陷", "severity": "HIGH",
             "affected": ["2.0.0"]},
        ],
        "upgrade": {
            # 同一包已分叉，保留分叉策略：两个节点各自升级到安全版本
            "fork_policy": "keep_fork",
        },
        "options": {"seed": 20261119},
    })

    # 3) 菱形图 + 最小变更 -------------------------------------------------
    cases.append({
        "id": "03-diamond-minimal-change",
        "platform": {"os": "win32"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-diamond"},
            "packages": [
                {"package": "pypi:web", "version": "3.1.0"},
                {"package": "pypi:db", "version": "2.1.0"},
                {"package": "pypi:net", "version": "1.1.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.1.0",
                 "requirement": "^3.0.0", "scope": "production"},
                {"from": None, "to": "pypi:db@2.1.0",
                 "requirement": "~2.1.0", "scope": "production"},
                {"from": "pypi:web@3.1.0", "to": "pypi:net@1.1.0",
                 "requirement": ">=1.0.0 <=1.2.0", "scope": "production"},
                {"from": "pypi:db@2.1.0", "to": "pypi:net@1.1.0",
                 "requirement": ">=1.1.0", "scope": "production"},
            ],
        },
        "advisories": [
            {"id": "ADV-NET-11", "package": "pypi:net",
             "title": "net 1.1.0 中间人漏洞", "severity": "HIGH",
             # 锁定版本 1.1.0 受影响；两臂约束交集允许 1.2.0，
             # 故最小变更为仅升级 net 一个包到 1.2.0
             "affected": ["1.1.0"]},
        ],
        "upgrade": {},
        "options": {"seed": 20261119},
    })

    # 4) 循环依赖 ----------------------------------------------------------
    cases.append({
        "id": "04-cycle",
        "platform": {"os": "win32"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-cycle"},
            "packages": [
                {"package": "pypi:cycle-a", "version": "1.0.0"},
                {"package": "pypi:cycle-b", "version": "1.0.0"},
                {"package": "pypi:crypto", "version": "1.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:cycle-a@1.0.0",
                 "requirement": "^1.0.0", "scope": "production"},
                {"from": "pypi:cycle-a@1.0.0", "to": "pypi:cycle-b@1.0.0",
                 "requirement": ">=1.0.0 <2.0.0", "scope": "production"},
                {"from": "pypi:cycle-b@1.0.0", "to": "pypi:cycle-a@1.0.0",
                 "requirement": ">=1.0.0 <2.0.0", "scope": "production"},
                {"from": "pypi:cycle-b@1.0.0", "to": "pypi:crypto@1.0.0",
                 "requirement": "^1.0.0", "scope": "production"},
            ],
        },
        "advisories": [
            {"id": "ADV-CRYPTO-1", "package": "pypi:crypto",
             "title": "弱默认算法", "severity": "MEDIUM",
             "affected": [">=1.0.0 <1.1.0"]},
        ],
        "upgrade": {},
        "options": {"seed": 20261119},
    })

    # 5) 回归版本：修复后再次引入 -----------------------------------------
    cases.append({
        "id": "05-regression-reintroduced",
        "platform": {"os": "win32"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-reg"},
            "packages": [
                {"package": "pypi:legacy", "version": "1.2.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:legacy@1.2.0",
                 "requirement": ">=1.0.0", "scope": "production"},
            ],
        },
        "advisories": [
            {
                "id": "ADV-LEGACY-REG",
                "package": "pypi:legacy",
                "title": "漏洞在 1.3 修复、后续回归（多区间表达）",
                "severity": "HIGH",
                # 两个受影响区间，中间夹着安全版本 1.3.0（回归再引入的标准写法）
                "affected": [">=1.0.0 <1.3.0", ">=2.0.0"],
            },
        ],
        "upgrade": {},
        "options": {"seed": 20261119},
    })

    # 6) 不可解升级 --------------------------------------------------------
    cases.append({
        "id": "06-unsat-upgrade",
        "platform": {"os": "win32"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-unsat"},
            "packages": [
                {"package": "pypi:web", "version": "3.1.0"},
                {"package": "pypi:net", "version": "1.2.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.1.0",
                 "requirement": "^3.0.0", "scope": "production"},
                {"from": "pypi:web@3.1.0", "to": "pypi:net@1.2.0",
                 "requirement": ">=1.2.0", "scope": "production"},
            ],
        },
        "advisories": [
            {"id": "ADV-NET-ALL", "package": "pypi:net",
             "title": "net 全候选区间均受影响", "severity": "CRITICAL",
             "affected": [">=1.0.0 <=1.2.0"]},
        ],
        "upgrade": {
            "allowed": [
                {"package": "pypi:net", "range": "<1.2.0"},
            ],
        },
        "options": {"seed": 20261119},
    })

    # 7) 可达性三态：生产可达 / 条件未知 / 仅 dev 不可达 ------------------
    cases.append({
        "id": "07-reachability-states",
        "platform": {"os": "win32"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-reach"},
            "packages": [
                {"package": "pypi:web", "version": "3.1.0"},
                {"package": "pypi:net", "version": "1.1.0"},
                {"package": "pypi:db", "version": "2.1.0"},
                {"package": "pypi:devtool", "version": "1.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.1.0",
                 "requirement": "^3.0.0", "scope": "production"},
                # 条件未知：上下文没有 libc 属性
                {"from": "pypi:web@3.1.0", "to": "pypi:net@1.1.0",
                 "requirement": ">=1.0.0", "scope": "production",
                 "condition": {"attribute": "libc", "op": "==",
                               "value": "glibc"}},
                # 条件为假：在 win32 上被剪枝
                {"from": "pypi:web@3.1.0", "to": "pypi:db@2.1.0",
                 "requirement": ">=2.0.0", "scope": "production",
                 "condition": {"attribute": "os", "op": "==",
                               "value": "linux"}},
                # 仅 dev 路径：锁文件存在但生产不可达
                {"from": None, "to": "pypi:devtool@1.0.0",
                 "requirement": "^1.0.0", "scope": "dev"},
            ],
        },
        "advisories": [
            {"id": "ADV-WEB-31", "package": "pypi:web",
             "title": "web 3.1.0 XSS", "severity": "HIGH",
             "affected": ["3.1.0"]},
            {"id": "ADV-NET-11", "package": "pypi:net",
             "title": "net 1.1.0 中间人", "severity": "HIGH",
             "affected": ["1.1.0"]},
            {"id": "ADV-DB-21", "package": "pypi:db",
             "title": "db 2.1.0 注入", "severity": "HIGH",
             "affected": ["2.1.0"]},
            {"id": "ADV-DEV-1", "package": "pypi:devtool",
             "title": "devtool 仅开发依赖漏洞", "severity": "LOW",
             "affected": ["1.0.0"]},
            # 平台条件明确不适用的公告（win32 上为假）
            {"id": "ADV-WEB-LINUX", "package": "pypi:web",
             "title": "仅 Linux 平台触发", "severity": "LOW",
             "affected": ["3.1.0"],
             "condition": {"attribute": "os", "op": "==",
                           "value": "linux"}},
        ],
        "upgrade": {},
        "options": {"seed": 20261119},
    })

    # 8) 别名归并与生态/命名空间隔离 --------------------------------------
    cases.append({
        "id": "08-alias-and-ecosystem-isolation",
        "platform": {"os": "win32"},
        "alias_mappings": [
            {"alias": pkg("pypi", "json_utils"),
             "canonical": pkg("pypi", "json-utils")},
        ],
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-alias"},
            "packages": [
                {"package": "pypi:json_utils", "version": "1.1.0"},
                {"package": "npm:utils", "version": "1.0.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:json-utils@1.1.0",
                 "requirement": ">=1.0.0", "scope": "production"},
                {"from": None, "to": "npm:utils@1.0.0",
                 "requirement": ">=1.0.0", "scope": "production"},
            ],
        },
        "advisories": [
            # 命中别名归并后的 pypi 包
            {"id": "ADV-JSON-PY", "package": "pypi:json-utils",
             "title": "python json-utils 原型污染", "severity": "HIGH",
             "affected": ["1.1.0"]},
            # 同名但生态不同：不得与 pypi:json-utils 混合；仅影响 1.0.0，
            # 1.1.0/2.0.0 可作为升级出口
            {"id": "ADV-JSON-NPM", "package": "npm:utils",
             "title": "npm utils 供应链投毒", "severity": "CRITICAL",
             "affected": ["1.0.0"]},
        ],
        "upgrade": {
            # 两个生态分别给出升级空间，验证同名包不混合
            "allowed": [
                {"package": "pypi:json-utils", "range": ">=1.0.0"},
                {"package": "npm:utils", "range": ">=1.0.0"},
            ],
        },
        "options": {"seed": 20261119},
    })

    # 9) 纯约束冲突的不可解升级（不依赖公告，MUS 必须包含可移除约束） ----
    cases.append({
        "id": "09-unsat-constraint-conflict",
        "platform": {"os": "win32"},
        "registry": registry_ref,
        "lockfile": {
            "root": {"name": "app-conflict"},
            "packages": [
                {"package": "pypi:web", "version": "3.1.0"},
                {"package": "pypi:net", "version": "1.1.0"},
            ],
            "edges": [
                {"from": None, "to": "pypi:web@3.1.0",
                 "requirement": "^3.0.0", "scope": "production"},
                # 锁文件内约束与锁定版本一致，保证图可建
                {"from": "pypi:web@3.1.0", "to": "pypi:net@1.1.0",
                 "requirement": ">=1.1.0 <1.2.0", "scope": "production"},
            ],
        },
        "advisories": [],
        "upgrade": {
            # 升级请求内部两条显式约束没有交集（候选只有 1.0.0/1.1.0/1.2.0）
            "allowed": [
                {"package": "pypi:net", "range": ">=1.2.0"},
                {"package": "pypi:net", "range": "<1.2.0"},
            ],
        },
        "options": {"seed": 20261119},
    })

    return cases


def main() -> None:
    cases = build()
    out = {
        "tool": "offline-dependency-risk-judge",
        "schema_version": "1.0",
        "description": "离线依赖风险判定器样例集（虚构数据，覆盖全部验收场景）",
        "cases": cases,
    }
    (EXAMPLES / "cases.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"wrote {EXAMPLES / 'cases.json'} ({len(cases)} cases)")
    print(f"wrote {EXAMPLES / 'registry.odr'}")


if __name__ == "__main__":
    main()
