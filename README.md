# 离线软件依赖风险判定器（Offline Dependency Risk Judge）

一个**完全离线**的依赖漏洞匹配与升级方案求解工具：读取包清单（锁文件）、
依赖图和本地漏洞公告，判定每个依赖的风险与生产可达性，并在有限候选版本集合上
求解受约束的最小变更升级方案。**不连接任何在线漏洞库或外部服务**，仅使用
Python 3.12 标准库（`json`、`struct`、`zlib`、`hashlib`、`dataclasses`、
`unittest` 等），CPU 运行，无需 Docker。

---

## 1. 快速开始

```bash
# 1. 生成样例输入（examples/cases.json + 二进制候选源 registry.odr）
python tools/build_examples.py

# 2. 风险判定与升级求解（题目规定入口）
python -m solution --input examples/cases.json --output result.json

# 3. 运行全部自动化测试（题目规定入口）
python -m unittest discover -s tests -v
```

- 退出码 `0`：正常（批量模式下个别用例失败会被结构化进结果，不影响退出码）。
- 退出码 `2`：顶层输入致命错误（文件缺失、JSON 非法、schema 错误等），
  错误对象同时写入输出文件与 stderr。

---

## 2. 目录结构

```
solution/
  __init__.py        包说明
  __main__.py        支持 python -m solution
  cli.py             命令行入口、退出码、批处理
  engine.py          单用例编排（建图→匹配→求解）
  errors.py          稳定错误码与 InputError
  models.py          版本号 Version、区间 Interval/VersionRange（并/交/差）
  packages.py        包标识 PackageKey、别名归并 AliasMap
  conditions.py      平台条件的 Kleene 三值逻辑（true/false/unknown）
  graph.py           依赖图、边解析、最短可达证据（Dijkstra）
  advisories.py      本地公告解析与多区间匹配、状态合成
  registry.py        二进制离线候选版本源（魔数+sha256+zlib）
  solver.py          受约束最小变更枚举求解 + 极小不可满足子集（MUS）
tests/               6 个测试模块、52 个断言式用例（含独立暴力枚举对拍）
tools/build_examples.py  生成样例与二进制候选源
examples/
  cases.json         9 个验收场景用例
  registry.odr       二进制离线候选版本源
```

---

## 3. 版本规则与区间代数（核心要求 1）

### 3.1 版本号

格式严格为 `major.minor.patch[-pre.N]`：

1. 先比较 `major / minor / patch` 数字三元组（按整数比较，`10.0.0 > 9.9.9`）；
2. 三元组相同时，**正式版高于任意预发布版**（`1.0.0 > 1.0.0-pre.99`）；
3. 同为预发布版时，按序号 `N` 的**数值**排序（`pre.2 < pre.10`，不是字符串序）；
4. 数字不允许前导零（`pre.01` 非法），比较键为
   `(major, minor, patch, is_release, N)`。

非法格式抛 `E1004`，例如 `1.2`、`v1.2.3`、`1.2.3-pre.1` 之外的错误后缀、
`1.2.3-pre.x` 等。

### 3.2 区间与并/交/差

区间是若干互不相交 `Interval`（端点可开/闭/无界）的并 `VersionRange`，
支持精确的 `union` / `intersection` / `difference` / `contains`，
以及从有限候选集过滤 `filter_versions`。

区间表达式三种写法（可混用）：

| 形式 | 示例 | 含义 |
|---|---|---|
| 字符串 | `*` | 全部版本 |
| 字符串 | `1.2.3` | 单点 |
| 字符串 | `>=1.0.0 <2.0.0` | 空格分隔 = 交集 AND |
| 字符串 | `>=1.0.0 \|\| >=3.0.0` | `\|\|` = 并集 OR（优先级低于 AND） |
| 字符串 | `^1.2.3` | 兼容更新 `>=1.2.3 <2.0.0`（`^0.y.z` 锁 minor） |
| 字符串 | `~1.2.3` | 补丁更新 `>=1.2.3 <1.3.0` |
| 比较符 | `>= <= > < = ==` | 闭/开边界 |
| dict | `{"intervals":[{"lo":"1.0.0","hi":null,"lo_inclusive":true,...}]}` | 结构化 |
| list | `[区间dict, 区间dict]` | 列表整体为并集 |

“差”用于从可用集合中剔除受影响区间，例如回归漏洞
`[1.0,4.0) − [2.0,3.0)` 得到两个安全区间 `[1.0,2.0) ∪ [3.0,4.0)`。

### 3.3 别名归并与生态/命名空间隔离

包身份是三元组 `(ecosystem, namespace, name)`：

- `pypi:utils` 与 `npm:utils` 同名但**生态不同，绝不混合**；
- `npm:@a/x` 与 `npm:@b/x` **命名空间不同，不混合**；
- 别名仅按输入中**显式映射**归并（支持传递），映射冲突或成环抛 `E1006`；
- 别名不会跨生态生效。

---

## 4. 漏洞公告与可达证据（核心要求 2）

### 4.1 公告表达能力

每条公告（`advisories[]`）含：

- `id`（唯一）、`package`、`severity`、`title`；
- `affected`：**多个受影响区间的并**。补丁回退再次引入用相邻区间表达，
  中间夹着的安全版本不属于任何区间，例如
  `"affected": [">=1.0.0 <1.3.0", ">=2.0.0"]` 表示 1.3.x 安全、2.0 起回归；
- `condition`：可选平台条件，三值求值。

### 4.2 平台三值逻辑

条件叶子 `{"attribute","op","value"}`，`op ∈ ==, !=, in, not_in`；
复合用 `all / any / not`，采用 Kleene 逻辑：上下文缺属性 → `unknown`，
含 `false` 的 `all` 恒为 `false`（未知不能“救回”被否定的路径）。

`options.unknown_policy`：

- `exclude`（默认，保守）：公告条件未知仍计入风险；
- `ignore`：条件未知公告视为不适用。

### 4.3 可达性与证据链

锁文件建模为有向图，节点=锁定包版本（同包多版本可共存），边=依赖声明
（携带版本要求、`scope`、条件）。**只有 `production`/`runtime` scope 的边
参与生产可达**，`dev` 等非生产边不参与。

两遍 Dijkstra（代价 `(跳数, 未知条件数)`）产出三态：

| 状态 | 含义 |
|---|---|
| `reachable` | 存在条件全为 true 的生产路径（给最短证据链） |
| `condition_unknown` | 无确定路径，但存在 true/unknown 路径 |
| `unreachable` | 无生产路径；若仅 dev 可达，附 `locked_but_not_production_reachable` 与非生产证据 |

因此**不会把所有锁文件条目当作生产可达**。循环依赖由 visited/前驱表处理，
不会死循环，且最短路径不会绕环。

公告命中与可达状态合成为：`affected_reachable` /
`affected_condition_unknown` / `affected_unreachable` /
`platform_inapplicable` / `not_affected`。每条风险附带从 `@root` 出发的
逐跳证据（起点、终点、包、版本、约束、scope、边/节点条件真值）。

---

## 5. 受约束最小变更升级（核心要求 3）

### 5.1 变量与约束

- 候选版本**只来自输入有限集合**（二进制源或 inline），无源版本抛 `E1010`；
- 默认 `fork_policy=unify`：**同一规范包全图只能选一个版本**；
  `keep_fork` 时，锁文件中已分叉的包允许按节点保留多版本；
- 约束四类：根依赖 `root`、传递边 `edge`、用例显式 `upgrade`、
  公告禁用区间 `advisory`（后者不可作为反例删除对象，因它是客观风险事实）；
- 平台条件为 `false` 的约束剪枝，`unknown` 按 `unknown_policy` 处理。

### 5.2 优化目标（字典序）

1. 第一目标：**变更包数量最少**。选中版本 ≠ 该变量唯一锁定版本记一次变更
   （新增包、分叉归并计变更；keep_fork 下分叉变量与各自节点锁定版本比较）；
2. 平局：按全图 `(包名, 版本字符串)` 字典序签名打破，结果确定可重放。

求解用**完整枚举**（MRV 变量排序 + 前向检查 + 状态记忆 + 下界剪枝），
访问状态受 `VISITED_NODE_CAP=200000` 保护，超限返回 `incomplete` 而非静默截断。
测试中用一个**独立实现的笛卡尔积暴力枚举器对拍**，证明最优值正确。

### 5.3 无解反例（MUS）

无解时返回 `unsat` 与**极小不可满足约束子集**：通过删除过滤 + 迭代最小化得到，
并执行极小性自检（移除其中任意一条可移除约束后恢复可满足）。结果同时给出
每个变量的剩余候选域 `domains` 与空域包 `empty_domain_packages`，便于定位
是“无候选版本”还是“约束冲突”。

---

## 6. 输入 Schema

顶层支持单用例对象，或批量 `{"cases": [...]}`。

```jsonc
{
  "id": "string",                       // 用例 id
  "platform": {"os": "win32", "arch": "x86_64"},   // 平台上下文，扁平字符串
  "alias_mappings": [                   // 显式别名（可空）
    {"alias": "pypi:json_utils", "canonical": "pypi:json-utils"}
  ],
  "registry": {                         // 二选一：path 引用二进制源，或 inline
    "path": "registry.odr",
    "sha256": "<可选，声明校验和>"
  },
  // "registry": {"inline": {"packages": [{"package": "pypi:x",
  //                                        "candidates": ["1.0.0","1.1.0"]}]}},
  "lockfile": {
    "root": {"name": "app"},
    "packages": [
      {"id": "可选，同包多版本时必须唯一",
       "package": "pypi:core", "version": "1.1.0",
       "condition": null}
    ],
    "edges": [
      {"from": null,                    // null = 从根 @root 出发
       "to": "pypi:core@1.1.0",         // 目标节点 id（默认 包@版本）
       "requirement": ">=1.0.0 <2.0.0", // 区间表达式，必须包含锁定版本
       "scope": "production",           // production|runtime|dev|...
       "condition": null}
    ]
  },
  "advisories": [
    {"id": "ADV-1", "package": "pypi:core", "severity": "HIGH",
     "title": "...",
     "affected": [">=1.0.0 <1.3.0", ">=2.0.0"],   // 多区间并
     "condition": {"attribute": "os", "op": "==", "value": "linux"}}
  ],
  "upgrade": {                          // 可空；存在才求解
    "fork_policy": "unify",             // unify(默认) | keep_fork
    "allowed": [{"package": "pypi:x", "range": ">=1.0.0"}],
    "include": ["pypi:extra"],          // 强制纳入求解的包
    "exclude": ["pypi:skip"]            // 排除的包；与 include 交集报错
  },
  "options": {"unknown_policy": "exclude", "seed": 20261119}
}
```

包引用可写成 dict `{"ecosystem","namespace?","name"}` 或字符串
`ecosystem:name` / `ecosystem:namespace/name`。

### 二进制候选源格式（`registry.odr`，大端）

```
magic   = b"ODRJ"        # 4 字节魔数
version = uint16         # 格式版本，当前 1
flags   = uint16         # bit0=payload 经 zlib 压缩
sha256  = 32 字节        # 对（解压后）payload 的摘要
length  = uint32         # payload 字节数
payload = JSON UTF-8（可能 zlib 压缩）
```

读取时校验魔数、格式版本、sha256；任何不符抛 `E1009`。该文件由
`tools/build_examples.py` 纯本地生成，是项目内的模拟数据，不代表真实服务。

---

## 7. 输出 Schema

```jsonc
{
  "tool": "offline-dependency-risk-judge",
  "schema_version": "1.0",
  "case_count": 9,
  "results": [
    {
      "id": "...",
      "schema_version": "1.0",
      "aliases": {"pypi:json_utils": "pypi:json-utils"},
      "platform": {...},
      "vulnerability_report": {
        "counts": {"affected_reachable": 1, "affected_condition_unknown": 0,
                   "affected_unreachable": 0, "not_affected": 0,
                   "platform_inapplicable": 0},
        "findings": [
          {"advisory_id": "...", "title": "...", "severity": "...",
           "node_id": "...", "package": "...", "version": "...",
           "status": "affected_reachable",
           "advisory_condition_truth": "true",
           "evidence": {
             "reachability": "reachable", "hops": 2,
             "unknown_conditions": 0,
             "path": [
               {"from": "@root", "to": "...", "package": "...",
                "version": "...", "requirement": "...", "scope": "...",
                "edge_condition_truth": "true",
                "node_condition_truth": "true"}]}}
        ],
        "platform_inapplicable": [ /* 条件为假/被忽略的公告 */ ]
      },
      "reachability": { "<node_id>": {"status": "...", "hops": 2,
                                      "unknown_conditions": 0, "path": [...]} },
      "upgrade": {
        "status": "optimal",            // optimal | unsat | incomplete
        "fork_policy": "unify",
        "selection": [
          {"package": "pypi:x", "variable": "pypi:x", "node_ids": [...],
           "version": "1.2.0", "changed": true, "change_kind": "upgraded"}
          // change_kind: upgraded | added | deduplicated | kept_fork
        ],
        "objective": {"changed_packages": 1,
                      "tie_breaker": ["pypi:x@1.2.0"]},
        "stats": {"visited_states": 21, "cap_hit": false,
                  "enumerated_assignments": 21, "complete": true}
      }
      // 无解时 upgrade 为：
      // {"status":"unsat","reason":"empty_domain|constraint_conflict",
      //  "empty_domain_packages":[...],
      //  "unsatisfiable_constraints":[{"id","kind","package","variable",
      //                                "description","removable"}],
      //  "domains":{...},"stats":{"complete":true,
      //                           "mus_minimality_checked":true}}
    }
  ]
}
```

单用例失败时该结果为 `{"id": "...", "status": "error", "error": {...}}`，
不影响同批其它用例。

---

## 8. 错误码

| 错误码 | 含义 |
|---|---|
| `E1001` | 输入文件/引用文件不存在 |
| `E1002` | JSON 语法错误或顶层类型错误 |
| `E1003` | 结构/schema 校验失败（含空升级问题、include/exclude 冲突、非法策略） |
| `E1004` | 版本号不符合 `major.minor.patch[-pre.N]` |
| `E1005` | 区间表达式无法解析（含悬空 `\|\|`、未知比较符） |
| `E1006` | 别名映射冲突或成环 |
| `E1007` | 依赖边在锁文件中找不到满足约束的锁定版本 |
| `E1008` | 依赖边可解析到多个节点且未显式指定（保留） |
| `E1009` | 二进制候选源魔数/版本/校验和/结构错误 |
| `E1010` | 求解所需包在候选源中没有任何版本 |
| `E1011` | 引用了候选源/锁文件中不存在的包（保留） |
| `E1999` | 不应发生的内部错误 |

错误对象形如 `{"error_code": "E1004", "message": "...", "context": "..."}`，
`context` 用 JSON Pointer 风格定位出错字段。

---

## 9. 验收场景映射

| 场景 | 用例 | 关键断言 |
|---|---|---|
| 预发布边界 | `01-prerelease-boundary` | pre.N 数值序、正式版>预发布、受影响且升级到 `pre.1` |
| 分叉依赖 | `02-forked-versions` | keep_fork 两节点独立升级、恰好 2 次变更；unify 另有单测验证强制单版本 |
| 菱形图 | `03-diamond-minimal-change` | 两臂传递约束交集、仅升级 1 个包到 `1.2.0` |
| 循环依赖 | `04-cycle` | 图遍历不死循环、最短证据 3 跳、升级成功 |
| 回归（再引入） | `05-regression-reintroduced` | 多区间安全岛 `1.3.0` 不被误判 |
| 不可解升级 | `06` / `09` | `06` 公告封死候选；`09` 纯约束冲突，MUS 恰为两条矛盾显式约束 |
| 可达三态 | `07-reachability-states` | reachable / condition_unknown / unreachable 计数与 dev 备注 |
| 别名/生态隔离 | `08-alias-and-ecosystem-isolation` | 别名归并可升级、同名不同生态不混合 |

另在 `tests/` 中以固定种子（`20261119` / `42` / `99`）做随机小问题的
**暴力枚举对拍**与 MUS 极小性独立验证，全部断言具体值/状态/证据，
无“仅打印成功”式测试。

---

## 10. 范围与非安全性细节约定

- 所有操作局限于项目目录与本机；不发起任何网络请求、不监听端口、不使用 Docker。
- 平台上下文是扁平字符串字典；未提供的属性求值为 `unknown` 而非报错。
- 非生产 scope（如 `dev`、`test`）不参与生产可达与升级变量，但仍在
  证据中以 `non_production_path` 体现“锁文件存在但生产不可达”。
- 候选版本去重并按版本升序；同一版本字符串重复出现只计一次。
- 输出 JSON 使用 UTF-8、`ensure_ascii=False`，键顺序稳定，便于 diff 与重放。
- 本项目未使用 `cryptography`；二进制源完整性以标准库 `hashlib.sha256` 保证，
  满足离线完整性校验需要。
