"""单用例编排：输入 schema 校验 -> 建图 -> 公告匹配 -> 升级求解。

输入用例结构（完整字段说明见 README）::

    {
      "id": "...",
      "platform": {"os": "win32", ...},
      "alias_mappings": [{"alias": <pkg>, "canonical": <pkg>}],
      "registry": {"path": "...", "sha256": "..."} 或 {"inline": {...}},
      "lockfile": {"root": {...}, "packages": [...], "edges": [...]},
      "advisories": [...],
      "upgrade": {"allowed": [...], "include": [...], "exclude": [...]},
      "options": {"unknown_policy": "exclude", "seed": 20261119}
    }
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from . import advisories as adv_mod
from . import solver as solver_mod
from .errors import E_FILE_NOT_FOUND, E_SCHEMA, InputError
from .graph import Graph
from .packages import AliasMap
from .registry import Registry

SCHEMA_VERSION = "1.0"


def run_case(case: dict, base_dir: Path) -> dict:
    if not isinstance(case, dict):
        raise InputError(E_SCHEMA, "用例必须是 JSON 对象")
    case_id = str(case.get("id", "unnamed-case"))
    context = dict(case.get("platform") or {})
    options = case.get("options") or {}
    unknown_policy = str(options.get("unknown_policy", "exclude"))
    seed = options.get("seed", 20261119)
    if seed is not None and not isinstance(seed, int):
        raise InputError(E_SCHEMA, "options.seed 必须是整数或 null")

    aliases = AliasMap(case.get("alias_mappings"))
    registry = _load_registry(case.get("registry"), aliases, base_dir)
    graph = Graph.build(case.get("lockfile") or {}, aliases)
    advisory_list = adv_mod.parse_advisories(
        case.get("advisories") or [], aliases
    )

    match = adv_mod.match_graph(
        graph, advisory_list, context, unknown_policy=unknown_policy
    )

    result: dict = {
        "id": case_id,
        "schema_version": SCHEMA_VERSION,
        "aliases": aliases.as_dict(),
        "platform": context,
        "vulnerability_report": {
            "counts": match["counts"],
            "findings": match["findings"],
            "platform_inapplicable": match["platform_inapplicable"],
        },
        "reachability": match["reachability"],
    }

    if "upgrade" in case and case["upgrade"] is not None:
        problem = solver_mod.build_problem(
            graph, advisory_list, registry, context,
            case["upgrade"], unknown_policy=unknown_policy,
        )
        result["upgrade"] = solver_mod.solve(problem, registry, seed=seed)
    return result


def _load_registry(spec: Optional[dict], aliases: AliasMap,
                   base_dir: Path) -> Registry:
    if spec is None:
        # 没有升级请求时允许缺省；给一个空源
        return Registry({"packages": []}, aliases)
    if not isinstance(spec, dict):
        raise InputError(E_SCHEMA, "registry 必须是对象")
    if "inline" in spec:
        return Registry(spec["inline"], aliases)
    if "path" in spec:
        path = Path(spec["path"])
        if not path.is_absolute():
            path = (base_dir / path).resolve()
        if not path.exists():
            raise InputError(E_FILE_NOT_FOUND, f"候选源文件不存在：{path}")
        return Registry.read(
            path, aliases, expected_sha256=spec.get("sha256")
        )
    raise InputError(
        E_SCHEMA, "registry 需要 inline 或 path 字段"
    )
