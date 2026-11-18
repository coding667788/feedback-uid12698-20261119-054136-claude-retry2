"""命令行入口：``python -m solution --input cases.json --output result.json``。

顶层输入支持两种形态：

* 单用例：任意包含 ``lockfile`` 的对象；
* 批量：``{"cases": [用例, ...]}``。

退出码：

* ``0`` 正常（含单用例内部被捕获并写入结果的错误）；
* ``2`` 顶层输入错误（文件缺失/JSON 非法/schema 错误等），错误对象同时
  写入输出文件（若可写）与 stderr。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import run_case
from .errors import E_INVALID_JSON, E_SCHEMA, InputError


def _load_input(path: Path) -> dict:
    if not path.exists():
        raise InputError("E1001", f"输入文件不存在：{path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(
            E_INVALID_JSON, f"输入不是合法 JSON：{exc.msg}（行 {exc.lineno}）"
        ) from exc
    if not isinstance(data, dict):
        raise InputError(E_SCHEMA, "输入顶层必须是 JSON 对象")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="离线软件依赖风险判定器（不访问任何在线漏洞库）",
    )
    parser.add_argument("--input", required=True, help="用例 JSON 文件路径")
    parser.add_argument("--output", required=True, help="结果 JSON 输出路径")
    args = parser.parse_args(argv)

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    try:
        data = _load_input(input_path)
        cases = data.get("cases", [data]) if "cases" in data else [data]
        if not isinstance(cases, list) or not cases:
            raise InputError(E_SCHEMA, "cases 必须是非空列表")
        results = []
        for i, case in enumerate(cases):
            try:
                results.append(run_case(case, input_path.parent))
            except InputError as exc:
                # 单用例失败不拖垮整批，错误结构化进结果
                results.append({
                    "id": str(case.get("id", f"case-{i}"))
                    if isinstance(case, dict) else f"case-{i}",
                    "status": "error",
                    "error": exc.to_dict(),
                })
        payload = {
            "tool": "offline-dependency-risk-judge",
            "schema_version": "1.0",
            "case_count": len(results),
            "results": results,
        }
    except InputError as exc:
        payload = {
            "tool": "offline-dependency-risk-judge",
            "schema_version": "1.0",
            "status": "fatal",
            "error": exc.to_dict(),
        }
        _safe_write(output_path, payload)
        print(json.dumps(payload, ensure_ascii=False, indent=2),
              file=sys.stderr)
        return 2

    _safe_write(output_path, payload)
    return 0


def _safe_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
