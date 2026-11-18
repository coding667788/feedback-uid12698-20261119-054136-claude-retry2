"""平台条件的三值逻辑。

条件求值在给定平台上下文（扁平字符串字典）上进行，结果为三值：

* ``True``        条件成立，路径/公告有效；
* ``False``       条件不成立，路径/公告无效（剪枝）；
* ``UNKNOWN``     上下文缺少相关属性，无法判定。

支持的叶子表达式：``{"attribute": "os", "op": "==", "value": "win32"}``
支持的 op：``==``、``!=``、``in``、``not_in``（后两者 value 为列表）。
复合表达式：``{"all": [...]}``、``{"any": [...]}``、``{"not": ...}``，
采用 Kleene 三值逻辑。
"""

from __future__ import annotations

from .errors import E_SCHEMA, InputError

TRUE = True
FALSE = False
UNKNOWN = None  # 三值逻辑中的“未知”


def _eval_leaf(node: dict, context: dict[str, str]):
    try:
        attr = node["attribute"]
        op = node["op"]
        value = node["value"]
    except KeyError as exc:
        raise InputError(
            E_SCHEMA, f"条件叶子缺少字段 {exc.args[0]}：{node!r}"
        ) from exc
    if attr not in context:
        return UNKNOWN
    actual = context[attr]
    if op in ("==", "="):
        return actual == value
    if op == "!=":
        return actual != value
    if op == "in":
        if not isinstance(value, list):
            raise InputError(E_SCHEMA, f"op=in 的 value 必须是列表：{node!r}")
        return actual in value
    if op in ("not_in", "notin"):
        if not isinstance(value, list):
            raise InputError(
                E_SCHEMA, f"op=not_in 的 value 必须是列表：{node!r}"
            )
        return actual not in value
    raise InputError(E_SCHEMA, f"不支持的条件操作符 {op!r}")


def evaluate(node, context: dict[str, str]):
    """三值求值。``node`` 为 None 时视为无条件（TRUE）。"""
    if node is None:
        return TRUE
    if not isinstance(node, dict):
        raise InputError(E_SCHEMA, f"条件必须是对象或 null：{node!r}")
    if "all" in node:
        result = TRUE
        for sub in node["all"]:
            v = evaluate(sub, context)
            if v is FALSE:
                return FALSE
            if v is UNKNOWN:
                result = UNKNOWN
        return result
    if "any" in node:
        result = FALSE
        for sub in node["any"]:
            v = evaluate(sub, context)
            if v is TRUE:
                return TRUE
            if v is UNKNOWN:
                result = UNKNOWN
        return result
    if "not" in node:
        v = evaluate(node["not"], context)
        if v is UNKNOWN:
            return UNKNOWN
        return not v
    if "attribute" in node:
        return _eval_leaf(node, context)
    raise InputError(E_SCHEMA, f"条件对象无法识别（需要 all/any/not/attribute）：{node!r}")


def is_unknown(v) -> bool:
    return v is UNKNOWN
