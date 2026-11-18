"""统一的错误码与异常类型。

所有可预期的输入/数据错误都抛出 :class:`InputError`，携带稳定错误码，
CLI 层据此输出结构化错误对象并以非零状态退出。
"""

from __future__ import annotations

# ---- 错误码（在 README“错误码”一节中保持同步说明） ----
E_FILE_NOT_FOUND = "E1001"      # 输入文件/引用文件不存在
E_INVALID_JSON = "E1002"        # JSON 语法错误或顶层类型错误
E_SCHEMA = "E1003"              # 结构/schema 校验失败
E_INVALID_VERSION = "E1004"     # 版本号不符合 major.minor.patch[-pre.N]
E_INVALID_RANGE = "E1005"       # 区间表达式无法解析
E_ALIAS_CONFLICT = "E1006"      # 别名映射冲突或成环
E_EDGE_UNRESOLVED = "E1007"     # 依赖边在锁文件中找不到满足约束的包
E_EDGE_AMBIGUOUS = "E1008"      # 依赖边可解析到多个锁文件节点且未显式指定
E_REGISTRY = "E1009"            # 二进制离线源魔数/校验和/结构错误
E_NO_CANDIDATES = "E1010"       # 求解所需包在候选源中没有任何版本
E_UNKNOWN_PACKAGE = "E1011"     # 引用了候选源/锁文件中不存在的包
E_INTERNAL = "E1999"            # 不应发生的内部错误


class InputError(Exception):
    """携带稳定错误码的输入异常。"""

    def __init__(self, code: str, message: str, *, context: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        # context 用 JSON Pointer 风格字符串指出出错位置，便于定位
        self.context = context

    def to_dict(self) -> dict:
        d = {"error_code": self.code, "message": self.message}
        if self.context is not None:
            d["context"] = self.context
        return d
