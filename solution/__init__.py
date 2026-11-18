"""离线软件依赖风险判定器（offline dependency risk judge）。

仅使用 Python 标准库实现，模块划分：

* ``models``      -- 版本号、版本区间与区间并/交/差
* ``packages``    -- 包标识、别名归并
* ``conditions``  -- 平台条件的三值逻辑
* ``graph``       -- 依赖图与最短可达证据
* ``advisories``  -- 本地漏洞公告匹配
* ``solver``      -- 受约束最小变更升级求解与不可解反例
* ``registry``    -- 二进制离线候选版本源
* ``engine``      -- 单条用例编排
* ``cli``         -- 命令行入口与错误码
"""

__all__ = ["__version__"]
__version__ = "1.0.0"
