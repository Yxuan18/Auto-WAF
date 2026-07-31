#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF 规则自动生成器 - 向后兼容包装模块

此模块保持原有 API 签名，实际逻辑委托给各子模块。
后续可直接从子模块导入以获得更好的 IDE 支持。

迁移指南:
    # 旧写法（仍支持）
    from auto_waf_rule import auto_gen_rule, auto_gen_rule_with_type

    # 新写法（推荐）
    from auto_waf_rule import (
        auto_gen_rule, auto_gen_rule_with_type,
        parse_http_input, detect_vuln_type, generate_sec_rules
    )
"""
# 向后兼容：直接委托给 main 模块
from main import auto_gen_rule, auto_gen_rule_with_type

__all__ = ["auto_gen_rule", "auto_gen_rule_with_type"]
