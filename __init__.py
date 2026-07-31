# -*- coding: utf-8 -*-
"""
WAF 规则自动生成器

用法:
    from auto_waf_rule import auto_gen_rule, auto_gen_rule_with_type

    result = auto_gen_rule(http_raw_request)
    result = auto_gen_rule_with_type(http_raw, vuln_type="SQLi", selected_param="id")
"""
from constants import (
    REGEX_TEMPLATES, TAG_MAP, VULN_NAME_MAP,
    SUPPORTED_VULN_TYPES, DEFAULT_REV, EXTENSION_GROUPS
)
from parser import parse_http_input, get_all_param_names
from detector import detect_vuln_type, find_payload_params
from generators.sec_rules import generate_sec_rules, generate_sec_rules_auto
from generators.suricata import generate_suricata_rule
from formatter import format_output
from main import auto_gen_rule, auto_gen_rule_with_type

# 向后兼容：保留原模块名导入路径
from main import auto_gen_rule as _auto_gen_rule
from main import auto_gen_rule_with_type as _auto_gen_rule_with_type

__all__ = [
    # 常量
    "REGEX_TEMPLATES",
    "TAG_MAP",
    "VULN_NAME_MAP",
    "SUPPORTED_VULN_TYPES",
    "DEFAULT_REV",
    "EXTENSION_GROUPS",
    # 解析
    "parse_http_input",
    "get_all_param_names",
    # 检测
    "detect_vuln_type",
    "find_payload_params",
    # 生成
    "generate_sec_rules",
    "generate_sec_rules_auto",
    "generate_suricata_rule",
    # 格式化
    "format_output",
    # API
    "auto_gen_rule",
    "auto_gen_rule_with_type",
]
