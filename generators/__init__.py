# -*- coding: utf-8 -*-
"""
规则生成器模块
提供 ModSecurity SecRule 和 Suricata 规则生成
"""
from generators.sec_rules import generate_sec_rules, generate_sec_rules_auto
from generators.suricata import generate_suricata_rule

__all__ = ["generate_sec_rules", "generate_sec_rules_auto", "generate_suricata_rule"]
