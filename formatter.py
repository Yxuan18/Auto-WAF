# -*- coding: utf-8 -*-
"""
输出格式化模块
负责将生成的规则格式化为可读输出
"""
from typing import List, Dict, Any

from generators.suricata import generate_suricata_rule


# ============================================================
# 类型别名
# ============================================================
PocInfo = Dict[str, Any]


# ============================================================
# 格式化输出
# ============================================================
def format_output(
    rules: List[str],
    poc_info: PocInfo,
    vuln_type: str,
    vuln_name: str,
    matched_payload: str,
    confidence: float,
    selected_param: str = "",
    raw_input: str = ""
) -> str:
    """格式化最终输出"""
    output: List[str] = []

    # 检测说明
    if matched_payload:
        output.append(f"[*] 检测到漏洞类型: {vuln_type} ({confidence:.0%})")
        output.append(f"[*] 匹配 Payload: {matched_payload}")
    output.append("")

    # ModSecurity 规则
    output.append("【ModSecurity SecRule 规则】")
    output.append("")
    for r in rules:
        output.append(r)
    output.append("")

    # Suricata 规则
    output.append("【Suricata 规则】")
    output.append("")
    suricata_rule = generate_suricata_rule(poc_info, vuln_type, selected_param, raw_input)
    output.append(suricata_rule)
    output.append("")

    return "\n".join(output)
