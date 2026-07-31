# -*- coding: utf-8 -*-
"""
WAF 规则自动生成器 - CLI 入口
"""
import sys
import logging
from typing import Optional

from constants import REGEX_TEMPLATES, VULN_NAME_MAP, SUPPORTED_VULN_TYPES
from parser import parse_http_input
from detector import detect_vuln_type, find_payload_params
from generators.sec_rules import generate_sec_rules
from generators.suricata import generate_suricata_rule
from formatter import format_output

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ============================================================
# 主 API
# ============================================================
def auto_gen_rule(http_raw: str, rule_name: str = "") -> str:
    """
    自动识别漏洞类型并生成规则
    """
    poc_info = parse_http_input(http_raw)
    vuln_type, matched_payload, confidence = detect_vuln_type(poc_info)

    if not vuln_type:
        return "[!] 未能识别漏洞类型，请手动指定。"

    # 自动识别 payload 参数
    selected_param = ""
    payload_params = find_payload_params(poc_info, vuln_type)
    if payload_params:
        selected_param = payload_params[0][0]

    path = poc_info.get("path", "/unknown")
    vuln_name = rule_name if rule_name else f"{path} {VULN_NAME_MAP.get(vuln_type, vuln_type)}"
    rules = generate_sec_rules(poc_info, vuln_type, vuln_name, http_raw, selected_param)

    return format_output(rules, poc_info, vuln_type, vuln_name, matched_payload, confidence,
                        raw_input=http_raw)


def auto_gen_rule_with_type(
    http_raw: str,
    vuln_type: str = "",
    selected_param: str = "",
    rule_name: str = ""
) -> str:
    """
    带手动指定漏洞类型的入口
    selected_param: 用户手动选定的参数名
    rule_name: 自定义规则名称（替换 msg）
    """
    poc_info = parse_http_input(http_raw)

    if vuln_type:
        if vuln_type not in REGEX_TEMPLATES and vuln_type not in ("Auth_Bypass",):
            return f"[!] 不支持的漏洞类型: {vuln_type}。支持: {', '.join(sorted(SUPPORTED_VULN_TYPES))}"
    else:
        vuln_type, _, _ = detect_vuln_type(poc_info)

    if not vuln_type:
        return "[!] 未能识别漏洞类型，请手动指定。"

    path = poc_info.get("path", "/unknown")
    vuln_name = rule_name if rule_name else f"{path} {VULN_NAME_MAP.get(vuln_type, vuln_type)}"
    rules = generate_sec_rules(poc_info, vuln_type, vuln_name, http_raw, selected_param)

    return format_output(rules, poc_info, vuln_type, vuln_name, "", 1.0, selected_param,
                        raw_input=http_raw)


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  WAF 规则自动生成器")
    print("  输入 HTTP 请求/响应（支持多行，输入 END 结束）")
    print("=" * 60)
    print()

    lines = []
    print("请输入 HTTP 报文:")
    try:
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
    except EOFError:
        pass

    raw = "\n".join(lines).strip()
    if not raw:
        logger.error("未输入任何内容")
        sys.exit(1)

    logger.info("开始分析 HTTP 报文...")

    vuln_type = input("指定漏洞类型 (回车=自动检测): ").strip()

    if vuln_type:
        result = auto_gen_rule_with_type(raw, vuln_type)
    else:
        result = auto_gen_rule(raw)

    print()
    print(result)
    logger.info("规则生成完成")
