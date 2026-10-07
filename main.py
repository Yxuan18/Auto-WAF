# -*- coding: utf-8 -*-
"""
WAF 规则自动生成器 - CLI 入口
"""
import sys
import logging
from typing import Any, Dict

from constants import REGEX_TEMPLATES, VULN_NAME_MAP, SUPPORTED_VULN_TYPES
from parser import parse_http_input
from detector import detect_vuln_type, find_payload_params
from generators.sec_rules import generate_sec_rules
from generators.suricata import generate_suricata_rule
from formatter import format_output

# 日志配置推迟到 __main__ / server 启动时执行，
# 避免宿主程序 import 本库时被改写全局 logging 配置
logger = logging.getLogger(__name__)


# ============================================================
# 主 API
# ============================================================
AnalyzeResult = Dict[str, Any]


def analyze_http(
    http_raw: str,
    vuln_type: str = "",
    selected_param: str = "",
    rule_name: str = ""
) -> AnalyzeResult:
    """
    结构化分析入口：解析报文、识别漏洞类型、生成双格式规则。

    返回 dict：
        成功: ok=True + vuln_type / vuln_name / matched_payload / confidence /
              selected_param / sec_rules(List[str]) / suricata_rule
        失败: ok=False + error(原因文本)

    供 HTTP 服务等程序化调用方使用；人类可读文本走 auto_gen_rule。
    """
    poc_info = parse_http_input(http_raw)
    manual = bool(vuln_type)
    matched_payload = ""
    confidence = 0.0

    if manual:
        if vuln_type not in REGEX_TEMPLATES and vuln_type not in ("Auth_Bypass",):
            return {"ok": False, "error": f"不支持的漏洞类型: {vuln_type}。支持: {', '.join(sorted(SUPPORTED_VULN_TYPES))}"}
    else:
        vuln_type, matched_payload, confidence = detect_vuln_type(poc_info)

    if not vuln_type:
        return {"ok": False, "error": "未能识别漏洞类型，请手动指定。"}

    # 自动模式下补齐 payload 参数；手动模式只用调用方给的值
    if not manual and not selected_param:
        payload_params = find_payload_params(poc_info, vuln_type)
        if payload_params:
            selected_param = payload_params[0][0]

    path = poc_info.get("path", "/unknown")
    vuln_name = rule_name if rule_name else f"{path} {VULN_NAME_MAP.get(vuln_type, vuln_type)}"

    sec_rules = generate_sec_rules(poc_info, vuln_type, vuln_name, http_raw, selected_param)
    suricata_rule = generate_suricata_rule(poc_info, vuln_type, selected_param, http_raw)

    return {
        "ok": True,
        "vuln_type": vuln_type,
        "vuln_name": vuln_name,
        "matched_payload": matched_payload,
        # 手动指定类型时无检测过程，按既有展示逻辑置 1.0
        "confidence": 1.0 if manual else confidence,
        "selected_param": selected_param,
        "sec_rules": sec_rules,
        "suricata_rule": suricata_rule,
    }


def auto_gen_rule(http_raw: str, rule_name: str = "") -> str:
    """
    自动识别漏洞类型并生成规则（人类可读文本输出）
    """
    return _format_result(analyze_http(http_raw, rule_name=rule_name), http_raw)


def auto_gen_rule_with_type(
    http_raw: str,
    vuln_type: str = "",
    selected_param: str = "",
    rule_name: str = ""
) -> str:
    """
    带手动指定漏洞类型的入口（人类可读文本输出）
    selected_param: 用户手动选定的参数名
    rule_name: 自定义规则名称（替换 msg）
    """
    return _format_result(analyze_http(http_raw, vuln_type, selected_param, rule_name), http_raw)


def _format_result(result: AnalyzeResult, http_raw: str) -> str:
    """把 analyze_http 的结构化结果渲染为文本（供 CLI 与旧 API）"""
    if not result["ok"]:
        return f"[!] {result['error']}"

    poc_info = parse_http_input(http_raw)
    return format_output(
        result["sec_rules"], poc_info, result["vuln_type"],
        result["matched_payload"], result["confidence"], result["selected_param"],
        raw_input=http_raw, suricata_rule=result["suricata_rule"]
    )


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
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
        # 管道输入（echo ... | python main.py）结束时 input() 抛 EOF，视为输入完毕，正常路径
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
