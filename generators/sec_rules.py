# -*- coding: utf-8 -*-
"""
ModSecurity SecRule 规则生成器
"""
import re
import random
from typing import List, Tuple, Dict, Any

from constants import (
    REGEX_TEMPLATES, TAG_MAP, VULN_NAME_MAP, DEFAULT_REV,
    CONTEXT_PARAM_WHITELIST
)
from parser import collect_all_params
from detector import find_payload_params, get_tag
from extensions import (
    extract_dangerous_extensions, extract_filename_extensions,
    extract_multipart_file_field_names, extract_chain_args_from_params,
    extract_specific_chain_args, build_files_rx, has_file_upload_markers,
    has_directory_traversal
)
from encoder import extract_response_keywords_list, extract_response_header_keywords


# ============================================================
# 类型别名
# ============================================================
PocInfo = Dict[str, Any]


# ============================================================
# 辅助函数
# ============================================================
def _escape_rx(rx: str) -> str:
    """转义正则中的引号"""
    return rx.replace('"', '\\"')


def _build_path_chain(path: str, vuln_name: str, tag: str, rev: str) -> str:
    """构建路径链"""
    return (
        f'SecRule REQUEST_FILENAME "@pm {path}" '
        f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
        f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
    )


def _build_context_chain(param_name: str, param_value: str) -> str:
    """构建上下文参数链"""
    return f'SecRule "ARGS:{param_name}" "@pm {param_value}" "chain"'


# ============================================================
# 通用规则生成子函数
# ============================================================
def _build_json_rules(poc_info: PocInfo, path: str, vuln_name: str, 
                       tag: str, rev: str, selected_param: str) -> List[str]:
    """生成 JSON 报文的规则"""
    rules = []
    regex_template = REGEX_TEMPLATES.get("SQLi", "")  # JSON 通用正则
    
    # 尝试获取当前漏洞类型的正则
    from detector import find_payload_params
    from parser import collect_all_params
    
    rx_escaped = _escape_rx(regex_template)
    
    if path:
        rules.append(
            f'SecRule REQUEST_FILENAME "@pm {path}" '
            f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
        )
    
    if selected_param:
        leaf_key = selected_param.rsplit('.', 1)[-1]
        leaf_key = re.sub(r'\[[^\]]*\]', '', leaf_key) or selected_param
        rules.append(
            f'SecRule "ARGS:{leaf_key}" "@rx {rx_escaped}" '
            f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
            f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
        )
    else:
        rules.append(
            f'SecRule REQUEST_BODY "@rx {rx_escaped}" '
            f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
            f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
        )
    return rules


def _build_path_type_rules(poc_info: PocInfo, path: str, vuln_type: str,
                            vuln_name: str, tag: str, rev: str) -> List[str]:
    """生成路径型漏洞规则（Dir_Traversal, File_Read 等）"""
    rules = []
    path_regex = REGEX_TEMPLATES.get(vuln_type, "")
    
    if path_regex and re.search(path_regex, path):
        rules.append(
            f'SecRule REQUEST_FILENAME "@pm {path}" '
            f'"{rev},capture,t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\','
            f'setvar:\'tx.msg=%{{rule.msg}}\','
            f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
        )
    return rules


def _build_payload_rules(poc_info: PocInfo, vuln_type: str, 
                          vuln_name: str, tag: str, rev: str,
                          selected_param: str, payload_params: List) -> List[str]:
    """生成 payload 参数规则"""
    rules = []
    regex_template = REGEX_TEMPLATES.get(vuln_type)
    if not regex_template:
        return rules
    
    rx_escaped = _escape_rx(regex_template)
    
    # XML body
    if not selected_param and payload_params and payload_params[0][0] == "__XML_BODY__":
        rules.append(
            f'SecRule REQUEST_BODY "@rx {rx_escaped}" '
            f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
            f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
        )
        return rules
    
    # 获取非 payload 参数
    all_params = collect_all_params(poc_info)
    if selected_param:
        non_payload = [(k, v) for k, v in all_params if k != selected_param]
    else:
        payload_names = {p[0] for p in payload_params}
        non_payload = [(k, v) for k, v in all_params if k not in payload_names]
    
    # 优先白名单参数
    priority = [(k, v) for k, v in non_payload if k in CONTEXT_PARAM_WHITELIST]
    others = [(k, v) for k, v in non_payload if k not in CONTEXT_PARAM_WHITELIST]
    non_payload = priority + others
    
    # 添加 context chain
    for np_name, np_val in non_payload[:3]:
        rules.append(_build_context_chain(np_name, np_val))
    
    # 添加 payload 检测规则
    target_params = [(selected_param, "", "")] if selected_param else payload_params
    total = len(target_params)
    
    for i, (pn, pv, ploc) in enumerate(target_params):
        transform = ",t:base64Decode" if poc_info.get("is_base64_param", {}).get(pn) else ""
        is_last = (i == total - 1)
        action_prefix = "capture" if is_last else "chain,capture"
        
        if ploc == "name":
            rules.append(
                f'SecRule ARGS_NAMES "@rx {rx_escaped}" '
                f'"{action_prefix},setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
        elif ploc == "header":
            rules.append(
                f'SecRule "REQUEST_HEADERS:{pn}" "@rx {rx_escaped}" '
                f'"{action_prefix},setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
        else:
            rules.append(
                f'SecRule "ARGS:{pn}" "@rx {rx_escaped}" '
                f'"{action_prefix}{transform},setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
    
    return rules


def _build_fallback_rules(poc_info: PocInfo, vuln_type: str) -> List[str]:
    """生成 fallback 规则（无 payload 时兜底）"""
    rules = []
    regex_template = REGEX_TEMPLATES.get(vuln_type)
    if not regex_template:
        return rules
    
    rx_escaped = _escape_rx(regex_template)
    raw_body = poc_info.get("request_body_raw", "").strip()
    
    if raw_body and raw_body.startswith("<"):
        rules.append(
            f'SecRule REQUEST_BODY "@rx {rx_escaped}" '
            f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
            f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
        )
    else:
        all_params = collect_all_params(poc_info)
        if all_params:
            context_params = []
            other_params = []
            for k, v in all_params:
                if k in CONTEXT_PARAM_WHITELIST or re.search(r'\b' + re.escape(k) + r'\b', regex_template, re.I):
                    context_params.append((k, v))
                else:
                    other_params.append((k, v))
            
            if not context_params:
                context_params, other_params = other_params[:-1], [other_params[-1]]

            for cp_name, cp_val in context_params[:3]:
                rules.append(_build_context_chain(cp_name, cp_val))

            if other_params:
                rx_name = other_params[0][0]
                rules.append(
                    f'SecRule "ARGS:{rx_name}" "@rx {rx_escaped}" '
                    f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
                    f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
                )
        else:
            rules.append(
                f'SecRule ARGS "@rx {rx_escaped}" '
                f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
    return rules

# ============================================================
# 通用规则生成
# ============================================================
def generate_generic_rules(
    poc_info: PocInfo,
    vuln_type: str,
    vuln_name: str,
    tag: str,
    rev: str,
    selected_param: str = ""
) -> List[str]:
    """生成通用规则（非特殊类型）- 简化后的主函数"""
    path = poc_info.get("path", "")
    
    # JSON 报文特例
    if poc_info.get("json_body"):
        return _build_json_rules(poc_info, path, vuln_name, tag, rev, selected_param)
    
    # 路径型漏洞
    if path and vuln_type in ("Dir_Traversal", "File_Read", "File_Include", "SSRF"):
        rules = _build_path_type_rules(poc_info, path, vuln_type, vuln_name, tag, rev)
        if rules:
            return rules
    
    rules = []
    
    # 路径链
    if path:
        rules.append(_build_path_chain(path, vuln_name, tag, rev))
    
    # payload 参数查找
    payload_params = [(selected_param, "", "")] if selected_param else find_payload_params(poc_info, vuln_type)
    
    if payload_params:
        rules.extend(_build_payload_rules(poc_info, vuln_type, vuln_name, tag, rev, selected_param, payload_params))
    else:
        rules.extend(_build_fallback_rules(poc_info, vuln_type))
    
    return rules



def generate_sec_rules(
    poc_info: PocInfo,
    vuln_type: str,
    vuln_name: str,
    raw_input: str = "",
    selected_param: str = ""
) -> List[str]:
    """
    生成 ModSecurity SecRule 规则
    selected_param: 用户手动选定的参数名，优先级高于自动检测
    """
    tag = get_tag(vuln_type)
    rev = DEFAULT_REV

    # 特殊类型处理
    if vuln_type == "File_Upload":
        return _generate_file_upload_rules(poc_info, vuln_name, tag, rev, raw_input)

    if vuln_type == "Info_Leak":
        return _generate_info_leak_rules(poc_info, vuln_name, tag, rev)

    if vuln_type == "Auth_Bypass":
        return _generate_auth_bypass_rules(poc_info, vuln_name, tag, rev)

    return generate_generic_rules(poc_info, vuln_type, vuln_name, tag, rev, selected_param)


def generate_sec_rules_auto(
    poc_info: PocInfo,
    vuln_type: str,
    vuln_name: str,
    raw_input: str = ""
) -> List[str]:
    """自动检测参数生成规则"""
    from detector import find_payload_params
    selected_param = ""
    payload_params = find_payload_params(poc_info, vuln_type)
    if payload_params:
        selected_param = payload_params[0][0]
    return generate_sec_rules(poc_info, vuln_type, vuln_name, raw_input, selected_param)
