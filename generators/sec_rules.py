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
    """生成通用规则（非特殊类型）"""
    rules: List[str] = []
    path = poc_info.get("path", "")
    is_json = bool(poc_info.get("json_body"))
    regex_template = REGEX_TEMPLATES.get(vuln_type, "")

    # JSON 报文特例
    if is_json and regex_template:
        rx_escaped = _escape_rx(regex_template)
        if path:
            rules.append(
                f'SecRule REQUEST_FILENAME "@pm {path}" '
                f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
                f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
            )
            if selected_param:
                leaf_key = selected_param.rsplit('.', 1)[-1]
                leaf_key = re.sub(r'\[[^\]]*\]', '', leaf_key)
                if not leaf_key:
                    leaf_key = selected_param
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

    # 路径型漏洞
    if path and vuln_type in ("Dir_Traversal", "File_Read", "File_Include", "SSRF"):
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

    # 路径链
    if path:
        rules.append(_build_path_chain(path, vuln_name, tag, rev))

    # payload 参数查找
    if selected_param:
        payload_params = [(selected_param, "", "")]
    else:
        payload_params = find_payload_params(poc_info, vuln_type)

    regex_template = REGEX_TEMPLATES.get(vuln_type)

    if payload_params and regex_template:
        rx_escaped = _escape_rx(regex_template)

        # XML body 单独处理
        if not selected_param and payload_params[0][0] == "__XML_BODY__":
            rules.append(
                f'SecRule REQUEST_BODY "@rx {rx_escaped}" '
                f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
        elif selected_param:
            # 用户手动选定参数
            all_params = collect_all_params(poc_info)
            non_payload = [(k, v) for k, v in all_params if k != selected_param]
            priority = [(k, v) for k, v in non_payload if k in CONTEXT_PARAM_WHITELIST]
            others = [(k, v) for k, v in non_payload if k not in CONTEXT_PARAM_WHITELIST]
            non_payload = priority + others

            for np_name, np_val in non_payload[:3]:
                rules.append(_build_context_chain(np_name, np_val))

            rules.append(
                f'SecRule "ARGS:{selected_param}" "@rx {rx_escaped}" '
                f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
        else:
            # 自动检测
            all_params = collect_all_params(poc_info)
            payload_names = {p[0] for p in payload_params}
            non_payload = [(k, v) for k, v in all_params if k not in payload_names]
            priority = [(k, v) for k, v in non_payload if k in CONTEXT_PARAM_WHITELIST]
            others = [(k, v) for k, v in non_payload if k not in CONTEXT_PARAM_WHITELIST]
            non_payload = priority + others

            for np_name, np_val in non_payload[:3]:
                rules.append(_build_context_chain(np_name, np_val))

            total = len(payload_params)
            for i, (pn, pv, ploc) in enumerate(payload_params):
                transform = ""
                if poc_info.get("is_base64_param", {}).get(pn):
                    transform = ",t:base64Decode"
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

    # Fallback: 无 payload 参数
    if not payload_params and not selected_param:
        regex_template = REGEX_TEMPLATES.get(vuln_type)
        if regex_template:
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
                        if (k in CONTEXT_PARAM_WHITELIST or
                            re.search(r'\b' + re.escape(k) + r'\b', regex_template, re.I)):
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
# 文件上传规则生成
# ============================================================
def _generate_file_upload_rules(
    poc_info: PocInfo,
    vuln_name: str,
    tag: str,
    rev: str,
    raw_input: str
) -> List[str]:
    """生成文件上传专用规则"""
    rules: List[str] = []
    path = poc_info.get("path", "")

    # 提取 chain 参数
    chain_args = extract_chain_args_from_params(poc_info)
    if not chain_args:
        chain_args = extract_specific_chain_args(raw_input)

    # 提取 multipart 文件字段名
    file_field_names = extract_multipart_file_field_names(raw_input)
    if file_field_names:
        file_field_set = set(file_field_names)
        chain_args = [(k, v) for k, v in chain_args if k not in file_field_set]

    # 提取扩展名
    extensions = extract_dangerous_extensions(raw_input)
    has_filename = bool(re.search(r'filename\s*[=:]', raw_input, re.I))
    if not extensions and has_filename:
        extensions = extract_filename_extensions(raw_input)

    # 无扩展名也无上传特征 → 回退通用规则
    if not extensions and not has_file_upload_markers(raw_input):
        return generate_generic_rules(poc_info, "File_Upload", vuln_name, tag, rev)

    files_rx = build_files_rx(extensions)
    rx_escaped = _escape_rx(files_rx)

    chain_header_actions = (
        f"chain,{rev},t:none,t:urlDecodeUni,msg:'{vuln_name}',tag:'{tag}',"
        f"logdata:'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}'"
    )

    # 路径链 / 参数链
    if path and path != "/":
        rules.append(f'SecRule REQUEST_FILENAME "@pm {path}" "{chain_header_actions}"')
        for param_name, param_value in chain_args:
            rules.append(f'SecRule "ARGS:{param_name}" "@pm {param_value}" "chain"')
    elif chain_args:
        first_name, first_val = chain_args[0]
        rules.append(f'SecRule "ARGS:{first_name}" "@pm {first_val}" "{chain_header_actions}"')
        for param_name, param_value in chain_args[1:]:
            rules.append(f'SecRule "ARGS:{param_name}" "@pm {param_value}" "chain"')

    has_chain_start = bool(rules)

    # FILES_NAMES 规则
    for idx, fname in enumerate(file_field_names):
        is_last_name = (idx == len(file_field_names) - 1)
        if not has_chain_start and idx == 0:
            rules.append(f'SecRule FILES_NAMES "@pm {fname}" "{chain_header_actions}"')
        else:
            rules.append(f'SecRule FILES_NAMES "@pm {fname}" "chain"')

    # FILES / MULTIPART_FILENAME
    var_name = "MULTIPART_FILENAME" if has_directory_traversal(raw_input) else "FILES"
    rules.append(
        f'SecRule {var_name} "@rx {rx_escaped}" '
        f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
        f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
    )

    return rules


# ============================================================
# 信息泄漏规则生成
# ============================================================
def _generate_info_leak_rules(
    poc_info: PocInfo,
    vuln_name: str,
    tag: str,
    rev: str
) -> List[str]:
    """生成信息泄漏专用规则"""
    rules: List[str] = []
    path = poc_info.get("path", "")
    resp_status = poc_info.get("response_status", "")
    resp_body = poc_info.get("response_body", "")
    resp_headers = poc_info.get("response_headers", {})

    # 路径型泄露检测
    path_leak_patterns = [
        r"/actuator/", r"/swagger", r"/api-docs", r"/druid/",
        r"/heapdump", r"/threaddump", r"/trace", r"/mappings",
        r"/configprops", r"/beans", r"/autoconfig", r"/jolokia/",
        r"/phpinfo", r"/server-status", r"/server-info",
        r"/\.env", r"/\.git/", r"/WEB-INF/", r"/META-INF/",
        r"/\.svn/", r"/\.DS_Store",
    ]
    is_path_leak = any(re.search(p, path, re.I) for p in path_leak_patterns)

    # 路径链 / 参数名链
    if path and path != "/":
        rules.append(
            f'SecRule REQUEST_FILENAME "@pm {path}" '
            f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
        )
    elif poc_info.get("query_params"):
        param_names = list(poc_info["query_params"].keys())
        pm_list = " ".join(param_names)
        rules.append(
            f'SecRule ARGS_NAMES "@pm {pm_list}" '
            f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
        )

    if is_path_leak:
        rules[-1] = rules[-1].replace('"chain,', '"')
        return rules

    # Referer/Cookie 校验链
    rules.append(f'SecRule &REQUEST_HEADERS:Referer "@eq 0" "chain"')
    rules.append(f'SecRule &REQUEST_COOKIES "@eq 0" "chain"')

    # 响应头特征
    resp_header_kw = extract_response_header_keywords(resp_headers)
    for hk, hv in resp_header_kw[:1]:
        rules.append(
            f'SecRule RESPONSE_HEADERS:{hk} "@contains {hv}" "chain"'
        )

    # 响应状态码
    if resp_status:
        status_code = resp_status.split()[1] if " " in resp_status else resp_status
        rules.append(f'SecRule RESPONSE_STATUS "@pm {status_code}" "chain"')

    # 响应体特征
    body_kws = extract_response_keywords_list(resp_body)
    if body_kws:
        total = len(body_kws)
        for i, (op, content) in enumerate(body_kws):
            is_last = (i == total - 1)
            action = (
                f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            ) if is_last else '"chain"'
            content_escaped = content.replace('"', '\\"')
            rules.append(
                f'SecRule RESPONSE_BODY "{op} {content_escaped}" {action}'
            )
    elif resp_header_kw:
        rules[-1] = rules[-1].replace('"chain"', 
            '"capture,setvar:\'tx.msg=%{rule.msg}\',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}"')
    elif resp_status:
        rules[-1] = rules[-1].replace('"chain"',
            '"capture,setvar:\'tx.msg=%{rule.msg}\',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}"')

    return rules


# ============================================================
# 认证绕过规则生成
# ============================================================
def _generate_auth_bypass_rules(
    poc_info: PocInfo,
    vuln_name: str,
    tag: str,
    rev: str
) -> List[str]:
    """生成认证绕过专用规则"""
    rules: List[str] = []
    path = poc_info.get("path", "")

    if path and path != "/":
        rules.append(
            f'SecRule REQUEST_FILENAME "@pm {path}" '
            f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
        )
    elif poc_info.get("query_params"):
        param_names = list(poc_info["query_params"].keys())
        pm_list = " ".join(param_names)
        rules.append(
            f'SecRule ARGS_NAMES "@pm {pm_list}" '
            f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
        )

    rules.append(f'SecRule &REQUEST_HEADERS:Referer "@eq 0" "chain"')
    rules.append(f'SecRule &REQUEST_COOKIES "@eq 0" "chain"')

    resp_status = poc_info.get("response_status", "")
    if resp_status:
        status_code = resp_status.split()[1] if " " in resp_status else resp_status
        rules.append(f'SecRule RESPONSE_STATUS "@pm {status_code}" "chain"')

    resp_header_kw = extract_response_header_keywords(poc_info.get("response_headers", {}))
    if resp_header_kw:
        hk, hv = resp_header_kw[0]
        rules.append(
            f'SecRule RESPONSE_HEADERS:{hk} "@contains {hv}" '
            f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
            f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
        )

    return rules


# ============================================================
# 主入口
# ============================================================
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
