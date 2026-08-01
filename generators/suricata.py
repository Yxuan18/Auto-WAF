# -*- coding: utf-8 -*-
"""
Suricata 规则生成器
"""
import random
from typing import Dict, Any

from constants import REGEX_TEMPLATES, TAG_MAP
from detector import find_payload_params
from extensions import extract_dangerous_extensions, build_suricata_file_ext


# ============================================================
# 类型别名
# ============================================================
PocInfo = Dict[str, Any]


# ============================================================
# Suricata 规则生成子函数
# ============================================================
def _find_param_location(poc_info: PocInfo, param_name: str) -> tuple:
    """查找参数位置，返回 (param_value, location)"""
    for pn, pv in poc_info.get("query_params", {}).items():
        if pn == param_name:
            return pv, "query"
    for pn, pv in poc_info.get("body_params", {}).items():
        if pn == param_name:
            return pv, "body"
    return "", ""


def _build_body_pcre(param_name: str, regex_template: str, content_type: str, location: str) -> str:
    """根据 content_type 构建 body PCRE"""
    if "json" in content_type:
        return (f'http.request_body; url_decode; pcre:"/\x22{param_name}'
                f'\x22\x3a\x22[^\x0a\x0d\x22]*?{regex_template}/i";')
    elif "form-data" in content_type:
        return (f'http.request_body; pcre:"/\bname=\x22{param_name}'
                f'\x22[\s\S]*?{regex_template}/i";')
    else:
        return (f'http.request_body; url_decode; pcre:"/\b{param_name}'
                f'=[^\x0a\x0d\x26]*?{regex_template}/i";')


def _build_uri_pcre(param_name: str, regex_template: str, param_value: str) -> str:
    """构建 URI PCRE"""
    pcre_body = regex_template if param_value else r'[^\x0a\x0d\x26]+'
    return (f'http.uri; url_decode; pcre:"/\b{param_name}'
            f'={pcre_body}/i";')


def _build_auto_payload_rules(poc_info: PocInfo, regex_template: str) -> list:
    """自动检测 payload 参数并生成规则"""
    parts = []
    payload_params = find_payload_params(poc_info, vuln_type="")
    
    if not payload_params:
        return parts
    
    param_name, param_value, location = payload_params[0]
    if not regex_template or param_name == "ARGS":
        return parts
    
    content_type = poc_info.get("content_type", "")
    
    if param_name == "__XML_BODY__":
        parts.append(f'http.request_body; pcre:"/{regex_template}/i";')
    elif location == "query":
        parts.append(
            f'http.uri; url_decode; pcre:"/\b{param_name}'
            f'=[^\x0a\x0d\x26]*?{regex_template}/i";'
        )
    else:
        parts.append(_build_body_pcre(param_name, regex_template, content_type, location))
    
    return parts


def _build_metadata(vuln_type: str) -> str:
    """构建 metadata 部分"""
    metadata = "service http;"
    if vuln_type:
        tag = TAG_MAP.get(vuln_type, "").replace("TOPWAF_CRS/", "")
        if tag:
            metadata += f" classtype:{tag};"
    return metadata


def _finalize_rule(parts: list, vuln_type: str) -> str:
    """完成规则构建"""
    sid = random.randint(1000000, 99999999)
    rule_body = " ".join(parts)
    return f'alert http any any -> any any ({rule_body} metadata:{_build_metadata(vuln_type)}; sid:{sid};)'


# ============================================================
# 规则生成
# ============================================================
def _generate_file_upload_rule(poc_info: PocInfo, raw_input: str) -> str:
    """生成文件上传专用 Suricata 规则"""
    parts = ["flow:to_server;"]
    method = poc_info.get("method", "")
    if method:
        parts.append(f'http.method; content:"{method}";')

    path = poc_info.get("path", "")
    if path:
        parts.append(f'http.uri; content:"{path}"; fast_pattern; nocase;')

    extensions = extract_dangerous_extensions(raw_input)
    ext_pcre = build_suricata_file_ext(extensions)
    parts.append(
        f'http.request_body; pcre:"/\\bfilename=\\x22[^\\x0a\\x0d\\x22]*?{ext_pcre}/i";'
    )

    metadata = "service http;"
    tag = TAG_MAP.get("File_Upload", "").replace("TOPWAF_CRS/", "")
    if tag:
        metadata += f" classtype:{tag};"

    sid = random.randint(1000000, 99999999)
    rule_body = " ".join(parts)
    return f'alert http any any -> any any ({rule_body} metadata:{metadata}; sid:{sid};)'


def generate_suricata_rule(
    poc_info: PocInfo,
    vuln_type: str,
    selected_param: str = "",
    raw_input: str = ""
) -> str:
    """生成 Suricata 格式规则"""
    # File_Upload 专用处理
    if vuln_type == "File_Upload" and raw_input:
        return _generate_file_upload_rule(poc_info, raw_input)

    parts = ["flow:to_server;"]
    path = poc_info.get("path", "")
    
    if path:
        parts.append(f'http.uri; url_decode; content:"{path}"; nocase;')

    regex_template = REGEX_TEMPLATES.get(vuln_type)

    # 有指定参数
    if selected_param:
        param_value, param_location = _find_param_location(poc_info, selected_param)
        content_type = poc_info.get("content_type", "")
        
        if param_location == "body":
            parts.append(_build_body_pcre(selected_param, regex_template, content_type, param_location))
        else:
            parts.append(_build_uri_pcre(selected_param, regex_template, param_value))
    # 自动检测 payload
    elif regex_template:
        auto_rules = _build_auto_payload_rules(poc_info, regex_template)
        if auto_rules:
            parts.extend(auto_rules)
        else:
            parts.append(f'http.uri; url_decode; pcre:"/{regex_template}/i";')

    return _finalize_rule(parts, vuln_type)



    parts = ["flow:to_server;"]

    path = poc_info.get("path", "")
    if path:
        parts.append(f'http.uri; url_decode; content:"{path}"; nocase;')

    regex_template = REGEX_TEMPLATES.get(vuln_type)

    if selected_param:
        param_value = ""
        param_location = ""
        for pn, pv in poc_info.get("query_params", {}).items():
            if pn == selected_param:
                param_value = pv
                param_location = "query"
                break
        if not param_location:
            for pn, pv in poc_info.get("body_params", {}).items():
                if pn == selected_param:
                    param_value = pv
                    param_location = "body"
                    break

        if param_location == "body":
            content_type = poc_info.get("content_type", "")
            if "json" in content_type:
                parts.append(
                    f'http.request_body; url_decode; pcre:"/\\x22{selected_param}'
                    f'\\x22\\x3a\\x22[^\\x0a\\x0d\\x22]*?{regex_template}/i";'
                )
            elif "form-data" in content_type:
                parts.append(
                    f'http.request_body; pcre:"/\\bname=\\x22{selected_param}'
                    f'\\x22[\\s\\S]*?{regex_template}/i";'
                )
            else:
                parts.append(
                    f'http.request_body; url_decode; pcre:"/\\b{selected_param}'
                    f'=[^\\x0a\\x0d\\x26]*?{regex_template}/i";'
                )
        else:
            pcre_body = regex_template if param_value else r'[^\x0a\x0d\x26]+'
            parts.append(
                f'http.uri; url_decode; pcre:"/\\b{selected_param}'
                f'=[^\\x0a\\x0d\\x26]*?{pcre_body}/i";'
            )
    else:
        payload_params = find_payload_params(poc_info, vuln_type)
        if payload_params:
            param_name, param_value, location = payload_params[0]
            if regex_template and param_name != "ARGS":
                if param_name == "__XML_BODY__":
                    parts.append(f'http.request_body; pcre:"/{regex_template}/i";')
                elif location == "query":
                    parts.append(
                        f'http.uri; url_decode; pcre:"/\\b{param_name}'
                        f'=[^\\x0a\\x0d\\x26]*?{regex_template}/i";'
                    )
                else:
                    content_type = poc_info.get("content_type", "")
                    if "json" in content_type:
                        parts.append(
                            f'http.request_body; url_decode; pcre:"/\\x22{param_name}'
                            f'\\x22\\x3a\\x22[^\\x0a\\x0d\\x22]*?{regex_template}/i";'
                        )
                    elif "form-data" in content_type:
                        parts.append(
                            f'http.request_body; pcre:"/\\bname=\\x22{param_name}'
                            f'\\x22[\\s\\S]*?{regex_template}/i";'
                        )
                    else:
                        parts.append(
                            f'http.request_body; url_decode; pcre:"/\\b{param_name}'
                            f'=[^\\x0a\\x0d\\x26]*?{regex_template}/i";'
                        )
        elif regex_template:
            parts.append(f'http.uri; url_decode; pcre:"/{regex_template}/i";')

    metadata = "service http;"
    if vuln_type:
        tag = TAG_MAP.get(vuln_type, "").replace("TOPWAF_CRS/", "")
        if tag:
            metadata += f" classtype:{tag};"

    sid = random.randint(1000000, 99999999)
    rule_body = " ".join(parts)
    return f'alert http any any -> any any ({rule_body} metadata:{metadata}; sid:{sid};)'
