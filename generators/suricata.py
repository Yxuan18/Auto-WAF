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
    """
    生成 Suricata 格式规则
    """
    # File_Upload 专用处理
    if vuln_type == "File_Upload" and raw_input:
        return _generate_file_upload_rule(poc_info, raw_input)

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
