# -*- coding: utf-8 -*-
"""
漏洞检测模块
负责自动识别漏洞类型、查找 payload 参数
"""
import re
from typing import List, Tuple, Dict, Any

from constants import REGEX_TEMPLATES, CONTEXT_PARAM_WHITELIST, TAG_MAP
from parser import (
    full_unquote, try_base64_decode, collect_all_params,
    get_all_param_names
)


# ============================================================
# 类型别名
# ============================================================
PocInfo = Dict[str, Any]
PayloadParam = Tuple[str, str, str]  # (param_name, param_value, location)


# ============================================================
# 漏洞检测子函数
# ============================================================
def _build_detection_text(poc_info: PocInfo) -> str:
    """构建用于漏洞检测的完整文本"""
    text_parts = []
    
    # 路径
    path = poc_info.get("path")
    if path:
        text_parts.append(path)
    
    # 请求头
    for k, v in poc_info.get("headers", {}).items():
        text_parts.append(f"{k}: {v}")
    
    # 查询参数（含解码）
    for k, v in poc_info.get("query_params", {}).items():
        text_parts.append(f"{k}={v}")
        dv = full_unquote(v)
        if dv != v:
            text_parts.append(f"{k}={dv}")
    
    # 请求体参数
    for k, v in poc_info.get("body_params", {}).items():
        if k != "__XML_BODY__":
            text_parts.append(f"{k}={v}")
            dv = full_unquote(v)
        if dv != v:
                text_parts.append(f"{k}={dv}")
    
    # 原始请求体
    raw_body = poc_info.get("request_body_raw")
    if raw_body:
        text_parts.append(raw_body)
    
    # 响应体
    resp_body = poc_info.get("response_body")
    if resp_body:
        text_parts.append(resp_body)
    
    # 响应头
    for k, v in poc_info.get("response_headers", {}).items():
        text_parts.append(f"{k}: {v}")
    
    # Base64 解码
    all_params = {**poc_info.get("query_params", {}), **poc_info.get("body_params", {})}
    filtered = {k: v for k, v in all_params.items() if k != "__XML_BODY__"}
    for decoded in try_base64_decode(filtered).values():
        text_parts.append(decoded)
    
    return "\n".join(text_parts)


def _match_vuln_patterns(combined_text: str) -> Tuple[str, str, float]:
    """匹配漏洞模式"""
    detections = [
        ("File_Upload", REGEX_TEMPLATES["File_Upload"], 0.88),
        ("XXE", REGEX_TEMPLATES["XXE"], 0.85),
        ("OS_Command", REGEX_TEMPLATES["OS_Command"], 0.90),
        ("Code_Exec", REGEX_TEMPLATES["Code_Exec"], 0.85),
        ("SQLi", REGEX_TEMPLATES["SQLi"], 0.80),
        ("XSS", REGEX_TEMPLATES["XSS"], 0.85),
        ("Dir_Traversal", REGEX_TEMPLATES["Dir_Traversal"], 0.85),
        ("File_Read", REGEX_TEMPLATES["File_Read"], 0.82),
        ("File_Include", REGEX_TEMPLATES["File_Include"], 0.82),
        ("SSRF", REGEX_TEMPLATES["SSRF"], 0.82),
        ("Template_Injection", REGEX_TEMPLATES["Template_Injection"], 0.82),
        ("Info_Leak", REGEX_TEMPLATES["Info_Leak"], 0.75),
    ]
    
    for vuln_type, regex, confidence in detections:
        m = re.search(regex, combined_text)
        if m:
            return vuln_type, m.group(0)[:80], confidence
    
    return "", "", 0.0


def _detect_from_response(poc_info: PocInfo) -> Tuple[str, str, float]:
    """从响应特征检测"""
    resp_status = poc_info.get("response_status", "")
    
    if resp_status and re.match(r'HTTP/.*?\b3\d\d\b', resp_status):
        set_cookie = poc_info.get("response_headers", {}).get("Set-Cookie", "")
        location = poc_info.get("response_headers", {}).get("Location", "")
        auth_keywords = ["auth", "register", "login", "oauth", "sso", "token", "session", "callback"]
        if any(kw in poc_info.get("path", "").lower() or kw in set_cookie.lower() or kw in location.lower() 
               for kw in auth_keywords):
            return "Auth_Bypass", resp_status, 0.90
    
    resp_body = poc_info.get("response_body")
    if resp_body:
        return "Info_Leak", resp_body[:80], 0.85
    
    return "", "", 0.0


# ============================================================
# 漏洞检测
# ============================================================
def detect_vuln_type(poc_info: PocInfo) -> Tuple[str, str, float]:
    """自动检测漏洞类型，返回 (vuln_type, matched_payload, confidence)"""
    # 构建检测文本
    combined_text = _build_detection_text(poc_info)
    
    # 正则模式匹配
    vuln_type, payload, confidence = _match_vuln_patterns(combined_text)
    if vuln_type:
        return vuln_type, payload, confidence
    
    # 响应特征检测
    return _detect_from_response(poc_info)



# ============================================================
# 辅助函数
# ============================================================
def get_tag(vuln_type: str) -> str:
    """获取漏洞类型的标签"""
    return TAG_MAP.get(vuln_type, f"TOPWAF_CRS/WEB_ATTACK/{vuln_type}")


# ============================================================
# Payload 参数查找（保留原有函数）
# ============================================================
def find_payload_params(poc_info: PocInfo, vuln_type: str) -> List[PayloadParam]:
    """找出包含 payload 的具体参数"""
    found: List[PayloadParam] = []
    regex = REGEX_TEMPLATES.get(vuln_type)
    if not regex:
        return found

    def _search(params: Dict[str, str], location: str, sep: str = "=") -> None:
        for k, v in params.items():
            combined = f"{k}{sep}{v}"
            if (re.search(regex, combined) or re.search(regex, v)) and len(v) >= 3:
                found.append((k, v, location))
            elif re.search(regex, k):
                found.append((k, v, "name"))

    _search(poc_info.get("query_params", {}), "query")

    for k, v in poc_info.get("body_params", {}).items():
        if k == "__XML_BODY__":
            found.append(("__XML_BODY__", v[:60], "body"))
        else:
            combined = f"{k}={v}"
            if (re.search(regex, combined) or re.search(regex, v)) and len(v) >= 3:
                found.append((k, v, "body"))
            elif re.search(regex, k):
                found.append((k, v, "name"))

    _search(poc_info.get("headers", {}), "header", sep=": ")

    filtered_params = {k: v for k, v in {
        **poc_info.get("query_params", {}),
        **poc_info.get("body_params", {})
    }.items() if k != "__XML_BODY__"}

    b64_decoded = try_base64_decode(filtered_params)
    for k, decoded_v in b64_decoded.items():
        if re.search(regex, decoded_v):
            orig_v = poc_info.get("query_params", {}).get(k) or poc_info.get("body_params", {}).get(k, "")
            loc = "query" if k in poc_info.get("query_params", {}) else "body"
            if not any(f[0] == k for f in found):
                found.append((k, orig_v, loc))
                poc_info["is_base64_param"][k] = True

    return found
