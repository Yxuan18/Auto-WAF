#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动生成 WAF 规则 (ModSecurity + Suricata)
从 HTTP 请求/响应原始报文自动识别漏洞类型并生成对应规则
"""

import re
import json
import base64
import random

from typing import Dict, List, Tuple, Optional
from urllib.parse import unquote

# ============================================================
# 漏洞类型正则模板
# ============================================================
REGEX_TEMPLATES = {
    "SQLi": (
        r"(?i:\b(select|union|update|order|insert|\x2f\x2a\x2a|delete|updatexml|extractvalue|"
        r"substr|or|and)\b[^\x0a\x0d]*?\b(select|sleep|by|from|where|into|set|md5|concat|version|convert|char)\b|"
        r"\bWAITFOR\b[\s\S]*\bDELAY\b|(substring\x28|int\x2c)sys\x2efn\x5fsqlvarbasetostr)"
    ),

    "XSS": (
        r"(?i:\x3c\b(script|iframe|img|svg|div|bgsound|link|input|body|table|base|embed|"
        r"href)\b.*?\b((fromcharcode|alert|write|eval|confirm|expression|prompt|style|src|xss|location)\b|"
        r"on[a-z]{3,15}|\bconsole\x2e\w+)\s*[\x28\x60\x3d].*\x3e)"
    ),

    "Code_Exec": (
        r"(?i:system\s*\(|exec\s*\(|\bpassthru\s*\(|\bshell\x5fexec\s*\(|\bpopen\s*\(|\bproc\x5fopen\s*\(|"
        r"\beval\s*\(|\x60[^`]+\x60)"
    ),

    "OS_Command": (
        r"(?i:[\x3b\x60\x26\x7c]*?\b((rm|cp|md)\s\S+|(cat|net|reg|del)\s\S+|"
        r"(move|copy|more|curl|echo)\s\S+|ipconfig|systeminfo|shutdown|taskkill|"
        r"whoami|ifconfig|netstat|reboot|poweroff|shutdown|mkdir|useradd|userdel|"
        r"head|xcopy|replace|dir|schtasks|tasklist|ipconfig|execute|more|less|"
        r"tac|head|tail|od|id|rename|wget|ping)\b)"
    ),

    "Dir_Traversal": (
        r"(\.{1,}\x3b{0,}[\x2f\x5c]+){2,}"
    ),

    "File_Read": (
        r"(?i:\b(file|path|folder|dir|load\x5ffile|readfile|download)\b.*?(\.\.|\x2fetc\x2f|\x2fwindows\x2f|"
        r"WEB\x2dINF|boot\.ini|c\x3a\\|\.\x2f|\.\.\x2f))"
    ),

    "File_Upload": (
        r"(?i:\bContent\x2dDisposition\b.*?\bfilename\b.*?\.(jsp|php|asp|aspx|phtml|pht|shtml|war|jar|exe|sh|"
        r"py|pl|cgi|cer|asa|jspx)\b|\bfilename[=:]\s*[\x22\x27]?.*?\.(jsp|php|asp|aspx|phtml|pht|shtml|war|"
        r"jar|exe|sh|py|pl|cgi|cer|asa|jspx)\b)"
    ),

    "SSRF": (
        r"(?i:(file|https?|ftp)\x3a\x2f\x2f(127\x2e0\x2e0\x2e1|127\x2e1|localhost|(192|172|10)\x2e|169\x2e254\x2e169\x2e254))"
    ),

    "XXE": (
        r"(?i:\x3c\x21ENTITY\b.*?\b(SYSTEM|PUBLIC)\b|\bDOCTYPE\b.*?\bENTITY\b)"
    ),

    "File_Include": (
        r"(?i:\b(include|require|require\x5fonce|include\x5fonce)\s*\(?\s*[\x22\x27]?\s*(http|https|ftp|php|"
        r"data|expect|ogg|phar|zip)\x3a\x2f\x2f|\.\.\x2f|file\x3a\x2f\x2f|php\x3a\x2f\x2finput|"
        r"php\x3a\x2f\x2ffilter|data\x3a\x2f\x2f|expect\x3a\x2f\x2f|phar\x3a\x2f\x2f|ogg\x3a\x2f\x2f|"
        r"zip\x3a\x2f\x2f)"
    ),

    "Template_Injection": (
        r"(?i:\{\{.*?\}\}|\{\x25\s*.*?\s*\x25\}|\$\{.*?\}|\{\{.*?\.\w+|\{\{.*?\[|\#\{.*?\})"
    ),

    "Info_Leak": (
        r"(?i:\b[a-z_]*password[a-z_]*\b\s*[:=]|\b[a-z_]*passwd[a-z_]*\b\s*[:=]|"
        r"\b[a-z_]*secret[a-z_]*\b\s*[:=]|\b[a-z_]*token[a-z_]*\b\s*[:=]|\b[a-z_]*api[_-]?key[a-z_]*\b\s*[:=]|"
        r"\b[a-z_]*access[_-]?key[a-z_]*\b\s*[:=]|\b[a-z_]*private[_-]?key[a-z_]*\b\s*[:=]|"
        r"\b[a-z_]*key[a-z_]*\b\s*[:=]|\b[a-z_]*connection[_-]?string[a-z_]*\b\s*[:=]|\bjdbc\x3a|\bmysql\x3a|"
        r"\bredis\x3a|\bmongodb\x3a|\broot\x3a\w+\x3a\d+\x3a\d+\x3a|\x3c\?(?:php|\x3d)\b|\x2fWEB\x2dINF\x2f|"
        r"\x2fMETA\x2dINF\x2f|\.git\x2f|\.env\b|\.svn\x2f|\.DS\x5fStore|\x2factuator\x2f|\x2fswagger|"
        r"\x2fapi\x2ddocs|\x2fdruid\x2f|\x2fheapdump|\x2fthreaddump|\x2ftrace|\x2fmappings|\x2fconfigprops|"
        r"\x2fbeans|\x2fautoconfig|\x2fmetrics|\x2fhealth|\x2finfo|\x2fdump|\x2fjolokia\x2f|\x2fphpinfo|"
        r"\x2fserver\x2dstatus|\x2fserver\x2dinfo|\"threadName\"|\"stackTrace\"|heapdump|threaddump)"
    ),

}
# ============================================================
# 扩展名分组（用于 File_Upload 规则压缩）
# ============================================================
_EXTENSION_GROUPS = {
    "jsp": ["jsp", "jspx"],
    "php": ["php", "phtml", "pht", "php3", "php4", "php5", "php7", "php8"],
    "asp": ["asp", "aspx"],
}

# 分组正则覆盖：对需要精简表达的分组直接指定正则片段
# 例如 php 分组压缩为 \x2eph(p\d?|t(ml)?)，匹配 .php/.php5/.php7/.pht/.phtml
_GROUP_REGEX_OVERRIDE = {
    "php": r"\x2eph(p\d?|t(ml)?)",
}

# 漏洞类型中文名
VULN_NAME_MAP = {
    "SQLi": "SQL injection vulnerability",
    "XSS": "Cross-site scripting vulnerability",
    "Code_Exec": "Code execution vulnerability",
    "OS_Command": "OS command injection vulnerability",
    "Dir_Traversal": "Directory traversal vulnerability",
    "File_Read": "arbitrary file read vulnerability",
    "File_Upload": "arbitrary file upload vulnerability",
    "SSRF": "Server-side request forgery vulnerability",
    "XXE": "XML external entity vulnerability",
    "File_Include": "File inclusion vulnerability",
    "Info_Leak": "Information leakage vulnerability",
    "Auth_Bypass": "Authentication bypass vulnerability",
}

# 上下文参数白名单：典型漏洞场景参数，强制加入 chain 作为上下文匹配
CONTEXT_PARAM_WHITELIST = ("action", "cmd", "topicurl")

# 标签映射
TAG_MAP = {
    "SQLi": "TOPWAF_CRS/WEB_ATTACK/SQLi",
    "XSS": "TOPWAF_CRS/WEB_ATTACK/XSS",
    "Code_Exec": "TOPWAF_CRS/WEB_ATTACK/OSI",
    "OS_Command": "TOPWAF_CRS/WEB_ATTACK/OSI",
    "Dir_Traversal": "TOPWAF_CRS/WEB_ATTACK/Path Traversal",
    "File_Read": "TOPWAF_CRS/WEB_ATTACK/File_Read",
    "File_Upload": "TOPWAF_CRS/WEB_ATTACK/File_Upload",
    "SSRF": "TOPWAF_CRS/WEB_ATTACK/SSRF",
    "XXE": "TOPWAF_CRS/WEB_ATTACK/XXE",
    "File_Include": "TOPWAF_CRS/WEB_ATTACK/Path Traversal",
    "Template_Injection": "TOPWAF_CRS/WEB_ATTACK/Template_Injection",
    "Info_Leak": "TOPWAF_CRS/WEB_ATTACK/Info_Leak",
    "Auth_Bypass": "TOPWAF_CRS/WEB_ATTACK/Auth_Bypass",
}


# ============================================================
# HTTP 请求/响应解析
# ============================================================
def parse_http_input(raw: str) -> Dict:
    """
    解析 HTTP 原始报文（请求行+头部+body），支持响应报文
    返回 poc_info dict
    """
    lines = raw.strip().split("\n")
    if not lines:
        return {}

    info: Dict = {
        "method": "",
        "path": "",
        "query_params": {},
        "headers": {},
        "body_params": {},
        "request_body_raw": "",
        "response_status": "",
        "response_headers": {},
        "response_body": "",
        "json_body": None,
        "json_param_keys": [],
        "content_type": "",
        "is_base64_param": {},
    }

    first_line = lines[0].strip()

    # 判断第一行：响应（HTTP/1.x 状态码）或请求（METHOD /path）
    if first_line.upper().startswith("HTTP/"):
        info["response_status"] = first_line
    elif first_line.startswith("/"):
        # 以 / 开头的路径（无方法前缀，如 "/cgi-bin/test.cgi"）
        info["method"] = "GET"
        if "?" in first_line:
            info["path"], qs = first_line.split("?", 1)
            info["query_params"] = _parse_query_string(qs)
        else:
            info["path"] = first_line
    elif " " in first_line:
        # 用更稳健的方式解析: METHOD SP [URI] SP HTTP/version
        # URI 中可能有空格（不规范但需兼容），取第一个空格后到 HTTP/ 之前的部分
        parts = first_line.split(" ", 2)
        method = parts[0].upper()
        # 尝试从尾部找 HTTP/
        if len(parts) >= 3 and parts[2].upper().startswith("HTTP/"):
            full_url = parts[1]
        elif len(parts) >= 2:
            remaining = " ".join(parts[1:])
            if remaining.upper().startswith("HTTP/"):
                full_url = "/"
            else:
                # 查找最后一个 HTTP/ 作为版本标识
                upper_remaining = remaining.upper()
                http_idx = upper_remaining.rfind(" HTTP/")
                if http_idx >= 0:
                    full_url = remaining[:http_idx]
                else:
                    full_url = remaining
        info["method"] = method

        # 解析路径和查询参数
        if "?" in full_url:
            info["path"], qs = full_url.split("?", 1)
            info["query_params"] = _parse_query_string(qs)
        else:
            info["path"] = full_url
    else:
        # 无 HTTP 方法行，可能是纯参数
        info["method"] = "GET"
        info["path"] = "/"
        info["query_params"] = _parse_query_string(raw)

    # 分离响应头和响应体
    response_section = False
    body_lines = []
    header_end = 1  # 跳过请求行

    for i, line in enumerate(lines):
        if i == 0:
            continue

        # 检测响应状态行或空行后数字状态码
        stripped = line.strip()
        if stripped.upper().startswith("HTTP/") and " " in stripped:
            response_section = True
            info["response_status"] = stripped
            header_end = i + 1
            continue
        if not response_section and _is_response_status_line(stripped):
            response_section = True
            info["response_status"] = stripped
            header_end = i + 1
            continue

        if not line.strip():
            # 空行 = 头/体分隔
            if response_section:
                # 已在响应区，空行后面全是响应体
                body_lines = lines[i + 1:]
                break
            # 如果已收集到 body 行，不再覆盖（此空行可能是请求体与响应的分界）
            if not body_lines:
                body_lines = lines[i + 1:]
            break

        if stripped.startswith("{") or stripped.startswith("["):
            # JSON body 行
            body_lines.append(line)
        elif ":" in line and not response_section:
            # 如果 "=" 出现在 ":" 之前，说明是 body 参数而非 HTTP 头（如 sender=xxx;WAITFOR DELAY '0:0:5'）
            eq_pos = line.find("=")
            colon_pos = line.find(":")
            if eq_pos != -1 and eq_pos < colon_pos:
                body_lines.append(line)
            else:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                info["headers"][key] = value
                if key.lower() == "content-type":
                    info["content_type"] = value
        elif ":" in line and response_section:
            # 如果行首有 { 或 [，或 key 中含 "/{（非标准头部），或值为空 → 当作响应体
            key_part = line.split(":", 1)[0]
            value_part = line.split(":", 1)[1].strip() if ":" in line else ""
            if stripped.startswith("{") or stripped.startswith("[") or '"' in key_part or not value_part:
                body_lines.append(line)
            else:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip()
                info["response_headers"][key] = value
        elif "=" in line and ":" not in line and not response_section:
            # 无方法前缀的请求体参数行（如 "cmd=xxx&name=yyy"）
            body_lines.append(line)
        elif response_section and not line.startswith("--"):
            # 响应段中既无 : 也无 = 的行 → 响应体内容
            body_lines.append(line)

    body_str = "\n".join(body_lines).strip()

    # 如果 body_lines 以响应状态行开头，分离为响应头和响应体
    if body_lines and (body_lines[0].upper().startswith("HTTP/") or _is_response_status_line(body_lines[0])):
        response_section = True
        info["response_status"] = body_lines[0]
        resp_header_lines = []
        resp_body_start = 1
        raw_body_lines = body_lines[1:]
        for j, bl in enumerate(raw_body_lines):
            if not bl.strip():
                resp_body_lines = raw_body_lines[j + 1:]
                break
            elif ":" in bl:
                k, _, v = bl.partition(":")
                info["response_headers"][k.strip()] = v.strip()
            else:
                resp_body_lines = raw_body_lines[j:]
                break
        else:
            resp_body_lines = []

        body_str = "\n".join(resp_body_lines).strip()
        body_lines = resp_body_lines
    # 否则，在 lines 中查找响应段（空行后的 HTTP/ 响应）
    elif not response_section:

        for i, line in enumerate(lines[1:], 1):
            stripped = line.strip()
            if (stripped.upper().startswith("HTTP/") and " " in stripped) or _is_response_status_line(stripped):
                info["response_status"] = stripped
                resp_header_lines = []
                for j, rl in enumerate(lines[i + 1:], i + 1):
                    if not rl.strip():
                        resp_body_lines = lines[j + 1:]
                        info["response_body"] = "\n".join(resp_body_lines).strip()
                        response_section = True
                        break
                    elif ":" in rl:
                        k, _, v = rl.partition(":")
                        info["response_headers"][k.strip()] = v.strip()
                    else:
                        resp_body_lines = lines[j:]
                        info["response_body"] = "\n".join(resp_body_lines).strip()
                        response_section = True
                        break
                break

    if response_section:
        info["response_body"] = body_str if not info.get("response_body") else info["response_body"]
        # 只将响应段之前的 body 作为请求体
        req_lines = []
        in_resp = False
        for bl in body_lines:
            s = bl.strip()
            if s.upper().startswith("HTTP/") or _is_response_status_line(s):
                in_resp = True
            if not in_resp:
                req_lines.append(bl)
        info["request_body_raw"] = "\n".join(req_lines).strip()
        _parse_body_params(info, info["request_body_raw"])
    else:
        info["request_body_raw"] = body_str
        _parse_body_params(info, body_str)

    return info


def _is_response_status_line(line: str) -> bool:
    """判断是否为响应状态行（纯数字，如 200, 302 等）"""
    stripped = line.strip()
    if stripped.isdigit() and len(stripped) == 3:
        return True
    return False


def _full_unquote(s: str) -> str:
    """递归 URL 解码直到不再变化，处理多重编码 payload"""
    for _ in range(5):  # 最多解码 5 层
        try:
            decoded = unquote(s, errors='ignore')
        except Exception:
            return s
        if decoded == s:
            return s
        s = decoded
    return s


def _parse_query_string(qs: str) -> Dict[str, str]:
    """解析 URL 查询字符串"""
    params = {}
    for pair in qs.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            params[k.strip()] = v.strip()
        else:
            params[pair.strip()] = ""
    return params


def _parse_multipart(body: str, content_type: str) -> Dict[str, str]:
    """解析 multipart/form-data，返回 {name: value} 或 {name: filename}"""
    boundary = ""
    if content_type:
        m = re.search(r'boundary=(?:"([^";,]+)"|([^;,\s]+))', content_type)
        if m:
            boundary = m.group(1) or m.group(2)
    # fallback: 没贴 Content-Type 头时，从 body 第一行提取 boundary（去掉 -- 前缀）
    if not boundary:
        stripped = body.lstrip()
        if stripped.startswith("--"):
            first_line = stripped.split("\n", 1)[0].strip()
            # 去掉末尾可能的 --（结束标记）和前缀 --
            if first_line.endswith("--"):
                first_line = first_line[:-2]
            boundary = first_line[2:]
    if not boundary:
        return {}
    body_norm = body.replace("\r\n", "\n")
    delim = "--" + boundary
    params = {}
    for seg in body_norm.split(delim):
        s = seg.strip("\n").strip()
        if not s or s == "--":
            continue
        if "\n\n" in s:
            header_block, _, value = s.partition("\n\n")
        else:
            # 兼容不规范的 multipart：header 与 value 之间无空行
            # 把整段当 header 处理（提取 name/filename），value 留空
            header_block, value = s, ""
        m_name = re.search(r'name="([^"]*)"', header_block)
        if not m_name:
            continue
        name = m_name.group(1)
        m_file = re.search(r'filename="([^"]*)"', header_block)
        if m_file:
            # 文件字段：value 用 filename 占位，便于前端展示
            params[name] = m_file.group(1)
        else:
            params[name] = value.strip()
    return params


def _looks_like_multipart(body: str) -> bool:
    """检测 body 是否像 multipart/form-data（即使没贴 Content-Type 头）"""
    stripped = body.lstrip()
    if not stripped.startswith("--"):
        return False
    return "Content-Disposition" in body and "form-data" in body


def _parse_body_params(info: Dict, body: str):
    """解析请求体参数"""
    content_type = info.get("content_type", "").lower()
    body_params = {}

    if "json" in content_type:
        try:
            info["json_body"] = json.loads(body)
            body_params = _flatten_json(info["json_body"])
            info["json_param_keys"] = list(body_params.keys())
        except (json.JSONDecodeError, TypeError):
            body_params = {"__RAW__": body}
    elif "xml" in content_type or body.strip().startswith("<"):
        # XML body
        info["body_params"]["__XML_BODY__"] = body.strip()
        return
    elif "multipart/form-data" in content_type:
        body_params = _parse_multipart(body, content_type)
        if not body_params:
            body_params = {"__RAW__": body}
    elif "form-data" in content_type or "x-www-form-urlencoded" in content_type:
        body_params = _parse_query_string(body)
    else:
        # 尝试解析 JSON（即使没有 Content-Type 头）
        stripped = body.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                info["json_body"] = json.loads(stripped)
                body_params = _flatten_json(info["json_body"])
                info["json_param_keys"] = list(body_params.keys())
            except (json.JSONDecodeError, TypeError):
                body_params = {"__RAW__": body}
        elif _looks_like_multipart(stripped):
            # 没贴 Content-Type 头但 body 像 multipart → 兜底解析
            body_params = _parse_multipart(body, "")
            if not body_params:
                body_params = {"__RAW__": body}
        elif "=" in body and "\n" not in body:
            body_params = _parse_query_string(body)
        else:
            body_params = {"__RAW__": body}

    info["body_params"] = body_params


def _flatten_json(data, prefix: str = "") -> Dict[str, str]:
    """展平 JSON 对象，返回 key -> value 映射（仅叶子节点）"""
    result = {}
    if isinstance(data, dict):
        for k, v in data.items():
            new_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                result.update(_flatten_json(v, new_key))
            else:
                result[new_key] = str(v)
    elif isinstance(data, list):
        for i, v in enumerate(data):
            new_key = f"{prefix}[{i}]" if prefix else f"[{i}]"
            if isinstance(v, (dict, list)):
                result.update(_flatten_json(v, new_key))
            else:
                result[new_key] = str(v)
    return result


# ============================================================
# Base64 检测与解码
# ============================================================
def _try_base64_decode(params: Dict[str, str]) -> Dict[str, str]:
    """尝试解码 base64 参数值，返回 {param_name: decoded_value}"""
    decoded = {}
    for k, v in params.items():
        if not v or len(v) < 8:
            continue
        # 纯 base64 字符检测
        if re.match(r'^[A-Za-z0-9+/=]+$', v) and len(v) % 4 == 0:
            try:
                raw_bytes = base64.b64decode(v, validate=True)
                text = raw_bytes.decode("utf-8", errors="replace")
                # 确认是有效文本（非乱码）
                if _is_meaningful_text(text):
                    decoded[k] = text
            except Exception:
                pass
    return decoded


def _is_meaningful_text(text: str) -> bool:
    """判断解码后文本有意义（非纯乱码）"""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return printable / max(len(text), 1) > 0.5


# ============================================================
# 扩展名处理（File_Upload 专用）
# ============================================================
def _extract_dangerous_extensions(raw_input: str) -> List[str]:
    """从原始输入中提取危险文件扩展名（匹配 filename=xxx.ext 或 .ext 模式）"""
    found = []
    # 所有可能的危险扩展名
    all_dangerous = []
    for ext_list in _EXTENSION_GROUPS.values():
        all_dangerous.extend(ext_list)
    all_dangerous += ["war", "jar", "exe", "sh", "py", "pl", "cgi"]

    # 用 \.ext 模式匹配（确保是文件扩展名，而非字符串中的巧合子串）
    lower = raw_input.lower()
    for ext in all_dangerous:
        # 匹配 .ext 且后面跟边界（引号、空格、换行、分号、行尾等）
        if re.search(r'\.' + re.escape(ext) + r'(?:"|\s|;|$)', lower):
            found.append(ext)
    return found


def _extract_filename_extensions(raw_input: str) -> List[str]:
    """从 filename="xxx.ext" / filename=xxx.ext / filename: "xxx.ext" 模式提取所有扩展名
    兜底用：当 _extract_dangerous_extensions 没匹配到危险扩展名但 POC 里有 filename= 模式时
    """
    found = []
    for m in re.finditer(r'filename\s*[=:]\s*[\x22\x27]?([^\x22\x27\s;]+)', raw_input, re.I):
        fname = m.group(1)
        if '.' in fname:
            ext = fname.rsplit('.', 1)[-1].lower()
            if ext and re.match(r'^[a-z0-9]+$', ext) and ext not in found:
                found.append(ext)
    return found


def _extract_multipart_file_field_names(raw_input: str) -> List[str]:
    """从 multipart 报文里提取文件字段名（name="..." 且该 part 含 filename=）
    用于在 File_Upload 规则链中追加 FILES_NAMES 规则。
    跳过 name="file"，因为该字段已被 FILES 规则覆盖。
    """
    names = []
    # 按行扫描 Content-Disposition，同一行内既有 name= 又有 filename= 即视为文件字段
    for m in re.finditer(
        r'name=["\']([^"\']+)["\'][^"\n]*?filename\s*[=:]',
        raw_input, re.I
    ):
        name = m.group(1).strip()
        if name and name != "file" and name not in names:
            names.append(name)
    return names


def _build_suricata_file_ext(extensions: List[str]) -> str:
    """构建 Suricata 文件扩展名 pcre 片段，如 \\x2e(jsp|jspx|php)"""
    if not extensions:
        # 默认：所有扩展名
        all_exts = []
        for grp_exts in _EXTENSION_GROUPS.values():
            all_exts.extend(grp_exts)
        all_exts += ["war", "jar", "exe", "sh", "py", "pl", "cgi"]
    else:
        all_exts = set()
        for ext in extensions:
            found_group = False
            for grp_exts in _EXTENSION_GROUPS.values():
                if ext in grp_exts:
                    all_exts.update(grp_exts)
                    found_group = True
                    break
            if not found_group:
                all_exts.add(ext)
        all_exts = sorted(all_exts)
    return f"\\x2e({'|'.join(all_exts)})"


def _build_files_rx(extensions: List[str]) -> str:
    """构建文件扩展名正则（hex 编码格式，如 (?i:\\x2ejsp(x)?)）"""
    if not extensions:
        # 默认：所有扩展名分组
        all_parts = []
        for grp_name, grp_exts in _EXTENSION_GROUPS.items():
            if grp_name in _GROUP_REGEX_OVERRIDE:
                all_parts.append(_GROUP_REGEX_OVERRIDE[grp_name])
                continue
            aliases = [e[len(grp_name):] for e in grp_exts
                       if len(e) > len(grp_name) and e.startswith(grp_name)]
            if aliases:
                if len(aliases) == 1:
                    # 单字符 alias（如 jspx / aspx）→ 不加括号直接量词：jspx?
                    if len(aliases[0]) == 1:
                        all_parts.append(f"\\x2e{grp_name}{aliases[0]}?")
                    else:
                        all_parts.append(f"\\x2e{grp_name}({aliases[0]})?")
                else:
                    all_parts.append(f"\\x2e{grp_name}({'|'.join(aliases)})?")
            else:
                all_parts.append(f"\\x2e{grp_name}")
        all_parts += [f"\\x2e{e}" for e in ["war", "jar", "exe", "sh", "py", "pl", "cgi"]]
        return f"(?i:{'|'.join(all_parts)}\\b)"

    # 找出匹配的分组（使用完整分组列表，覆盖所有变体）
    matched_groups = set()
    standalone = []
    for ext in extensions:
        found = False
        for grp_name, grp_exts in _EXTENSION_GROUPS.items():
            if ext in grp_exts:
                matched_groups.add(grp_name)
                found = True
                break
        if not found:
            standalone.append(ext)

    parts = []
    for grp_name in matched_groups:
        if grp_name in _GROUP_REGEX_OVERRIDE:
            parts.append(_GROUP_REGEX_OVERRIDE[grp_name])
            continue
        grp_exts = _EXTENSION_GROUPS[grp_name]
        aliases = [e[len(grp_name):] for e in grp_exts
                   if len(e) > len(grp_name) and e.startswith(grp_name)]
        if aliases:
            if len(aliases) == 1:
                # 单字符 alias（如 jspx / aspx）→ 不加括号直接量词：jspx?
                if len(aliases[0]) == 1:
                    parts.append(f"\\x2e{grp_name}{aliases[0]}?")
                else:
                    parts.append(f"\\x2e{grp_name}({aliases[0]})?")
            else:
                parts.append(f"\\x2e{grp_name}({'|'.join(aliases)})?")
        else:
            parts.append(f"\\x2e{grp_name}")

    for ext in standalone:
        parts.append(f"\\x2e{ext}")

    return f"(?i:{'|'.join(parts)}\\b)"


def _has_file_upload_markers(raw_input: str) -> bool:
    """检查是否有文件上传特征 (multipart 或 Content-Disposition filename)"""
    return bool(re.search(
        r'multipart/form-data|\bContent-Disposition\b.*?\bfilename\b',
        raw_input, re.I
    ))


def _extract_specific_chain_args(raw_input: str) -> List[Tuple[str, str]]:
    """从原始输入中提取可用于 chain 的具体参数名和值（如 id=123）"""
    result = []
    # 查找请求体中的参数行（兼容 \n\n 和 \r\n\r\n 分隔）
    body_part = re.split(r'\r?\n\s*\r?\n', raw_input, 1)
    if len(body_part) > 1:
        body_text = body_part[1]
        for line in body_text.strip().split("\n"):
            line = line.strip()
            # 跳过 multipart 分隔符和头行
            if (line.startswith("--") or
                line.lower().startswith("content-disposition:") or
                line.lower().startswith("content-type:")):
                continue
            if "=" in line:
                # form 参数
                for pair in line.split("&"):
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        k, v = k.strip(), v.strip()
                        if len(v) >= 3 and len(v) <= 50:
                            result.append((k, v))
    return result


def _extract_chain_args_from_params(poc_info: Dict) -> List[Tuple[str, str]]:
    """从已解析的 query_params/body_params 提取可用于 chain 的参数
    能正确处理 multipart（_extract_specific_chain_args 仅扫 raw，对 multipart 头行/独占行 value 漏识别）
    跳过文件字段（value 是 {{...}} 占位符或 filename 占位），由 FILES 规则覆盖
    """
    result = []
    seen = set()
    for src in ("query_params", "body_params"):
        for k, v in poc_info.get(src, {}).items():
            if k in ("__RAW__", "__XML_BODY__") or k in seen:
                continue
            seen.add(k)
            # 跳过文件字段（filename 等）：由 FILES 规则覆盖，不应进 ARGS chain
            if k.lower() in ("filename", "file", "upload", "files"):
                continue
            v = (v or "").strip()
            if not v:
                continue
            # 跳过模板占位符（如 {{filename}}.php）
            if "{{" in v and "}}" in v:
                continue
            if len(v) < 3 or len(v) > 50:
                continue
            result.append((k, v))
    return result


# ============================================================
# 漏洞检测
# ============================================================
def detect_vuln_type(poc_info: Dict) -> Tuple[str, str, float]:
    """
    自动检测漏洞类型
    返回: (vuln_type, matched_payload, confidence)
    """
    # 构建检测文本
    text_parts = []

    # 路径
    path = poc_info.get("path", "")
    if path:
        text_parts.append(path)

    # 请求头（含 Content-Disposition 等，用于 File_Upload 检测）
    for k, v in poc_info.get("headers", {}).items():
        text_parts.append(f"{k}: {v}")

    # 查询参数（含 URL 解码版本，解决 XSS 等 URL 编码 payload 漏检）
    for k, v in poc_info.get("query_params", {}).items():
        text_parts.append(f"{k}={v}")
        # URL 递归解码，兼顾多重编码 payload
        dv = _full_unquote(v)
        if dv != v:
            text_parts.append(f"{k}={dv}")

    # 请求体参数（排除 XML body 占位符）
    for k, v in poc_info.get("body_params", {}).items():
        if k != "__XML_BODY__":
            text_parts.append(f"{k}={v}")
            dv = _full_unquote(v)
            if dv != v:
                text_parts.append(f"{k}={dv}")

    # 原始请求体
    raw_body = poc_info.get("request_body_raw", "")
    if raw_body:
        text_parts.append(raw_body)

    # 响应体
    resp_body = poc_info.get("response_body", "")
    if resp_body:
        text_parts.append(resp_body)

    # 响应头 Cookie
    for k, v in poc_info.get("response_headers", {}).items():
        text_parts.append(f"{k}: {v}")

    # Base64 解码尝试
    b64_decoded = {}
    all_params = {**poc_info.get("query_params", {}), **poc_info.get("body_params", {})}
    filtered_params = {k: v for k, v in all_params.items() if k != "__XML_BODY__"}
    b64_decoded = _try_base64_decode(filtered_params)
    for v in b64_decoded.values():
        text_parts.append(v)

    combined_text = "\n".join(text_parts)

    # 检测顺序（优先级从高到低）
    # File_Upload 置顶（multipart/form-data 特征唯一，避免被 SQLi 的 -- 误匹配）
    # XXE 在 File_Read 之前（DOCTYPE ENTITY 特征唯一）
    # Dir_Traversal 在 File_Read 之前（避免 file=.. 被 File_Read 抢走）
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
            payload = m.group(0)[:80]
            return vuln_type, payload, confidence

    # 响应体特征检测
    resp_status = poc_info.get("response_status", "")
    resp_body = poc_info.get("response_body", "")
    has_resp = bool(resp_status or resp_body)

    if has_resp:
        # 检查 Auth_Bypass: 3xx + Set-Cookie + auth 关键词
        if re.match(r'HTTP/.*?\b3\d\d\b', resp_status) or resp_status in ("301", "302", "303", "307"):
            set_cookie = poc_info.get("response_headers", {}).get("Set-Cookie", "")
            location = poc_info.get("response_headers", {}).get("Location", "")
            auth_keywords = ["auth", "register", "login", "oauth", "sso", "token", "session", "callback"]
            has_auth = any(kw in path.lower() or kw in set_cookie.lower() or kw in location.lower()
                          for kw in auth_keywords)
            if has_auth:
                return "Auth_Bypass", resp_status, 0.90

        # 响应体有内容 → Info_Leak
        if resp_body:
            return "Info_Leak", resp_body[:80], 0.85

    return "", "", 0.0


# ============================================================
# 查找 payload 参数
# ============================================================
def find_payload_params(poc_info: Dict, vuln_type: str) -> List[Tuple[str, str, str]]:
    """
    找出包含 payload 的具体参数
    返回: [(param_name, param_value, location), ...]
    location: query / body / header / cookie / name  (name=payload在参数名中)
    """
    found = []
    regex = REGEX_TEMPLATES.get(vuln_type)
    if not regex:
        return found

    def _search(params: Dict[str, str], location: str, sep: str = "="):
        """在参数字典中搜索 payload，匹配的加入 found"""
        for k, v in params.items():
            combined = f"{k}{sep}{v}"
            if (re.search(regex, combined) or re.search(regex, v)) and len(v) >= 3:
                found.append((k, v, location))
            elif re.search(regex, k):
                found.append((k, v, "name"))

    _search(poc_info.get("query_params", {}), "query")

    # body 特殊处理 __XML_BODY__
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

    # Base64 参数
    filtered_params = {k: v for k, v in {**poc_info.get("query_params", {}),
                                          **poc_info.get("body_params", {})}.items()
                       if k != "__XML_BODY__"}
    b64_decoded = _try_base64_decode(filtered_params)
    for k, decoded_v in b64_decoded.items():
        if re.search(regex, decoded_v):
            orig_v = poc_info.get("query_params", {}).get(k) or poc_info.get("body_params", {}).get(k, "")
            loc = "query" if k in poc_info.get("query_params", {}) else "body"
            if not any(f[0] == k for f in found):
                found.append((k, orig_v, loc))
                poc_info["is_base64_param"][k] = True

    return found


def _collect_all_params(poc_info: Dict) -> List[Tuple[str, str]]:
    """收集所有 query + body 参数（排除 __RAW__ / __XML_BODY__ 伪字段），返回 [(name, value), ...]"""
    all_params = []
    for k, v in poc_info.get("query_params", {}).items():
        if k in ("__RAW__", "__XML_BODY__"):
            continue
        if v and len(v) >= 2:
            all_params.append((k, v))
    for k, v in poc_info.get("body_params", {}).items():
        if k in ("__RAW__", "__XML_BODY__"):
            continue
        if v and len(v) >= 2:
            all_params.append((k, v))
    return all_params


def get_all_param_names(poc_info: Dict) -> List[str]:
    """提取所有可用的参数名（供前端选择），排除 __RAW__ / __XML_BODY__ 伪字段"""
    names = []
    for k in poc_info.get("query_params", {}).keys():
        if k in ("__RAW__", "__XML_BODY__"):
            continue
        names.append(k)
    for k in poc_info.get("body_params", {}).keys():
        if k in ("__RAW__", "__XML_BODY__"):
            continue
        if k not in names:
            names.append(k)
    json_keys = poc_info.get("json_param_keys", [])
    for k in json_keys:
        if k not in names:
            names.append(k)
    for k in poc_info.get("headers", {}).keys():
        if k not in names:
            names.append(k)
    return names


# ============================================================
# 字符串转 hex / pm 混合编码
# ============================================================
def _str_to_hex(s: str) -> str:
    """字符串转 hex 表示，如 'abc' -> '61 62 63'"""
    return " ".join(f"{b:02x}" for b in s.encode("utf-8"))


def _str_to_pm_mixed(s: str) -> str:
    """混合编码：字母数字保持原样，特殊字符用 |xx xx| 格式
    如 '<title>phpMyAdmin setup</title>' -> '|3c|title|3e|phpMyAdmin setup|3c 2f|title|3e|'
    空格保留原样
    """
    result = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isalnum() or c == ' ':
            result.append(c)
            i += 1
        else:
            # 连续特殊字符合并为一个 |xx xx| 块
            specials = []
            while i < len(s) and not (s[i].isalnum() or s[i] == ' '):
                specials.append(f"{ord(s[i]):02x}")
                i += 1
            result.append(f"|{' '.join(specials)}|")
    return "".join(result)


def _extract_response_pm_keywords(poc_info: Dict) -> Tuple[str, str]:
    """提取响应体匹配关键词
    返回 (操作符, 内容)
    """
    kws = _extract_response_keywords_list(poc_info)
    if kws:
        return kws[0]
    return "", ""


def _extract_response_keywords_list(poc_info: Dict) -> List[Tuple[str, str]]:
    """提取响应体匹配关键词列表，每个关键词一个条目
    返回 [(操作符, 内容), ...]
    """
    resp_body = poc_info.get("response_body", "")
    if not resp_body:
        return []

    # HTML 响应 → @contains 混合编码（整体作为一条）
    if re.search(r'<[a-zA-Z]+\b[^>]*>', resp_body):
        encoded = _str_to_pm_mixed(resp_body.strip())
        return [("@contains", encoded)]

    # 纯中文 / 含中文 → 直接 @pm 字面匹配（不转 hex）
    if re.search(r'[\u4e00-\u9fff]', resp_body):
        return [("@pm", resp_body.strip())]

    # 普通文本 → 每行单独一条
    # 判定：短语里每个单词的字母长度都 > 4 → @contains（整段子串匹配）
    # 否则（含短单词）→ @containsWord（单词边界匹配，防误报）
    result = []
    for line in resp_body.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        literal = line.replace('"', '\\"')
        # 按空格分词，只统计字母字符长度
        words = [w for w in line.split() if w]
        if words and all(len(re.sub(r'[^a-zA-Z]', '', w)) > 4 for w in words):
            result.append(("@contains", literal))
        else:
            result.append(("@containsWord", literal))
    return result if result else []


def _extract_response_header_keywords(poc_info: Dict) -> List[Tuple[str, str]]:
    """提取响应头特征
    返回 [(header_name, value), ...]
    """
    results = []
    resp_headers = poc_info.get("response_headers", {})
    for k, v in resp_headers.items():
        key_lower = k.lower()
        if key_lower in ("set-cookie", "location", "server", "x-powered-by"):
            if v:
                results.append((k, v))
    return results


# ============================================================
# SecRule 规则生成
# ============================================================
def generate_sec_rules(poc_info: Dict, vuln_type: str, vuln_name: str,
                        raw_input: str = "", selected_param: str = "") -> List[str]:
    """
    生成 ModSecurity SecRule 规则
    selected_param: 用户手动选定的参数名，优先级高于自动检测
    """
    rules = []
    tag = TAG_MAP.get(vuln_type, f"TOPWAF_CRS/WEB_ATTACK/{vuln_type}")
    rev = "rev:'1',ver:'TOPWAF_CRS/1.0.7'"
    path = poc_info.get("path", "")

    # File_Upload 特殊处理
    if vuln_type == "File_Upload":
        return _generate_file_upload_rules(poc_info, vuln_type, vuln_name,
                                           tag, rev, raw_input)

    # Info_Leak 特殊处理
    if vuln_type == "Info_Leak":
        return _generate_info_leak_rules(poc_info, vuln_type, vuln_name, tag, rev)

    # Auth_Bypass 特殊处理
    if vuln_type == "Auth_Bypass":
        return _generate_auth_bypass_rules(poc_info, vuln_type, vuln_name, tag, rev)

    # JSON 报文特例：参数名展平后含 [ ] . 特殊字符，不能用 ARGS:<展平名>
    # 选了具体参数 → 用最末 key 直接 ARGS:<leaf_key>（如 bill[0].data.org_code → ARGS:org_code）
    # 未选参数 → REQUEST_BODY @rx 整体匹配
    is_json = bool(poc_info.get("json_body"))
    regex_template = REGEX_TEMPLATES.get(vuln_type, "")
    if is_json and regex_template:
        rx_escaped = regex_template.replace('"', '\\"')
        if path:
            rules.append(
                f'SecRule REQUEST_FILENAME "@pm {path}" '
                f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
                f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
            )
            if selected_param:
                # 提取最末 key（如 bill[0].data.org_code → org_code）
                leaf_key = selected_param.rsplit('.', 1)[-1]
                leaf_key = re.sub(r'\[[^\]]*\]', '', leaf_key)  # 去掉 [n] 索引
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

    # ---- 通用规则生成 ----
    # 路径已含漏洞特征 → 单条 REQUEST_FILENAME @pm 即可，不需要 chain + ARGS @rx
    # 适用：Dir_Traversal/File_Read/File_Include 等路径型漏洞
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
        rules.append(
            f'SecRule REQUEST_FILENAME "@pm {path}" '
            f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
        )

    # 找 payload 参数
    if selected_param:
        payload_params = [(selected_param, "", "")]
    else:
        payload_params = find_payload_params(poc_info, vuln_type)

    regex_template = REGEX_TEMPLATES.get(vuln_type)

    if payload_params and regex_template:
        rx_escaped = regex_template.replace('"', '\\"')

        # XML body 单独处理
        if not selected_param and payload_params[0][0] == "__XML_BODY__":
            rules.append(
                f'SecRule REQUEST_BODY "@rx {rx_escaped}" '
                f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
        elif selected_param:
            # 用户手动选定参数 → 把白名单上下文参数（action/cmd/topicurl）作为 chain 加进
            all_params = _collect_all_params(poc_info)
            non_payload = [(k, v) for k, v in all_params if k != selected_param]
            priority = [(k, v) for k, v in non_payload if k in CONTEXT_PARAM_WHITELIST]
            others = [(k, v) for k, v in non_payload if k not in CONTEXT_PARAM_WHITELIST]
            non_payload = priority + others

            has_chain_context = bool(non_payload)
            for np_name, np_val in non_payload[:3]:
                rules.append(
                    f'SecRule "ARGS:{np_name}" "@pm {np_val}" "chain"'
                )
            # selected_param 作为最后一条，关闭链（永远只有 capture，不再加 chain）
            action_prefix = "capture"
            rules.append(
                f'SecRule "ARGS:{selected_param}" "@rx {rx_escaped}" '
                f'"{action_prefix},setvar:\'tx.msg=%{{rule.msg}}\','
                f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
            )
        else:
            # 自动检测：收集非 payload 参数作为链
            all_params = _collect_all_params(poc_info)

            payload_names = {p[0] for p in payload_params}
            non_payload = [(k, v) for k, v in all_params if k not in payload_names]

            # 上下文参数白名单优先排前面（action/cmd/topicurl 等）
            priority = [(k, v) for k, v in non_payload if k in CONTEXT_PARAM_WHITELIST]
            others = [(k, v) for k, v in non_payload if k not in CONTEXT_PARAM_WHITELIST]
            non_payload = priority + others

            # 非 payload 参数链（只链一次，在第一个 payload 规则前）
            for np_name, np_val in non_payload[:3]:
                rules.append(
                    f'SecRule "ARGS:{np_name}" "@pm {np_val}" "chain"'
                )

            # 为每个 payload 参数生成规则（链式串联，最后一个关闭链）
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

    # ---- 手动指定类型但没匹配到具体参数时，用 ARGS fallback ----
    if not payload_params and not selected_param:
        regex_template = REGEX_TEMPLATES.get(vuln_type)
        if regex_template:
            rx_escaped = regex_template.replace('"', '\\"')
            raw_body = poc_info.get("request_body_raw", "").strip()
            if raw_body and raw_body.startswith("<"):
                rules.append(
                    f'SecRule REQUEST_BODY "@rx {rx_escaped}" '
                    f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
                    f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
                )
            else:
                # 收集所有非 XML 参数
                all_params = _collect_all_params(poc_info)

                if all_params:
                    # 参数名匹配正则关键词的做 @pm 链（上下文参数），其余做 @rx
                    context_params = []
                    other_params = []
                    for k, v in all_params:
                        # 参数名匹配正则关键词，或在白名单里（action/cmd/topicurl）→ 作为 context 链
                        if (k in CONTEXT_PARAM_WHITELIST or
                            re.search(r'\b' + re.escape(k) + r'\b', regex_template, re.I)):
                            context_params.append((k, v))
                        else:
                            other_params.append((k, v))
                    # 没有 context 参数 → 前面的做链，最后一个做 @rx
                    if not context_params:
                        context_params, other_params = other_params[:-1], [other_params[-1]]

                    for cp_name, cp_val in context_params[:3]:
                        rules.append(
                            f'SecRule "ARGS:{cp_name}" "@pm {cp_val}" "chain"'
                        )
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


def _generate_file_upload_rules(poc_info: Dict, vuln_type: str, vuln_name: str,
                                 tag: str, rev: str, raw_input: str) -> List[str]:
    """生成文件上传专用规则
    - 路径有区分度 → REQUEST_FILENAME 作为 chain 起点
    - 路径无区分度（"/"或空）→ 第一个 query/body 参数作为 chain 起点（带 rev/msg）
    - 既无路径又无参数 → 直接 FILES 作为首条
    """
    rules = []
    path = poc_info.get("path", "")

    # 提取 chain 参数（优先用解析后的参数，能正确处理 multipart）
    chain_args = _extract_chain_args_from_params(poc_info)
    if not chain_args:
        chain_args = _extract_specific_chain_args(raw_input)

    # 提取 multipart 文件字段名（用于 FILES_NAMES 规则，并从 chain_args 中剔除）
    file_field_names = _extract_multipart_file_field_names(raw_input)
    if file_field_names:
        file_field_set = set(file_field_names)
        chain_args = [(k, v) for k, v in chain_args if k not in file_field_set]

    # 提取扩展名：优先危险扩展名，没有就兜底用 filename= 之后的扩展名
    extensions = _extract_dangerous_extensions(raw_input)
    has_filename = bool(re.search(r'filename\s*[=:]', raw_input, re.I))
    if not extensions and has_filename:
        extensions = _extract_filename_extensions(raw_input)

    # 没有扩展名、没有 multipart 特征、没有 filename= 模式 → 回退普通 regex 匹配
    if not extensions and not _has_file_upload_markers(raw_input):
        return _generate_generic_rule(poc_info, vuln_type, vuln_name, tag, rev)

    # 构建 FILES @rx 正则
    files_rx = _build_files_rx(extensions)
    rx_escaped = files_rx.replace('"', '\\"')

    # chain 起点的 actions（带 rev/msg/tag/logdata）
    chain_header_actions = (
        f"chain,{rev},t:none,t:urlDecodeUni,msg:'{vuln_name}',tag:'{tag}',"
        f"logdata:'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}'"
    )

    # 路径链 / 参数链
    if path and path != "/":
        # 路径有区分度 → REQUEST_FILENAME 作为 chain 起点
        rules.append(
            f'SecRule REQUEST_FILENAME "@pm {path}" '
            f'"{chain_header_actions}"'
        )
        # 额外上下文参数
        for param_name, param_value in chain_args:
            rules.append(
                f'SecRule "ARGS:{param_name}" "@pm {param_value}" "chain"'
            )
    elif chain_args:
        # 路径无区分度 → 第一个参数作为 chain 起点（带 rev/msg）
        first_name, first_val = chain_args[0]
        rules.append(
            f'SecRule "ARGS:{first_name}" "@pm {first_val}" '
            f'"{chain_header_actions}"'
        )
        for param_name, param_value in chain_args[1:]:
            rules.append(
                f'SecRule "ARGS:{param_name}" "@pm {param_value}" "chain"'
            )
    # 既无路径又无参数 → 跳过 chain 起点，FILES 直接作为首条

    # 追加 FILES_NAMES 规则：当 multipart 文件字段名不是 "file" 时
    # 用 FILES_NAMES 限定文件字段名，便于精确匹配特定上传字段
    # file_field_names 已在前面提取（同时从 chain_args 中剔除）
    has_chain_start = bool(rules)  # 前面是否已有 chain 起点规则
    for idx, fname in enumerate(file_field_names):
        is_last_name = (idx == len(file_field_names) - 1)
        if not has_chain_start and idx == 0:
            # 前面没有 chain 起点时，第一条 FILES_NAMES 带 chain_header_actions
            rules.append(
                f'SecRule FILES_NAMES "@pm {fname}" "{chain_header_actions}"'
            )
        else:
            rules.append(
                f'SecRule FILES_NAMES "@pm {fname}" "chain"'
            )

    # 判断目录穿越，选择 FILES 或 MULTIPART_FILENAME
    has_traversal = bool(re.search(r'filename[= "]+(?:\.\./|\.\.[/\\])', raw_input, re.I))
    var_name = "MULTIPART_FILENAME" if has_traversal else "FILES"
    rules.append(
        f'SecRule {var_name} "@rx {rx_escaped}" '
        f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
        f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
    )

    return rules


def _generate_generic_rule(poc_info: Dict, vuln_type: str, vuln_name: str,
                            tag: str, rev: str) -> List[str]:
    """回退：生成通用 regex 匹配规则（非文件上传专用）"""
    rules = []
    path = poc_info.get("path", "")
    regex_template = REGEX_TEMPLATES.get(vuln_type)
    if not regex_template:
        return rules

    rx_escaped = regex_template.replace('"', '\\"')

    if path:
        rules.append(
            f'SecRule REQUEST_FILENAME "@pm {path}" '
            f'"chain,{rev},t:none,t:urlDecodeUni,msg:\'{vuln_name}\',tag:\'{tag}\','
            f'logdata:\'Matched Data: %{{TX.0}} found within %{{MATCHED_VAR_NAME}}: %{{MATCHED_VAR}}\'"'
        )
    rules.append(
        f'SecRule ARGS "@rx {rx_escaped}" '
        f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
        f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
    )
    return rules


def _generate_info_leak_rules(poc_info: Dict, vuln_type: str, vuln_name: str,
                               tag: str, rev: str) -> List[str]:
    """生成信息泄漏专用规则
    逻辑:
      - 有响应状态码 → RESPONSE_STATUS chain → RESPONSE_BODY (响应体特征)
      - 有响应头 xxx: yyy → RESPONSE_HEADERS:xxx
      - 路径型泄露（/actuator/ 等）→ 路径特征即可
    """
    rules = []
    path = poc_info.get("path", "")
    resp_status = poc_info.get("response_status", "")
    resp_body = poc_info.get("response_body", "")
    resp_headers = poc_info.get("response_headers", {})

    # 判断路径型泄露
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
    # FILENAME 为空或无区分度（"/"）但请求带命名参数 → 用 ARGS_NAMES 精确识别
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
        # 路径型泄露：路径特征足以识别
        rules[-1] = rules[-1].replace('"chain,', '"')
        return rules

    # Referer/Cookie 校验链（响应型泄露需要无 Referer 和 Cookie）
    rules.append(f'SecRule &REQUEST_HEADERS:Referer "@eq 0" "chain"')
    rules.append(f'SecRule &REQUEST_COOKIES "@eq 0" "chain"')

    # 响应头特征 → RESPONSE_HEADERS:xxx (chain)
    resp_header_kw = _extract_response_header_keywords(poc_info)
    for hk, hv in resp_header_kw[:1]:
        rules.append(
            f'SecRule RESPONSE_HEADERS:{hk} "@contains {hv}" "chain"'
        )

    # 响应状态码 → RESPONSE_STATUS chain
    if resp_status:
        status_code = resp_status.split()[1] if " " in resp_status else resp_status
        rules.append(f'SecRule RESPONSE_STATUS "@pm {status_code}" "chain"')

    # 响应体特征 → 多条 RESPONSE_BODY (链式，最后一条 capture)
    body_kws = _extract_response_keywords_list(poc_info)
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
        # 没有响应体，但有响应头 → 最后一条改为 capture
        rules[-1] = rules[-1].replace('"chain"', '"capture,setvar:\'tx.msg=%{rule.msg}\',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}"')
    elif resp_status:
        # 只有状态码，无体无头 → 状态码作为最终匹配
        rules[-1] = rules[-1].replace('"chain"', '"capture,setvar:\'tx.msg=%{rule.msg}\',setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}"')

    return rules


def _generate_auth_bypass_rules(poc_info: Dict, vuln_type: str, vuln_name: str,
                                  tag: str, rev: str) -> List[str]:
    """生成认证绕过专用规则"""
    rules = []
    path = poc_info.get("path", "")

    # 路径链 / 参数名链
    # FILENAME 为空或无区分度（"/"）但请求带命名参数 → 用 ARGS_NAMES 精确识别
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

    # 响应头特征
    resp_header_kw = _extract_response_header_keywords(poc_info)
    if resp_header_kw:
        hk, hv = resp_header_kw[0]
        rules.append(
            f'SecRule RESPONSE_HEADERS:{hk} "@contains {hv}" '
            f'"capture,setvar:\'tx.msg=%{{rule.msg}}\','
            f'setvar:tx.anomaly_score=+%{{tx.critical_anomaly_score}}"'
        )

    return rules


# ============================================================
# Suricata 规则生成
# ============================================================
def _generate_suricata_file_upload(poc_info: Dict, raw_input: str) -> str:
    """生成文件上传专用 Suricata 规则"""
    parts = ["flow:to_server;"]
    method = poc_info.get("method", "")
    if method:
        parts.append(f'http.method; content:"{method}";')

    path = poc_info.get("path", "")
    if path:
        parts.append(f'http.uri; content:"{path}"; fast_pattern; nocase;')

    extensions = _extract_dangerous_extensions(raw_input)
    ext_pcre = _build_suricata_file_ext(extensions)
    parts.append(
        f'http.request_body; pcre:"/\\bfilename=\\x22[^\\x0a\\x0d\\x22]*?{ext_pcre}/i";'
    )

    # 元数据
    metadata = "service http;"
    tag = TAG_MAP.get("File_Upload", "").replace("TOPWAF_CRS/", "")
    if tag:
        metadata += f" classtype:{tag};"

    sid = random.randint(1000000, 99999999)
    rule_body = " ".join(parts)
    return f'alert http any any -> any any ({rule_body} metadata:{metadata}; sid:{sid};)'


def generate_suricata_rule(poc_info: Dict, vuln_type: str, selected_param: str = "",
                           raw_input: str = "") -> str:
    """
    生成 Suricata 格式规则
    """
    # File_Upload 专用处理
    if vuln_type == "File_Upload" and raw_input:
        return _generate_suricata_file_upload(poc_info, raw_input)

    parts = ["flow:to_server;"]

    path = poc_info.get("path", "")
    if path:
        parts.append(f'http.uri; url_decode; content:"{path}"; nocase;')

    regex_template = REGEX_TEMPLATES.get(vuln_type)

    if selected_param:
        # 用户手动选定参数：根据参数位置和 content-type 生成对应 pcre
        if regex_template:
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
                        f'http.request_body; url_decode; pcre:"/\\x22{re.escape(selected_param)}'
                        f'\\x22\\x3a\\x22[^\\x0a\\x0d\\x22]*?{regex_template}/i";'
                    )
                elif "form-data" in content_type:
                    parts.append(
                        f'http.request_body; pcre:"/\\bname=\\x22{re.escape(selected_param)}'
                        f'\\x22[\\s\\S]*?{regex_template}/i";'
                    )
                else:
                    parts.append(
                        f'http.request_body; url_decode; pcre:"/\\b{re.escape(selected_param)}'
                        f'=[^\\x0a\\x0d\\x26]*?{regex_template}/i";'
                    )
            else:
                # query 或未找到位置 → 用 URL pcre
                pcre_body = regex_template if param_value else r'[^\x0a\x0d\x26]+'
                parts.append(
                    f'http.uri; url_decode; pcre:"/\\b{re.escape(selected_param)}'
                    f'=[^\\x0a\\x0d\\x26]*?{pcre_body}/i";'
                )
    else:
        payload_params = find_payload_params(poc_info, vuln_type)
        if payload_params:
            param_name, param_value, location = payload_params[0]
            if regex_template and param_name != "ARGS":
                if param_name == "__XML_BODY__":
                    parts.append(
                        f'http.request_body; pcre:"/{regex_template}/i";'
                    )
                elif location == "query":
                    parts.append(
                        f'http.uri; url_decode; pcre:"/\\b{re.escape(param_name)}'
                        f'=[^\\x0a\\x0d\\x26]*?{regex_template}/i";'
                    )
                else:
                    content_type = poc_info.get("content_type", "")
                    if "json" in content_type:
                        parts.append(
                            f'http.request_body; url_decode; pcre:"/\\x22{re.escape(param_name)}'
                            f'\\x22\\x3a\\x22[^\\x0a\\x0d\\x22]*?{regex_template}/i";'
                        )
                    elif "form-data" in content_type:
                        parts.append(
                            f'http.request_body; pcre:"/\\bname=\\x22{re.escape(param_name)}'
                            f'\\x22[\\s\\S]*?{regex_template}/i";'
                        )
                    else:
                        parts.append(
                            f'http.request_body; url_decode; pcre:"/\\b{re.escape(param_name)}'
                            f'=[^\\x0a\\x0d\\x26]*?{regex_template}/i";'
                        )
        elif regex_template:
            parts.append(f'http.uri; url_decode; pcre:"/{regex_template}/i";')

    # 元数据
    metadata = f"service http;"
    if vuln_type:
        tag = TAG_MAP.get(vuln_type, "").replace("TOPWAF_CRS/", "")
        if tag:
            metadata += f" classtype:{tag};"

    # SID
    sid = random.randint(1000000, 99999999)

    rule_body = " ".join(parts)
    return f'alert http any any -> any any ({rule_body} metadata:{metadata}; sid:{sid};)'


# ============================================================
# 格式化输出
# ============================================================
def format_output(rules: List[str], poc_info: Dict, vuln_type: str, vuln_name: str,
                  matched_payload: str, confidence: float, selected_param: str = "",
                  raw_input: str = "") -> str:
    """格式化最终输出"""
    output = []

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


# ============================================================
# 主入口
# ============================================================
def auto_gen_rule(http_raw: str, rule_name: str = "") -> str:
    """自动识别漏洞类型并生成规则
    自动检测时也识别具体 payload 参数（如 JSON 里的 org_code），生成 ARGS:<leaf_key>
    """
    poc_info = parse_http_input(http_raw)
    vuln_type, matched_payload, confidence = detect_vuln_type(poc_info)

    if not vuln_type:
        return "[!] 未能识别漏洞类型，请手动指定。"

    # 自动识别 payload 参数（JSON 报文时让规则精确到字段）
    selected_param = ""
    payload_params = find_payload_params(poc_info, vuln_type)
    if payload_params:
        selected_param = payload_params[0][0]

    path = poc_info.get("path", "/unknown")
    vuln_name = rule_name if rule_name else f"{path} {VULN_NAME_MAP.get(vuln_type, vuln_type)}"
    rules = generate_sec_rules(poc_info, vuln_type, vuln_name, http_raw, selected_param)

    return format_output(rules, poc_info, vuln_type, vuln_name, matched_payload, confidence,
                          raw_input=http_raw)


def auto_gen_rule_with_type(http_raw: str, vuln_type: str = "", selected_param: str = "", rule_name: str = "") -> str:
    """
    带手动指定漏洞类型的入口
    selected_param: 用户手动选定的参数名
    rule_name: 自定义规则名称（替换 msg）
    """
    poc_info = parse_http_input(http_raw)

    if vuln_type:
        if vuln_type not in REGEX_TEMPLATES and vuln_type not in ("Auth_Bypass",):
            return f"[!] 不支持的漏洞类型: {vuln_type}。支持: {', '.join(sorted(REGEX_TEMPLATES.keys()))}, Info_Leak"
    else:
        vuln_type, _, _ = detect_vuln_type(poc_info)

    if not vuln_type:
        return f"[!] 未能识别漏洞类型，请手动指定。"

    path = poc_info.get("path", "/unknown")
    vuln_name = rule_name if rule_name else f"{path} {VULN_NAME_MAP.get(vuln_type, vuln_type)}"
    rules = generate_sec_rules(poc_info, vuln_type, vuln_name, http_raw, selected_param)

    return format_output(rules, poc_info, vuln_type, vuln_name, "", 1.0, selected_param,
                          raw_input=http_raw)


# ============================================================
# CLI
# ============================================================
if __name__ == "__main__":
    import sys

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
        print("[!] 未输入任何内容")
        sys.exit(1)

    vuln_type = input("指定漏洞类型 (回车=自动检测): ").strip()

    if vuln_type:
        result = auto_gen_rule_with_type(raw, vuln_type)
    else:
        result = auto_gen_rule(raw)

    print()
    print(result)
