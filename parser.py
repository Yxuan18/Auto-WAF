# -*- coding: utf-8 -*-
"""
HTTP 请求/响应解析模块
负责解析原始 HTTP 报文，提取方法、路径、参数、头部、body 等信息
"""
import re
import json
import base64
from typing import Dict, List, Tuple, Optional, Any

from constants import EXTENSION_GROUPS


# ============================================================
# 类型别名
# ============================================================
PocInfo = Dict[str, Any]


# ============================================================
# 公共工具函数
# ============================================================
def full_unquote(s: str, max_depth: int = 5) -> str:
    """递归 URL 解码直到不再变化，处理多重编码 payload"""
    for _ in range(max_depth):
        try:
            decoded = re.sub(r'%[0-9a-fA-F]{2}',
                           lambda m: bytes.fromhex(m.group(0)[1:]).decode('utf-8', errors='ignore'), s)
        except Exception:
            return s
        if decoded == s:
            return s
        s = decoded
    return s


def parse_query_string(qs: str) -> Dict[str, str]:
    """解析 URL 查询字符串"""
    params: Dict[str, str] = {}
    for pair in qs.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            params[k.strip()] = v.strip()
        else:
            params[pair.strip()] = ""
    return params


def _is_response_status_line(line: str) -> bool:
    """判断是否为响应状态行（纯数字，如 200, 302 等）"""
    stripped = line.strip()
    return stripped.isdigit() and len(stripped) == 3


def _is_meaningful_text(text: str) -> bool:
    """判断解码后文本有意义（非纯乱码）"""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return printable / max(len(text), 1) > 0.5


def try_base64_decode(params: Dict[str, str]) -> Dict[str, str]:
    """尝试解码 base64 参数值，返回 {param_name: decoded_value}"""
    decoded: Dict[str, str] = {}
    for k, v in params.items():
        if not v or len(v) < 8:
            continue
        # 纯 base64 字符检测
        if re.match(r'^[A-Za-z0-9+/=]+$', v) and len(v) % 4 == 0:
            try:
                raw_bytes = base64.b64decode(v, validate=True)
                text = raw_bytes.decode("utf-8", errors="replace")
                if _is_meaningful_text(text):
                    decoded[k] = text
            except Exception:
                pass
    return decoded


def _looks_like_multipart(body: str) -> bool:
    """检测 body 是否像 multipart/form-data"""
    stripped = body.lstrip()
    if not stripped.startswith("--"):
        return False
    return "Content-Disposition" in body and "form-data" in body


def _flatten_json(data: Any, prefix: str = "") -> Dict[str, str]:
    """展平 JSON 对象，返回 key -> value 映射（仅叶子节点）"""
    result: Dict[str, str] = {}
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
# Multipart 解析
# ============================================================
def parse_multipart(body: str, content_type: str) -> Dict[str, str]:
    """解析 multipart/form-data，返回 {name: value} 或 {name: filename}"""
    boundary = ""
    if content_type:
        m = re.search(r'boundary=(?:"([^";,]+)"|([^;,\s]+))', content_type)
        if m:
            boundary = m.group(1) or m.group(2)

    # fallback: 从 body 第一行提取 boundary
    if not boundary:
        stripped = body.lstrip()
        if stripped.startswith("--"):
            first_line = stripped.split("\n", 1)[0].strip()
            if first_line.endswith("--"):
                first_line = first_line[:-2]
            boundary = first_line[2:]

    if not boundary:
        return {}

    body_norm = body.replace("\r\n", "\n")
    delim = "--" + boundary
    params: Dict[str, str] = {}

    for seg in body_norm.split(delim):
        seg = seg.strip("\n").strip()
        if not seg or seg == "--":
            continue

        if "\n\n" in seg:
            header_block, _, value = seg.partition("\n\n")
        else:
            header_block, value = seg, ""

        m_name = re.search(r'name="([^"]*)"', header_block)
        if not m_name:
            continue

        name = m_name.group(1)
        m_file = re.search(r'filename="([^"]*)"', header_block)
        if m_file:
            params[name] = m_file.group(1)  # 文件字段用 filename 占位
        else:
            params[name] = value.strip()

    return params


def parse_body_params(info: PocInfo, body: str) -> None:
    """解析请求体参数，更新 info dict"""
    content_type = info.get("content_type", "").lower()
    body_params: Dict[str, str] = {}

    if "json" in content_type:
        try:
            info["json_body"] = json.loads(body)
            body_params = _flatten_json(info["json_body"])
            info["json_param_keys"] = list(body_params.keys())
        except (json.JSONDecodeError, TypeError):
            body_params = {"__RAW__": body}

    elif "xml" in content_type or body.strip().startswith("<"):
        info["body_params"]["__XML_BODY__"] = body.strip()
        return

    elif "multipart/form-data" in content_type:
        body_params = parse_multipart(body, content_type)
        if not body_params:
            body_params = {"__RAW__": body}

    elif "form-data" in content_type or "x-www-form-urlencoded" in content_type:
        body_params = parse_query_string(body)

    else:
        stripped = body.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                info["json_body"] = json.loads(stripped)
                body_params = _flatten_json(info["json_body"])
                info["json_param_keys"] = list(body_params.keys())
            except (json.JSONDecodeError, TypeError):
                body_params = {"__RAW__": body}
        elif _looks_like_multipart(stripped):
            body_params = parse_multipart(body, "")
            if not body_params:
                body_params = {"__RAW__": body}
        elif "=" in body and "\n" not in body:
            body_params = parse_query_string(body)
        else:
            body_params = {"__RAW__": body}

    info["body_params"] = body_params


# ============================================================
# 主解析函数
# ============================================================
def parse_http_input(raw: str) -> PocInfo:
    """
    解析 HTTP 原始报文（请求行+头部+body），支持响应报文
    返回 poc_info dict

    Args:
        raw: HTTP 原始报文字符串

    Returns:
        包含 method, path, query_params, headers, body_params 等字段的 dict
    """
    lines = raw.strip().split("\n")
    if not lines:
        return {}

    info: PocInfo = {
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
        info["method"] = "GET"
        if "?" in first_line:
            info["path"], qs = first_line.split("?", 1)
            info["query_params"] = parse_query_string(qs)
        else:
            info["path"] = first_line
    elif " " in first_line:
        parts = first_line.split(" ", 2)
        method = parts[0].upper()

        if len(parts) >= 3 and parts[2].upper().startswith("HTTP/"):
            full_url = parts[1]
        elif len(parts) >= 2:
            remaining = " ".join(parts[1:])
            if remaining.upper().startswith("HTTP/"):
                full_url = "/"
            else:
                upper_remaining = remaining.upper()
                http_idx = upper_remaining.rfind(" HTTP/")
                if http_idx >= 0:
                    full_url = remaining[:http_idx]
                else:
                    full_url = remaining

        info["method"] = method

        if "?" in full_url:
            info["path"], qs = full_url.split("?", 1)
            info["query_params"] = parse_query_string(qs)
        else:
            info["path"] = full_url
    else:
        info["method"] = "GET"
        info["path"] = "/"
        info["query_params"] = parse_query_string(raw)

    # 分离响应头和响应体
    response_section = False
    body_lines: List[str] = []

    for i, line in enumerate(lines):
        if i == 0:
            continue

        stripped = line.strip()

        # 检测响应状态行
        if stripped.upper().startswith("HTTP/") and " " in stripped:
            response_section = True
            info["response_status"] = stripped
            continue
        if not response_section and _is_response_status_line(stripped):
            response_section = True
            info["response_status"] = stripped
            continue

        if not line.strip():
            if response_section:
                body_lines = lines[i + 1:]
                break
            if not body_lines:
                body_lines = lines[i + 1:]
            break

        if stripped.startswith("{") or stripped.startswith("["):
            body_lines.append(line)
        elif ":" in line and not response_section:
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
            key_part = line.split(":", 1)[0]
            value_part = line.split(":", 1)[1].strip() if ":" in line else ""
            if stripped.startswith("{") or stripped.startswith("[") or '"' in key_part or not value_part:
                body_lines.append(line)
            else:
                key, _, value = line.partition(":")
                info["response_headers"][key.strip()] = value.strip()
        elif "=" in line and ":" not in line and not response_section:
            body_lines.append(line)
        elif response_section and not line.startswith("--"):
            body_lines.append(line)

    body_str = "\n".join(body_lines).strip()

    # 处理响应段
    if body_lines and (body_lines[0].upper().startswith("HTTP/") or _is_response_status_line(body_lines[0])):
        response_section = True
        info["response_status"] = body_lines[0]
        raw_body_lines = body_lines[1:]
        resp_body_lines: List[str] = []

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

    elif not response_section:
        for i, line in enumerate(lines[1:], 1):
            stripped = line.strip()
            if stripped.upper().startswith("HTTP/") and " " in stripped or _is_response_status_line(stripped):
                info["response_status"] = stripped
                for j, rl in enumerate(lines[i + 1:], i + 1):
                    if not rl.strip():
                        info["response_body"] = "\n".join(lines[j + 1:]).strip()
                        response_section = True
                        break
                    elif ":" in rl:
                        k, _, v = rl.partition(":")
                        info["response_headers"][k.strip()] = v.strip()
                    else:
                        info["response_body"] = "\n".join(lines[j:]).strip()
                        response_section = True
                        break
                break

    if response_section:
        info["response_body"] = body_str if not info.get("response_body") else info["response_body"]
        req_lines: List[str] = []
        in_resp = False
        for bl in body_lines:
            s = bl.strip()
            if s.upper().startswith("HTTP/") or _is_response_status_line(s):
                in_resp = True
            if not in_resp:
                req_lines.append(bl)
        info["request_body_raw"] = "\n".join(req_lines).strip()
        parse_body_params(info, info["request_body_raw"])
    else:
        info["request_body_raw"] = body_str
        parse_body_params(info, body_str)

    return info


# ============================================================
# 辅助函数
# ============================================================
def get_all_param_names(info: PocInfo) -> List[str]:
    """提取所有可用的参数名（供前端选择），排除 __RAW__ / __XML_BODY__ 伪字段"""
    names: List[str] = []

    for k in info.get("query_params", {}).keys():
        if k not in ("__RAW__", "__XML_BODY__"):
            names.append(k)

    for k in info.get("body_params", {}).keys():
        if k not in ("__RAW__", "__XML_BODY__") and k not in names:
            names.append(k)

    json_keys = info.get("json_param_keys", [])
    for k in json_keys:
        if k not in names:
            names.append(k)

    for k in info.get("headers", {}).keys():
        if k not in names:
            names.append(k)

    return names


def collect_all_params(info: PocInfo) -> List[Tuple[str, str]]:
    """收集所有 query + body 参数（排除伪字段），返回 [(name, value), ...]"""
    all_params: List[Tuple[str, str]] = []

    for k, v in info.get("query_params", {}).items():
        if k in ("__RAW__", "__XML_BODY__"):
            continue
        if v and len(v) >= 2:
            all_params.append((k, v))

    for k, v in info.get("body_params", {}).items():
        if k in ("__RAW__", "__XML_BODY__"):
            continue
        if v and len(v) >= 2:
            all_params.append((k, v))

    return all_params
