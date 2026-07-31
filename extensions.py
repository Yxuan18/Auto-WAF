# -*- coding: utf-8 -*-
"""
文件扩展名处理模块
提供危险扩展名检测、文件上传特征识别等功能
"""
import re
from typing import List, Dict, Tuple

from constants import EXTENSION_GROUPS, GROUP_REGEX_OVERRIDE


# ============================================================
# 扩展名提取
# ============================================================
def extract_dangerous_extensions(raw_input: str) -> List[str]:
    """
    从原始输入中提取危险文件扩展名
    匹配 filename=xxx.ext 或 .ext 模式
    """
    found: List[str] = []
    all_dangerous: List[str] = []

    for ext_list in EXTENSION_GROUPS.values():
        all_dangerous.extend(ext_list)
    all_dangerous += ["war", "jar", "exe", "sh", "py", "pl", "cgi"]

    lower = raw_input.lower()
    for ext in all_dangerous:
        if re.search(r'\.' + re.escape(ext) + r'(?:"|\s|;|$)', lower):
            found.append(ext)

    return found


def extract_filename_extensions(raw_input: str) -> List[str]:
    """
    从 filename="xxx.ext" / filename=xxx.ext / filename: "xxx.ext" 模式提取扩展名
    兜底用：当 extract_dangerous_extensions 没匹配到危险扩展名但 POC 里有 filename= 模式时
    """
    found: List[str] = []
    for m in re.finditer(r'filename\s*[=:]\s*[\x22\x27]?([^\x22\x27\s;]+)', raw_input, re.I):
        fname = m.group(1)
        if '.' in fname:
            ext = fname.rsplit('.', 1)[-1].lower()
            if ext and re.match(r'^[a-z0-9]+$', ext) and ext not in found:
                found.append(ext)
    return found


def extract_multipart_file_field_names(raw_input: str) -> List[str]:
    """
    从 multipart 报文里提取文件字段名（name="..." 且该 part 含 filename=）
    用于在 File_Upload 规则链中追加 FILES_NAMES 规则
    """
    names: List[str] = []
    for m in re.finditer(
        r'name=["\']([^"\']+)["\'][^"\n]*?filename\s*[=:]',
        raw_input, re.I
    ):
        name = m.group(1).strip()
        if name and name != "file" and name not in names:
            names.append(name)
    return names


# ============================================================
# 正则构建
# ============================================================
def build_suricata_file_ext(extensions: List[str]) -> str:
    """
    构建 Suricata 文件扩展名 pcre 片段
    如 \\x2e(jsp|jspx|php)
    """
    if not extensions:
        all_exts: List[str] = []
        for grp_exts in EXTENSION_GROUPS.values():
            all_exts.extend(grp_exts)
        all_exts += ["war", "jar", "exe", "sh", "py", "pl", "cgi"]
    else:
        all_exts_set: set = set()
        for ext in extensions:
            found = False
            for grp_exts in EXTENSION_GROUPS.values():
                if ext in grp_exts:
                    all_exts_set.update(grp_exts)
                    found = True
                    break
            if not found:
                all_exts_set.add(ext)
        all_exts = sorted(all_exts_set)

    return f"\\x2e({'|'.join(all_exts)})"


def build_files_rx(extensions: List[str]) -> str:
    """
    构建文件扩展名正则（hex 编码格式）
    如 (?i:\\x2ejsp(x)?)
    """
    if not extensions:
        all_parts: List[str] = []
        for grp_name, grp_exts in EXTENSION_GROUPS.items():
            if grp_name in GROUP_REGEX_OVERRIDE:
                all_parts.append(GROUP_REGEX_OVERRIDE[grp_name])
                continue

            aliases = [e[len(grp_name):] for e in grp_exts
                       if len(e) > len(grp_name) and e.startswith(grp_name)]

            if aliases:
                if len(aliases) == 1:
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

    # 找出匹配的分组
    matched_groups: set = set()
    standalone: List[str] = []
    for ext in extensions:
        found = False
        for grp_name, grp_exts in EXTENSION_GROUPS.items():
            if ext in grp_exts:
                matched_groups.add(grp_name)
                found = True
                break
        if not found:
            standalone.append(ext)

    parts: List[str] = []
    for grp_name in matched_groups:
        if grp_name in GROUP_REGEX_OVERRIDE:
            parts.append(GROUP_REGEX_OVERRIDE[grp_name])
            continue

        grp_exts = EXTENSION_GROUPS[grp_name]
        aliases = [e[len(grp_name):] for e in grp_exts
                   if len(e) > len(grp_name) and e.startswith(grp_name)]

        if aliases:
            if len(aliases) == 1:
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


# ============================================================
# 文件上传特征检测
# ============================================================
def has_file_upload_markers(raw_input: str) -> bool:
    """检查是否有文件上传特征 (multipart/form-data 或 Content-Disposition filename)"""
    return bool(re.search(
        r'multipart/form-data|\bContent-Disposition\b.*?\bfilename\b',
        raw_input, re.I
    ))


def has_directory_traversal(raw_input: str) -> bool:
    """检查文件名中是否包含目录穿越"""
    return bool(re.search(r'filename[= "]+(?:\.\./|\.\.[/\\])', raw_input, re.I))


# ============================================================
# Chain 参数提取
# ============================================================
def extract_chain_args_from_params(poc_info: dict) -> List[Tuple[str, str]]:
    """
    从已解析的 query_params/body_params 提取可用于 chain 的参数
    跳过文件字段（value 是 {{...}} 占位符或 filename 占位）
    """
    result: List[Tuple[str, str]] = []
    seen: set = set()

    for src in ("query_params", "body_params"):
        for k, v in poc_info.get(src, {}).items():
            if k in ("__RAW__", "__XML_BODY__") or k in seen:
                continue
            seen.add(k)

            # 跳过文件字段
            if k.lower() in ("filename", "file", "upload", "files"):
                continue

            v = (v or "").strip()
            if not v:
                continue

            # 跳过模板占位符
            if "{{" in v and "}}" in v:
                continue

            if len(v) < 3 or len(v) > 50:
                continue

            result.append((k, v))

    return result


def extract_specific_chain_args(raw_input: str) -> List[Tuple[str, str]]:
    """从原始输入中提取可用于 chain 的具体参数名和值"""
    result: List[Tuple[str, str]] = []
    body_part = re.split(r'\r?\n\s*\r?\n', raw_input, 1)

    if len(body_part) > 1:
        body_text = body_part[1]
        for line in body_text.strip().split("\n"):
            line = line.strip()
            if (line.startswith("--") or
                line.lower().startswith("content-disposition:") or
                line.lower().startswith("content-type:")):
                continue
            if "=" in line:
                for pair in line.split("&"):
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        k, v = k.strip(), v.strip()
                        if len(v) >= 3 and len(v) <= 50:
                            result.append((k, v))

    return result
