# -*- coding: utf-8 -*-
"""
编码工具模块
提供字符串 hex 编码、pm 混合编码等功能
"""
from typing import List, Tuple


# ============================================================
# 字符串编码
# ============================================================
def str_to_hex(s: str) -> str:
    """字符串转 hex 表示，如 'abc' -> '61 62 63'"""
    return " ".join(f"{b:02x}" for b in s.encode("utf-8"))


def str_to_pm_mixed(s: str) -> str:
    """
    混合编码：字母数字保持原样，特殊字符用 |xx xx| 格式
    如 '<title>phpMyAdmin setup</title>' -> '|3c|title|3e|phpMyAdmin setup|3c 2f|title|3e|'
    空格保留原样
    """
    result: List[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c.isalnum() or c == ' ':
            result.append(c)
            i += 1
        else:
            specials: List[str] = []
            while i < len(s) and not (s[i].isalnum() or s[i] == ' '):
                specials.append(f"{ord(s[i]):02x}")
                i += 1
            result.append(f"|{' '.join(specials)}|")
    return "".join(result)


# ============================================================
# 响应特征提取
# ============================================================
def extract_response_keywords_list(resp_body: str) -> List[Tuple[str, str]]:
    """
    提取响应体匹配关键词列表
    返回 [(操作符, 内容), ...]

    操作符: @contains, @containsWord, @pm
    """
    import re

    if not resp_body:
        return []

    # HTML 响应 → @contains 混合编码
    if re.search(r'<[a-zA-Z]+\b[^>]*>', resp_body):
        encoded = str_to_pm_mixed(resp_body.strip())
        return [("@contains", encoded)]

    # 纯中文 / 含中文 → 直接 @pm 字面匹配
    if re.search(r'[一-鿿]', resp_body):
        return [("@pm", resp_body.strip())]

    # 普通文本 → 每行单独一条
    result: List[Tuple[str, str]] = []
    for line in resp_body.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        literal = line.replace('"', '\\"')
        words = [w for w in line.split() if w]
        if words and all(len(re.sub(r'[^a-zA-Z]', '', w)) > 4 for w in words):
            result.append(("@contains", literal))
        else:
            result.append(("@containsWord", literal))

    return result if result else []


def extract_response_header_keywords(resp_headers: dict) -> List[Tuple[str, str]]:
    """提取响应头特征"""
    results: List[Tuple[str, str]] = []
    for k, v in resp_headers.items():
        key_lower = k.lower()
        if key_lower in ("set-cookie", "location", "server", "x-powered-by"):
            if v:
                results.append((k, v))
    return results
