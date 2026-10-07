# -*- coding: utf-8 -*-
"""
Suricata 规则生成器内容级断言（WI-2）

全部通过公共入口 parse_http_input + generate_suricata_rule 驱动，不 import 私有函数。
断言的是规则文本的具体内容片段（pcre 结构、参数名转义、路径、classtype、sid 结尾），
不是 startswith("alert http") 级别的接线断言——pcre 值写错了这里会红。

规格说明（assertion 等级）：
- Level 1（输出内容校验）：每条用例直接断言生成的规则字符串包含/不包含的具体片段
- 规格强度 S1/S2：四类 PoC 各代表一个等价类（query / urlencoded body / JSON body / multipart 上传）
- 法则（law）：无守恒量/往返/幂等律——纯字符串构造函数，按内容片段规格化即为全部承诺
"""
import re

from parser import parse_http_input
from generators import generate_suricata_rule


SQLI_QUERY_POC = """GET /search?q=1 UNION SELECT a FROM b-- HTTP/1.1
Host: example.com
"""

SQLI_FORM_POC = """POST /s HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

q=1 UNION SELECT a FROM b--
"""

XSS_JSON_POC = """POST /comment HTTP/1.1
Host: example.com
Content-Type: application/json

{"content": "<script>alert(1)</script>"}
"""

UPLOAD_MULTIPART_POC = """POST /upload HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="shell.jsp"

JSP file content
------X--
"""


def _assert_rule_envelope(rule):
    """所有分支共享的结构断言：alert 头 + flow 方向 + 数字 sid 收尾"""
    assert rule.startswith("alert http any any -> any any ("), rule
    assert "flow:to_server;" in rule, rule
    assert re.search(r"sid:\d+;\)$", rule), rule


def test_suri_query_param_rule_content():
    """query 参数 SQLi PoC → 路径链 + http.uri pcre（\b 参数名 + SQLi 模板）"""
    raw = SQLI_QUERY_POC
    poc = parse_http_input(raw)
    rule = generate_suricata_rule(poc, "SQLi", "q", raw)

    _assert_rule_envelope(rule)

    # 路径链：PoC 路径 /search 以 content 形式出现，且带 url_decode + nocase
    assert 'http.uri; url_decode; content:"/search"; nocase;' in rule, rule

    # 参数链：http.uri + url_decode + \b 词边界 + 参数名 q + SQLi 正则模板
    assert 'http.uri; url_decode; pcre:"/\\bq=(?i:' in rule, rule
    assert "(select|union" in rule, rule

    # metadata 携带 SQLi classtype（TAG_MAP 去前缀后的值）
    assert "classtype:WEB_ATTACK/SQLi;" in rule, rule


def test_suri_urlencoded_body_param_rule_content():
    """urlencoded body 参数 SQLi PoC → http.request_body pcre + 参数名 q"""
    raw = SQLI_FORM_POC
    poc = parse_http_input(raw)
    rule = generate_suricata_rule(poc, "SQLi", "q", raw)

    _assert_rule_envelope(rule)

    # 路径链仍在（POST /s）
    assert 'http.uri; url_decode; content:"/s"; nocase;' in rule, rule

    # body 参数走 http.request_body（而不是 http.uri）：location 维度可观测
    assert "http.request_body" in rule, rule
    assert "http.request_body; url_decode; pcre:\"/\\bq=" in rule, rule

    # 非 JSON 非 form-data 的 urlencoded 分支：[^...] 排除集以 hex 转义形式出现
    assert "[^\\x0a\\x0d\\x26]*?" in rule, rule
    assert "(select|union" in rule, rule


def test_suri_json_body_param_rule_content():
    """JSON body XSS PoC → pcre 含 \\x22参数名\\x22\\x3a 转义结构 + XSS 模板"""
    raw = XSS_JSON_POC
    poc = parse_http_input(raw)
    rule = generate_suricata_rule(poc, "XSS", "content", raw)

    _assert_rule_envelope(rule)

    # 路径链仍在（POST /comment）
    assert 'http.uri; url_decode; content:"/comment"; nocase;' in rule, rule

    # JSON 分支：参数名以 \x22content\x22\x3a\x22（"content":"）转义形式锚定，
    # 后跟排除引号/换行的字符类，再接 XSS 正则模板
    assert "http.request_body" in rule, rule
    assert "\\x22content\\x22\\x3a\\x22[^\\x0a\\x0d\\x22]*?" in rule, rule
    assert "\\x3c\\b(script" in rule, rule

    # metadata 携带 XSS classtype
    assert "classtype:WEB_ATTACK/XSS;" in rule, rule


def test_suri_file_upload_rule_content():
    """multipart 文件上传 PoC（File_Upload）→ filename pcre + 危险扩展名内容"""
    raw = UPLOAD_MULTIPART_POC
    poc = parse_http_input(raw)
    rule = generate_suricata_rule(poc, "File_Upload", "", raw)

    _assert_rule_envelope(rule)

    # 方法链 + 路径链（fast_pattern）
    assert 'http.method; content:"POST";' in rule, rule
    assert 'http.uri; content:"/upload"; fast_pattern; nocase;' in rule, rule

    # filename pcre：\bfilename=\x22 锚定 + 从 .jsp 归组出的 \x2e(jsp|jspx) 扩展名集
    assert (
        'http.request_body; pcre:"/\\bfilename=\\x22[^\\x0a\\x0d\\x22]*?\\x2e(jsp|jspx)/i";'
        in rule
    ), rule

    # File_Upload 专用分支不携带 SQLi/XSS 的 classtype
    assert "classtype:WEB_ATTACK/File_Upload;" in rule, rule
    assert "classtype:WEB_ATTACK/SQLi" not in rule, rule


# ============================================================
# WI-3：自动检测路径（selected_param=""）的转义缺陷 + 双位置断言
#
# 与上面四条的区别：不传参数名，走 _build_auto_payload_rules 自动检测，
# 参数名与位置（query/body）由检测器决定。断言仍是规则文本内容级（Level 1）。
# ============================================================


def test_suri_auto_detect_query_param_rule_content():
    """自动检测 + query SQLi PoC → 参数名锚定的 http.uri pcre（字面 \\bq=，非退格符）"""
    raw = SQLI_QUERY_POC
    poc = parse_http_input(raw)
    rule = generate_suricata_rule(poc, "SQLi", "", raw)

    _assert_rule_envelope(rule)

    # 路径链仍在（GET /search）
    assert 'http.uri; url_decode; content:"/search"; nocase;' in rule, rule

    # 自动检测锚定参数名 q：\b 为字面反斜杠 + b（双转义产物），
    # 排除集也是字面 \x0a\x0d\x26 文本，后接 SQLi 正则模板
    assert 'http.uri; url_decode; pcre:"/\\bq=' in rule, rule
    assert "[^\\x0a\\x0d\\x26]*?" in rule, rule
    assert "(select|union" in rule, rule

    # pcre 引号结构完整闭合：模板尾部紧跟 /i";（引号 + 指令分隔分号），而不是被提前截断
    assert "sqlvarbasetostr)/i\";" in rule, rule

    # 转义失败模式（S3）：f-string 单转义会把 \b 变成退格符 \x08、
    # \x0a/\x0d 变成真实换行/回车——规则文本里不允许出现裸控制字符
    assert "\x08" not in rule, repr(rule)
    assert "\n" not in rule, repr(rule)
    assert "\r" not in rule, repr(rule)


def test_suri_auto_detect_body_param_rule_content():
    """自动检测 + urlencoded body SQLi PoC → http.request_body pcre + 参数名 q（body 位置分支）"""
    raw = SQLI_FORM_POC
    poc = parse_http_input(raw)
    rule = generate_suricata_rule(poc, "SQLi", "", raw)

    _assert_rule_envelope(rule)

    # 路径链仍在（POST /s）
    assert 'http.uri; url_decode; content:"/s"; nocase;' in rule, rule

    # body 位置：参数链走 http.request_body（而非 http.uri），锚定参数名 q，
    # 排除集为字面 \x0a\x0d\x26 文本，后接 SQLi 正则模板
    assert "http.request_body" in rule, rule
    assert 'http.request_body; url_decode; pcre:"/\\bq=' in rule, rule
    assert "[^\\x0a\\x0d\\x26]*?" in rule, rule
    assert "(select|union" in rule, rule

    # 转义失败模式（S3）：不允许退格符/裸换行混进规则文本
    assert "\x08" not in rule, repr(rule)
    assert "\n" not in rule, repr(rule)
    assert "\r" not in rule, repr(rule)
