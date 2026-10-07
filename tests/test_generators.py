# -*- coding: utf-8 -*-
"""
SecRule 规则生成器行为测试（Info_Leak / Auth_Bypass 分支）

全部通过公共入口 generate_sec_rules 驱动，不 import 私有函数：
- Info_Leak 响应体泄露 → 路径链头 + RESPONSE_BODY 链 + anomaly_score 动作
- Info_Leak 路径型泄露（is_path_leak 分支）→ 仅保留 REQUEST_FILENAME 路径链
- Auth_Bypass（手动指定类型）→ Referer/Cookie 缺失校验链
"""
from parser import parse_http_input
from generators import generate_sec_rules


INFO_LEAK_RESPONSE_POC = """GET /api/userinfo HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain

password=admin123
"""

INFO_LEAK_PATH_POC = """GET /.git/config HTTP/1.1
Host: example.com
"""

AUTH_BYPASS_LOGIN_POC = """POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456
"""


def test_info_leak_response_body_rules():
    """响应体含敏感字段 → 路径链头 + RESPONSE_STATUS/RESPONSE_BODY 链，末条动作含 anomaly_score"""
    raw = INFO_LEAK_RESPONSE_POC
    poc = parse_http_input(raw)
    rules = generate_sec_rules(poc, "Info_Leak", "test_info_leak", raw)

    # 断言有杀伤力：空列表 / 空字符串规则都会在这里失败
    assert rules, "Info_Leak 响应型 PoC 应生成非空规则列表"

    # 链头是路径链（PoC 带路径）
    assert rules[0].startswith("SecRule REQUEST_FILENAME"), rules[0]

    # 响应状态码链
    assert any(r.startswith("SecRule RESPONSE_STATUS") for r in rules), rules

    # 响应体特征链
    body_rules = [r for r in rules if r.startswith("SecRule RESPONSE_BODY")]
    assert body_rules, rules
    assert "password=admin123" in body_rules[-1], body_rules[-1]

    # 末条规则动作携带 anomaly_score 计分
    assert "setvar:tx.anomaly_score" in rules[-1], rules[-1]


def test_info_leak_path_leak_rules():
    """路径型泄露（/.git/config）→ 仅保留 REQUEST_FILENAME 路径链，无任何响应链"""
    raw = INFO_LEAK_PATH_POC
    poc = parse_http_input(raw)
    rules = generate_sec_rules(poc, "Info_Leak", "test_info_leak_path", raw)

    assert rules, "Info_Leak 路径型 PoC 应生成非空规则列表"

    # 首条（也是唯一一类）规则以路径链开头
    assert rules[0].startswith("SecRule REQUEST_FILENAME"), rules[0]

    # is_path_leak 分支只留路径链：不混入 Referer/Cookie/响应链
    assert not any("RESPONSE_" in r for r in rules), rules
    assert all(r.startswith("SecRule REQUEST_FILENAME") for r in rules), rules


def test_auth_bypass_referer_cookie_chains():
    """Auth_Bypass（无模板类型，手动指定）→ 含 Referer 与 Cookie 缺失校验链"""
    raw = AUTH_BYPASS_LOGIN_POC
    poc = parse_http_input(raw)
    rules = generate_sec_rules(poc, "Auth_Bypass", "test_auth_bypass", raw)

    assert rules, "Auth_Bypass 登录 PoC 应生成非空规则列表"

    # 登录 PoC 带路径 → 路径链头
    assert rules[0].startswith("SecRule REQUEST_FILENAME"), rules[0]

    # Referer 缺失校验链
    assert any('&REQUEST_HEADERS:Referer "@eq 0"' in r for r in rules), rules

    # Cookie 缺失校验链
    assert any('&REQUEST_COOKIES "@eq 0"' in r for r in rules), rules
