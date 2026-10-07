# -*- coding: utf-8 -*-
"""
detector.py SQLi 检测行为测试
根因：SQLi 正则是"前导关键词 + 尾随关键词"两段式，布尔盲注（OR 1=1）与
README 示例（IF(1=1,SLEEP(6),0)）都没有两段结构，匹配不上。
"""

from parser import parse_http_input
from detector import detect_vuln_type


def _detect(raw):
    return detect_vuln_type(parse_http_input(raw))


class TestSqliDetection:

    def test_boolean_blind_sqli(self):
        """布尔盲注：q=1' OR 1=1 --（legacy 红测试同款 payload）"""
        raw = """POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1' OR 1=1 --"""
        vuln_type, _, confidence = _detect(raw)
        assert vuln_type == "SQLi"
        assert confidence > 0.5

    def test_quoted_boolean_sqli(self):
        """带引号的布尔盲注：' OR '1'='1"""
        raw = """POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

u=admin' OR '1'='1"""
        vuln_type, _, _ = _detect(raw)
        assert vuln_type == "SQLi"

    def test_readme_example_sqli(self):
        """README 首页示例 payload（文档承诺的行为）"""
        raw = """POST /wp-admin/admin-ajax.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=arm_directory_paging_action&orderby=display_name,IF(1=1,SLEEP(6),0)"""
        vuln_type, _, confidence = _detect(raw)
        assert vuln_type == "SQLi"
        assert confidence > 0.5

    def test_benign_request_not_sqli(self):
        """正常请求不得误报 SQLi"""
        raw = "GET /index.html HTTP/1.1\nHost: example.com"
        vuln_type, _, _ = _detect(raw)
        assert vuln_type != "SQLi"

    def test_union_select_still_detected(self):
        """两段式经典注入不回归"""
        raw = """POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1 UNION SELECT username, password FROM users--"""
        vuln_type, _, _ = _detect(raw)
        assert vuln_type == "SQLi"
