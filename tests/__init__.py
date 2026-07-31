# -*- coding: utf-8 -*-
"""
WAF 规则自动生成器 - 测试套件
"""
import pytest

from parser import parse_http_input
from detector import detect_vuln_type, find_payload_params
from constants import REGEX_TEMPLATES, SUPPORTED_VULN_TYPES
from generators.sec_rules import generate_sec_rules
from generators.suricata import generate_suricata_rule


class TestParser:
    """HTTP 报文解析测试"""

    def test_parse_simple_get(self):
        """解析简单 GET 请求"""
        raw = "GET /api/users?id=1 HTTP/1.1\nHost: example.com"
        result = parse_http_input(raw)
        assert result["method"] == "GET"
        assert result["path"] == "/api/users"
        assert result["query_params"]["id"] == "1"

    def test_parse_post_form(self):
        """解析 POST 表单请求"""
        raw = """POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=123456"""
        result = parse_http_input(raw)
        assert result["method"] == "POST"
        assert result["body_params"]["username"] == "admin"
        assert result["body_params"]["password"] == "123456"

    def test_parse_json_body(self):
        """解析 JSON 请求体"""
        raw = """POST /api/data HTTP/1.1
Content-Type: application/json

{"username": "admin", "action": "login"}"""
        result = parse_http_input(raw)
        assert result["method"] == "POST"
        assert result["json_body"]["username"] == "admin"
        assert "username" in result["json_param_keys"]

    def test_parse_response(self):
        """解析响应报文"""
        raw = """HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc123

{"status": "success"}"""
        result = parse_http_input(raw)
        assert result["response_status"] == "HTTP/1.1 200 OK"
        assert result["response_headers"]["Set-Cookie"] == "session=abc123"
        assert "success" in result["response_body"]


class TestDetector:
    """漏洞检测测试"""

    def test_detect_sqli(self):
        """检测 SQL 注入"""
        raw = """POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1' OR 1=1 --"""
        poc = parse_http_input(raw)
        vuln_type, _, confidence = detect_vuln_type(poc)
        assert vuln_type == "SQLi"
        assert confidence > 0.5

    def test_detect_xss(self):
        """检测 XSS"""
        raw = """POST /comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded

content=<script>alert(1)</script>"""
        poc = parse_http_input(raw)
        vuln_type, _, confidence = detect_vuln_type(poc)
        assert vuln_type == "XSS"
        assert confidence > 0.5

    def test_detect_command_injection(self):
        """检测命令注入"""
        raw = """GET /ping?host=127.0.0.1;cat /etc/passwd HTTP/1.1"""
        poc = parse_http_input(raw)
        vuln_type, _, confidence = detect_vuln_type(poc)
        assert vuln_type == "OS_Command"
        assert confidence > 0.5

    def test_detect_file_upload(self):
        """检测文件上传"""
        raw = """POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"

<?php phpinfo(); ?>
------WebKitFormBoundary--"""
        poc = parse_http_input(raw)
        vuln_type, _, confidence = detect_vuln_type(poc)
        assert vuln_type == "File_Upload"
        assert confidence > 0.5

    def test_find_payload_params(self):
        """查找 payload 参数"""
        raw = """POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1' UNION SELECT * FROM users--"""
        poc = parse_http_input(raw)
        params = find_payload_params(poc, "SQLi")
        assert len(params) > 0
        assert params[0][0] == "q"


class TestConstants:
    """常量配置测试"""

    def test_vuln_types_complete(self):
        """验证漏洞类型完整性"""
        expected_types = {
            "SQLi", "XSS", "Code_Exec", "OS_Command",
            "Dir_Traversal", "File_Read", "File_Upload",
            "SSRF", "XXE", "File_Include", "Template_Injection",
            "Info_Leak", "Auth_Bypass"
        }
        assert set(SUPPORTED_VULN_TYPES) == expected_types

    def test_regex_templates_valid(self):
        """验证正则模板格式正确"""
        import re
        for vuln_type, pattern in REGEX_TEMPLATES.items():
            re.compile(pattern)
            assert len(pattern) > 0


class TestRuleGeneration:
    """规则生成测试"""

    def test_generate_sec_rules_sqli(self):
        """生成 SQLi 规则"""
        raw = """POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1' OR 1=1 --"""
        poc = parse_http_input(raw)
        rules = generate_sec_rules(poc, "SQLi", "SQL Injection Test", raw)
        assert len(rules) > 0
        assert any("SecRule" in r for r in rules)

    def test_generate_suricata_rule(self):
        """生成 Suricata 规则"""
        raw = """POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1' OR 1=1 --"""
        poc = parse_http_input(raw)
        rule = generate_suricata_rule(poc, "SQLi", "q", raw)
        assert rule.startswith("alert http")
        assert "sid:" in rule


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
