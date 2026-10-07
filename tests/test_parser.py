# -*- coding: utf-8 -*-
"""
parser.py 响应解析行为测试
根因：首行即 HTTP/ 状态行的报文从未进入响应段（response_section 恒 False），
响应头被误存进请求头、响应体整段丢失。
"""

from parser import parse_http_input


class TestResponseParsing:

    def test_response_headers_parsed(self):
        """响应头进 response_headers，而不是被吞掉"""
        raw = """HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc123

{"status": "success"}"""
        result = parse_http_input(raw)
        assert result["response_status"] == "HTTP/1.1 200 OK"
        assert result["response_headers"]["Set-Cookie"] == "session=abc123"
        assert result["response_headers"]["Content-Type"] == "application/json"
        assert "success" in result["response_body"]

    def test_response_headers_do_not_pollute_request_headers(self):
        """响应头不得混入请求头字典"""
        raw = """HTTP/1.1 403 Forbidden
Server: nginx

denied"""
        result = parse_http_input(raw)
        assert result["response_headers"]["Server"] == "nginx"
        assert "Server" not in result["headers"]
        assert result["response_body"] == "denied"

    def test_response_without_body(self):
        """无响应体：头仍要解析，body 为空串"""
        raw = """HTTP/1.1 204 No Content
X-Trace-Id: abc

"""
        result = parse_http_input(raw)
        assert result["response_headers"]["X-Trace-Id"] == "abc"
        assert result["response_body"] == ""
