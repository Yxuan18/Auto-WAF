# -*- coding: utf-8 -*-
"""
HTTP 后端服务与结构化分析入口测试
"""
import http.client
import json
import socket
import threading
import time
from typing import Any, Tuple

import pytest

import server as server_mod
from main import analyze_http, auto_gen_rule, auto_gen_rule_with_type
from server import make_server, MAX_BODY_BYTES


SQLI_RAW = """POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=1 UNION SELECT username, password FROM users--"""

XSS_RAW = """POST /comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded

content=<script>alert(1)</script>"""

BENIGN_RAW = "GET /index.html HTTP/1.1\nHost: example.com"

XML_XXE_RAW = """POST /xmlapi HTTP/1.1
Content-Type: application/xml

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>"""

JSON_XSS_RAW = """POST /api/comment HTTP/1.1
Content-Type: application/json

{"content": "<script>alert(1)</script>"}"""

FILE_UPLOAD_RAW = """POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="shell.php"

<?php eval($_GET[1]); ?>
------x--"""


@pytest.fixture()
def server_addr():
    """在随机端口起一个测试服务，用完即关"""
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "127.0.0.1", server.server_address[1]
    server.shutdown()
    server.server_close()


def _request(addr, method, path, body=None, content_type="application/json") -> Tuple[int, Any]:
    """发请求，返回 (status, 解析后的 JSON 或原始文本)"""
    conn = http.client.HTTPConnection(addr[0], addr[1], timeout=5)
    try:
        headers = {"Content-Type": content_type} if body is not None else {}
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8")
        try:
            return resp.status, json.loads(raw)
        except json.JSONDecodeError:
            return resp.status, raw
    finally:
        conn.close()


class TestAnalyzeHttp:
    """结构化分析入口测试"""

    def test_sqli_returns_structured_result(self):
        result = analyze_http(SQLI_RAW)
        assert result["ok"] is True
        assert result["vuln_type"] == "SQLi"
        assert result["confidence"] == pytest.approx(0.8)
        assert isinstance(result["sec_rules"], list) and result["sec_rules"]
        assert result["suricata_rule"].startswith("alert http")
        assert result["selected_param"] == "q"

    def test_manual_type_overrides_detection(self):
        result = analyze_http(XSS_RAW, vuln_type="SQLi", rule_name="my_rule")
        assert result["ok"] is True
        assert result["vuln_type"] == "SQLi"
        assert result["vuln_name"] == "my_rule"
        # 手动指定时无检测过程
        assert result["confidence"] == 1.0

    def test_unsupported_type(self):
        result = analyze_http(SQLI_RAW, vuln_type="NotAType")
        assert result["ok"] is False
        assert "不支持的漏洞类型" in result["error"]
        assert "SQLi" in result["error"]  # 错误信息里列出支持的类型

    def test_undetectable_payload(self):
        result = analyze_http(BENIGN_RAW)
        assert result["ok"] is False
        assert "未能识别" in result["error"]

    def test_failure_error_contains_no_prefix(self):
        """错误文本不带 [!] 前缀——前缀由文本 API 层添加"""
        result = analyze_http(BENIGN_RAW)
        assert not result["error"].startswith("[!]")

    def test_xml_request_does_not_crash(self):
        """XML 报文 + 无 query 参数：修复前 dv 未绑定直接 NameError"""
        result = analyze_http(XML_XXE_RAW)
        assert result["ok"] is True
        assert result["vuln_type"] == "XXE"

    def test_json_xss_uses_xss_regex_not_sqli(self):
        """JSON 报文规则用当前漏洞类型正则：修复前 JSON 分支硬编码 SQLi 正则"""
        result = analyze_http(JSON_XSS_RAW)
        assert result["ok"] is True
        assert result["vuln_type"] == "XSS"
        joined = "\n".join(result["sec_rules"])
        assert "select|union" not in joined       # SQLi 模板特征不得出现
        assert "script|iframe" in joined          # XSS 模板特征应该出现

    def test_file_upload_rules_not_nameerror(self):
        """File_Upload 生成路径：a6f2a86 重构误删三个 _generate_* 函数，修复前 NameError"""
        result = analyze_http(FILE_UPLOAD_RAW)
        assert result["ok"] is True
        assert result["vuln_type"] == "File_Upload"
        assert isinstance(result["sec_rules"], list) and result["sec_rules"]


class TestLegacyApi:
    """旧文本 API 行为不回归"""

    def test_auto_gen_rule_output_text(self):
        out = auto_gen_rule(SQLI_RAW)
        assert out.startswith("[*] 检测到漏洞类型: SQLi")
        assert "【ModSecurity SecRule 规则】" in out
        assert "【Suricata 规则】" in out

    def test_auto_gen_rule_undetectable(self):
        assert auto_gen_rule(BENIGN_RAW) == "[!] 未能识别漏洞类型，请手动指定。"

    def test_auto_gen_rule_with_type_bad_type(self):
        out = auto_gen_rule_with_type(SQLI_RAW, "NotAType")
        assert out.startswith("[!] 不支持的漏洞类型: NotAType")
        assert "SQLi" in out

    def test_auto_gen_rule_with_type_manual(self):
        out = auto_gen_rule_with_type(SQLI_RAW, "SQLi", rule_name="wp_sqli")
        assert "wp_sqli" in out

    def test_import_does_not_touch_logging_config(self):
        """import 本库不得改宿主的全局 logging 配置（子进程验证全新解释器）"""
        import subprocess
        import sys
        from pathlib import Path
        project_root = str(Path(__file__).resolve().parent.parent)
        code = "import logging, main; print(len(logging.getLogger().handlers))"
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True, cwd=project_root, timeout=10)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "0"


class TestServerEndpoints:
    """HTTP 服务端点测试"""

    def test_generate_sqli(self, server_addr):
        status, body = _request(server_addr, "POST", "/generate",
                                json.dumps({"http_raw": SQLI_RAW}))
        assert status == 200
        assert body["ok"] is True
        assert body["vuln_type"] == "SQLi"
        assert isinstance(body["sec_rules"], list) and body["sec_rules"]

    def test_generate_with_manual_type(self, server_addr):
        status, body = _request(server_addr, "POST", "/generate",
                                json.dumps({"http_raw": SQLI_RAW, "vuln_type": "SQLi",
                                            "rule_name": "wp_sqli"}))
        assert status == 200
        assert body["ok"] is True
        assert body["vuln_name"] == "wp_sqli"

    def test_generate_undetectable_returns_ok_false(self, server_addr):
        """无法识别时 HTTP 仍是 200，业务失败在 ok 字段里表达"""
        status, body = _request(server_addr, "POST", "/generate",
                                json.dumps({"http_raw": BENIGN_RAW}))
        assert status == 200
        assert body["ok"] is False
        assert "未能识别" in body["error"]

    def test_generate_missing_http_raw(self, server_addr):
        status, body = _request(server_addr, "POST", "/generate", json.dumps({}))
        assert status == 400
        assert "http_raw" in body["error"]

    def test_generate_non_json_body(self, server_addr):
        status, body = _request(server_addr, "POST", "/generate", "not json at all")
        assert status == 400
        assert "JSON" in body["error"]

    def test_generate_bad_field_type(self, server_addr):
        status, body = _request(server_addr, "POST", "/generate",
                                json.dumps({"http_raw": SQLI_RAW, "vuln_type": 123}))
        assert status == 400
        assert "vuln_type" in body["error"]

    def test_generate_body_too_large(self, server_addr):
        huge = "x" * (MAX_BODY_BYTES + 1)
        status, _ = _request(server_addr, "POST", "/generate",
                             json.dumps({"http_raw": huge}))
        assert status == 413

    def test_health(self, server_addr):
        status, body = _request(server_addr, "GET", "/health")
        assert status == 200
        assert body == {"status": "ok"}

    def test_types(self, server_addr):
        status, body = _request(server_addr, "GET", "/types")
        assert status == 200
        assert "SQLi" in body["types"]
        assert "Auth_Bypass" in body["types"]

    def test_unknown_path_404(self, server_addr):
        status, _ = _request(server_addr, "GET", "/nope")
        assert status == 404

    def test_post_to_unknown_path_404(self, server_addr):
        status, _ = _request(server_addr, "POST", "/other", json.dumps({"http_raw": SQLI_RAW}))
        assert status == 404

    def test_response_is_utf8_json(self, server_addr):
        """中文错误信息必须原样到达调用方（ensure_ascii=False）"""
        status, body = _request(server_addr, "POST", "/generate", json.dumps({}))
        assert status == 400
        assert "缺少必填字段" in body["error"]

    def test_generate_deeply_nested_json_returns_400(self, server_addr):
        """深嵌套 JSON 触发 RecursionError 时回 400，而不是掐断连接"""
        status, body = _request(server_addr, "POST", "/generate", "[" * 50000)
        assert status == 400
        assert "嵌套" in body["error"]

    def test_oversized_body_trickle_cannot_hold_thread(self, server_addr, monkeypatch):
        """声明超大 Content-Length 的慢滴客户端不能无限占用线程

        修复前：413 后按声明长度 drain，客户端持续滴数据即可让连接永远存活。
        修复后：drain 有墙钟预算，预算耗尽即关闭连接。

        发送方是独立线程：主线程若边 recv 边发，recv 阻塞期间客户端静默，
        服务端 1s IO 超时就会关连接——那样钉死的是 IO 超时路径而非预算路径，
        drain 循环条件被变异（and→or）时测试不会失败。
        """
        monkeypatch.setattr(server_mod, "DRAIN_TIME_BUDGET_S", 0.5)
        sock = socket.create_connection(server_addr, timeout=10)
        try:
            declared = MAX_BODY_BYTES + 5000000
            sock.sendall(
                b"POST /generate HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {declared}\r\n\r\n".encode()
                + b"x" * 65536
            )
            # 先完整读到 413 响应
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    pytest.fail("未收到 413 响应连接就被关闭")
                buf += chunk
            assert b" 413 " in buf.split(b"\r\n", 1)[0]

            # 独立线程持续慢滴（20KB/s，3s 内 ~60KB，远低于 1MB 字节上限，
            # 终止 drain 的只能是时间预算）；主线程只等服务端关闭
            stop = threading.Event()

            def trickle():
                while not stop.is_set():
                    try:
                        sock.sendall(b"x" * 1024)
                    except OSError:
                        return
                    time.sleep(0.05)

            sender = threading.Thread(target=trickle, daemon=True)
            sender.start()
            sock.settimeout(3)
            closed = False
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        # 预算 0.5s + 一次 IO 超时 1s，正确实现 ~1.5s 内必关；
                        # 若循环条件变异成忽略预算，3s 内不会关，recv 超时即失败。
                        # 循环读是为了先消费完剩余响应体字节再等 EOF
                        d = sock.recv(4096)
                    except socket.timeout:
                        break
                    except ConnectionError:
                        # 发送线程还在灌数据，服务端关闭时收到 RST 而非干净 EOF——同样是关闭
                        closed = True
                        break
                    if d == b"":
                        closed = True
                        break
            finally:
                stop.set()
                sender.join(timeout=1)
            assert closed, "服务端应在 drain 预算耗尽后关闭慢滴连接"
        finally:
            sock.close()
