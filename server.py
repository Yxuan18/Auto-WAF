# -*- coding: utf-8 -*-
"""
WAF 规则生成器 - HTTP 后端服务（纯标准库，零依赖）

端点:
    POST /generate   请求体 {"http_raw": "...", "vuln_type": "", "selected_param": "", "rule_name": ""}
                     返回结构化 JSON（vuln_type / sec_rules / suricata_rule）
    GET  /health     存活检查
    GET  /types      支持的漏洞类型列表

启动:
    python server.py [--host 127.0.0.1] [--port 8317]

调用示例:
    curl -X POST http://127.0.0.1:8317/generate \
        -H "Content-Type: application/json" \
        -d '{"http_raw": "GET /a?id=1 HTTP/1.1\\nHost: x"}'
"""
import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

from constants import SUPPORTED_VULN_TYPES
from main import analyze_http

logger = logging.getLogger(__name__)

# 请求体上限：HTTP 报文再大也到不了 1MB，超了按异常处理，防内存被拖垮
MAX_BODY_BYTES = 1024 * 1024
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8317


class _HttpError(Exception):
    """请求本身不合法（4xx），携带状态码、给调用方的错误信息、需丢弃的未读字节数"""

    def __init__(self, status: int, message: str, drain_bytes: int = 0):
        super().__init__(message)
        self.status = status
        self.message = message
        self.drain_bytes = drain_bytes


class WafRuleRequestHandler(BaseHTTPRequestHandler):
    """处理 /generate、/health、/types 的请求"""

    # 让客户端知道服务名，便于排查
    server_version = "AutoWAF/1.0"

    # 套接字读写超时：Content-Length 造假不真发数据的客户端不能永久占用线程
    timeout = 30

    # ------------------------------------------------------------
    # 基础设施
    # ------------------------------------------------------------
    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        """读取并校验请求体，不合法时抛 _HttpError（4xx）"""
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            raise _HttpError(411, "缺少 Content-Length")
        try:
            length = int(length_header)
        except ValueError:
            raise _HttpError(400, "Content-Length 不是合法整数")
        if length < 0:
            raise _HttpError(400, "Content-Length 不能为负")
        if length > MAX_BODY_BYTES:
            # 响应先行、请求体稍后由 do_POST 分块丢弃，保证客户端能完整收到 413
            raise _HttpError(413, f"请求体超过上限 {MAX_BODY_BYTES} 字节", drain_bytes=length)

        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise _HttpError(400, "请求体不是合法 UTF-8 JSON")
        if not isinstance(data, dict):
            raise _HttpError(400, "JSON 根节点必须是对象")

        http_raw = data.get("http_raw", "")
        if not isinstance(http_raw, str) or not http_raw.strip():
            raise _HttpError(400, "缺少必填字段 http_raw（非空字符串）")
        return data

    def _drain_body(self, length: int) -> None:
        """分块丢弃未读的请求体（单块 64KB，内存有界）"""
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(64 * 1024, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - 基类签名固定
        """把默认的 stderr 访问日志接到 logging 体系"""
        logger.info("%s %s", self.address_string(), format % args)

    # ------------------------------------------------------------
    # 路由
    # ------------------------------------------------------------
    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
        elif self.path == "/types":
            self._send_json(200, {"types": sorted(SUPPORTED_VULN_TYPES)})
        else:
            self._send_json(404, {"error": f"未知路径: {self.path}"})

    def do_POST(self) -> None:
        if self.path != "/generate":
            self._send_json(404, {"error": f"未知路径: {self.path}"})
            return

        try:
            data = self._read_json_body()
        except _HttpError as e:
            self._send_json(e.status, {"error": e.message})
            if e.drain_bytes:
                self._drain_body(e.drain_bytes)
            return

        # 参数类型兜底：调用方传错类型时给 400 而不是 500
        for field in ("vuln_type", "selected_param", "rule_name"):
            if field in data and not isinstance(data[field], str):
                self._send_json(400, {"error": f"字段 {field} 必须是字符串"})
                return

        try:
            result = analyze_http(
                data["http_raw"],
                vuln_type=data.get("vuln_type", ""),
                selected_param=data.get("selected_param", ""),
                rule_name=data.get("rule_name", ""),
            )
        except Exception:
            # 内部错误必须留堆栈，不能静默；调用方拿 500 + 通用信息
            logger.exception("生成规则时发生未预期异常")
            self._send_json(500, {"error": "内部错误，请查看服务端日志"})
            return

        self._send_json(200, result)


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    """构建服务实例。测试用 port=0 取随机端口"""
    return ThreadingHTTPServer((host, port), WafRuleRequestHandler)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    arg_parser = argparse.ArgumentParser(description="WAF 规则生成器 HTTP 服务")
    arg_parser.add_argument("--host", default=DEFAULT_HOST, help="监听地址（默认 127.0.0.1）")
    arg_parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="监听端口（默认 8317）")
    args = arg_parser.parse_args()

    server = make_server(args.host, args.port)
    logger.info("服务已启动: http://%s:%d/generate（Ctrl+C 退出）", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("收到中断信号，服务退出")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
