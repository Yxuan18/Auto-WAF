# 架构与调用方式

本文件是 CLAUDE.md 的架构详版。CLAUDE.md 只留入口，细节都在这里。

## 流水线

核心是一条单流水线，数据以 `PocInfo = Dict[str, Any]` 贯穿全程：

```
原始 HTTP 报文
  → parse_http_input()      # parser.py: 拆 method/path/headers/params/body
  → detect_vuln_type()      # detector.py: 正则匹配 12 种漏洞类型，返回 (类型, payload, 置信度)
  → generate_sec_rules()    # generators/sec_rules.py: ModSecurity chain 规则
  → generate_suricata_rule()# generators/suricata.py: Suricata 规则（sid 随机生成）
  → format_output()         # formatter.py: 拼最终可读输出
```

**三种调用形态共用同一条流水线**：

| 形态 | 入口 | 输出 |
|------|------|------|
| Python import | `main.analyze_http()` | 结构化 dict |
| CLI | `python main.py` | 人类可读文本 |
| HTTP 服务 | `server.py` | JSON |

`main.py` 的 `analyze_http()` 是结构化编排入口，返回 dict（`ok` / `vuln_type` / `confidence` / `matched_payload` / `selected_param` / `sec_rules` / `suricata_rule`）；`auto_gen_rule` 系列只是它的文本渲染薄壳（对外行为字符串保持兼容）；`server.py` 把它的结果原样转 JSON。

## 模块职责

- `main.py` — `analyze_http`（结构化编排）+ `auto_gen_rule` / `auto_gen_rule_with_type`（文本 API）+ CLI 入口。`logging.basicConfig` 只在 `__main__` 里调，import 本库不污染宿主 logging（`tests/test_server.py` 有测试守着这条）
- `server.py` — HTTP 后端服务，纯标准库（`http.server`）。端点：`POST /generate`（4xx 校验错误、413 超限分块丢弃请求体、5xx 记堆栈）、`GET /health`、`GET /types`。业务失败（无法识别漏洞类型）HTTP 仍 200，在 `ok: false` + `error` 表达
- `auto_waf_rule.py` / `__init__.py` — 向后兼容层。历史 API 是 `from auto_waf_rule import auto_gen_rule`，两者都只是转发，逻辑不放这里
- `parser.py` — HTTP 解析：form-urlencoded、multipart、JSON、XML、请求与响应；含 `full_unquote`（递归 URL 解码，处理多重编码）和 `try_base64_decode`（Base64 参数自动解码）
- `detector.py` — 把 path/headers/params/body/响应全拼成一段文本，逐个跑 `REGEX_TEMPLATES` 正则
- `constants.py` — 所有正则模板与映射表。正则用 `\xNN` hex 转义写法（如 `\x28` 表示 `(`），这是刻意的：规避 WAF 引擎自身的转义/解析问题，**不要"顺手规范化"成可读字符**
- `generators/sec_rules.py` — ModSecurity 链式规则：路径链 → 上下文参数链（`CONTEXT_PARAM_WHITELIST` 里的参数强制入链）→ payload 正则链
- `generators/suricata.py` — 按 content-type 分流构建 pcre（JSON / form-data / 普通表单三种 body 格式各不相同）
- `extensions.py` — 文件上传危险扩展名提取与分组压缩（`EXTENSION_GROUPS` + `GROUP_REGEX_OVERRIDE`）
- `encoder.py` — pm 混合编码（`|3c|title|3e|` 形式，字母数字保留、特殊字符转 hex）
- `formatter.py` — 文本输出渲染；`suricata_rule` 可由调用方传入，避免重复生成（sid 是随机的，两次生成不一致）

## 导入约定

模块间全部是扁平顶层导入（`from parser import ...`），不是包相对导入。必须从项目根目录运行；`tests/conftest.py` 通过 `sys.path.insert` 处理。新增模块沿用同一约定。

**特例：** `Auth_Bypass` 在 `SUPPORTED_VULN_TYPES` 里但没有 `REGEX_TEMPLATES` 条目（不可自动检测，只能手动指定），`main.py` 对它有特判，改动类型表时注意保持这个约定。

## HTTP 服务端点细节

`POST /generate` 请求体（`http_raw` 必填，其余可选）：

```json
{
  "http_raw": "POST /search HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nq=1 UNION SELECT username, password FROM users--",
  "vuln_type": "",
  "selected_param": "",
  "rule_name": ""
}
```

请求体上限 1MB（超限 413，分块丢弃不爆内存）；套接字 30 秒超时（Content-Length 造假不真发数据的客户端不能永久占用线程）。

## 测试布局

- 测试一律写 `tests/test_*.py`（`pytest.ini` 的 `python_files = test_*.py` 决定收集范围）
- `tests/test_legacy.py` — 早期测试，2026-10-07 从 `tests/__init__.py` 迁移（包文件里的测试不被自动收集）
- `tests/__init__.py` — 只留包标记，不放测试
- 跑在项目 venv：`.venv/bin/python -m pytest`（`pip install -r requirements.txt` 建立）

## TDD Guardian

`.claude/tdd-guardian/config.json`（schema v2）已配置：单条 unit lane（`taskCompleted`/`commit` 触发，带 pytest-cov 覆盖率），覆盖率 `no-decrease` 棘轮模式（基线 2026-10-07：行 55.5% / 分支 41.4%），`generators/**` 为关键路径（规则是核心产出），mutmut 变异测试在 `push` 触发。gate 状态在 `.claude/tdd-guardian/state.json`（本机私有，不提交）。

## 已知失败（截至 2026-10-07，Python 3.11）

`test_parse_response`（响应头 `Set-Cookie` 解析后丢失，KeyError）和 `test_detect_sqli`（`q=1' OR 1=1 --` 检测不出 SQLi）。README 示例里的 `IF(1=1,SLEEP(6),0)` 同样检测不出——SQLi 正则要求"前导向关键词 + 尾随关键词"两段式结构。修 parser/detector 前先跑这两个测试确认现状。
