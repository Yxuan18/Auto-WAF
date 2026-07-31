# Auto-WAF

WAF 规则自动生成器 — 从 HTTP 请求/响应自动识别漏洞类型，生成 ModSecurity SecRule 和 Suricata 规则。

## 功能特性

- **12 种漏洞类型自动检测**：SQLi、XSS、OS Command Injection、Code Execution、Directory Traversal、File Read、File Upload、SSRF、XXE、File Inclusion、Template Injection、Info Leak
- **多格式请求解析**：支持 `application/x-www-form-urlencoded`、`multipart/form-data`、JSON、XML
- **智能编码处理**：Base64 参数自动解码、URL 多重编码递归解码
- **双规则输出**：同时生成 ModSecurity SecRule 和 Suricata 格式规则

## 安装

```bash
git clone https://github.com/Yxuan18/Auto-WAF.git
cd Auto-WAF
```

无需安装其他依赖，核心代码仅使用 Python 标准库。

## 使用方式

### Python API

```python
from auto_waf_rule import auto_gen_rule, auto_gen_rule_with_type

# 自动检测漏洞类型并生成规则
raw = """POST /wp-admin/admin-ajax.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=arm_directory_paging_action&orderby=display_name,IF(1=1,SLEEP(6),0)"""

result = auto_gen_rule(raw)
print(result)

# 指定漏洞类型和参数
result = auto_gen_rule_with_type(
    raw,
    vuln_type="SQLi",
    selected_param="orderby",
    rule_name="wp_sqli"
)
```

### CLI 交互式

```bash
python auto_waf_rule.py
```

按提示输入 HTTP 报文（输入 `END` 结束），即可自动检测并生成规则。

## 输出示例

```
[*] 检测到漏洞类型: SQLi (80%)
[*] 匹配 Payload: IF(1=1,SLEEP(6),0)

【ModSecurity SecRule 规则】

SecRule REQUEST_FILENAME "@pm /wp-admin/admin-ajax.php" "chain,..."
SecRule "ARGS:action" "@pm arm_directory_paging_action" "chain"
SecRule "ARGS:orderby" "@rx (?i:\b(select|union|..." "chain,capture,..."

【Suricata 规则】

alert http any any -> any any (flow:to_server; http.uri; ... sid:12345678;)
```

## 项目结构

```
Auto-WAF/
├── auto_waf_rule.py      # 向后兼容入口
├── main.py               # CLI 入口
├── parser.py             # HTTP 报文解析
├── detector.py           # 漏洞类型检测
├── constants.py          # 正则模板和配置
├── encoder.py            # 编码工具
├── extensions.py         # 文件扩展名处理
├── formatter.py          # 输出格式化
├── generators/
│   ├── sec_rules.py      # ModSecurity 规则生成
│   └── suricata.py       # Suricata 规则生成
└── tests/                # 测试套件
```

## 支持的漏洞类型

| 类型 | 说明 | 检测置信度 |
|------|------|-----------|
| SQLi | SQL 注入 | 80% |
| XSS | 跨站脚本 | 85% |
| OS_Command | 操作系统命令注入 | 90% |
| Code_Exec | 代码执行 | 85% |
| Dir_Traversal | 目录穿越 | 85% |
| File_Read | 任意文件读取 | 82% |
| File_Upload | 任意文件上传 | 88% |
| SSRF | 服务器端请求伪造 | 82% |
| XXE | XML 外部实体 | 85% |
| File_Include | 文件包含 | 82% |
| Template_Injection | 模板注入 | 82% |
| Info_Leak | 信息泄露 | 75% |

## 测试

```bash
pytest tests/ -v
```

## License

MIT
