# auto_waf_rule.py 说明

从 HTTP 原始报文（请求 + 响应）自动识别漏洞类型，生成 **ModSecurity SecRule** 和 **Suricata** 双格式 WAF 规则。

## 核心能力

- 自动识别 12 种漏洞类型（SQLi / XSS / OS_Command / Code_Exec / Dir_Traversal / File_Read / File_Upload / SSRF / XXE / File_Include / Info_Leak / Auth_Bypass）
- 支持手动指定漏洞类型与目标参数
- 支持 `application/x-www-form-urlencoded` / `multipart/form-data` / `JSON` / `XML` 多种请求体
- Base64 参数自动解码识别
- URL 多重编码递归解码
- multipart 兜底解析（即使没贴 Content-Type 头也能从 body 提取 boundary）
- 自动上下文参数链（白名单 `action` / `cmd` / `topicurl` 优先加入 chain）
- 响应体智能选择运算符（`@contains` / `@containsWord` / `@pm hex` / `@contains` 混合编码）

## 模块结构

### 1. 配置常量

| 名称                      | 说明                                  | 位置 |
| ------------------------- | ------------------------------------- | ---- |
| `REGEX_TEMPLATES`         | 各漏洞类型的 payload 正则模板         | L19  |
| `_EXTENSION_GROUPS`       | File_Upload 扩展名分组（jsp/php/asp） | L95  |
| `VULN_NAME_MAP`           | 漏洞类型中文名映射                    | L102 |
| `CONTEXT_PARAM_WHITELIST` | **上下文参数白名单**，强制加入 chain  | L118 |
| `TAG_MAP`                 | ModSecurity `tag` 标签映射            | L121 |

**白名单用法**：直接编辑 L118 即可追加新参数名

```python
CONTEXT_PARAM_WHITELIST = ("action", "cmd", "topicurl", "do", "step", "method")
```

### 2. HTTP 报文解析

| 函数                             | 说明                                             | 位置 |
| -------------------------------- | ------------------------------------------------ | ---- |
| `parse_http_input(raw)`          | 解析原始报文，返回 poc_info                      | L141 |
| `_parse_query_string(qs)`        | URL 查询字符串解析                               | L369 |
| `_parse_multipart(body, ct)`     | multipart/form-data 解析（含 boundary fallback） | L381 |
| `_looks_like_multipart(body)`    | 无 Content-Type 时兜底检测 multipart             | L425 |
| `_parse_body_params(info, body)` | 根据 Content-Type 路由到对应解析器               | L433 |
| `_flatten_json(data, prefix)`    | JSON 展平（嵌套 → `a.b.c` 形式）                 | L478 |
| `_full_unquote(s)`               | URL 递归解码（最多 5 层）                        | L356 |
| `_try_base64_decode(params)`     | 纯 Base64 字符自动解码                           | L501 |
| `_is_meaningful_text(text)`      | 判断解码文本是否非乱码                           | L520 |

### 3. poc_info 数据结构

```python
{
    "method": "POST",
    "path": "/wp-admin/admin-ajax.php",
    "query_params": {"k": "v"},
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "body_params": {"action": "xxx"},            # multipart 也展平到这里
    "request_body_raw": "原始 body 字符串",
    "response_status": "HTTP/1.1 200",
    "response_headers": {"Set-Cookie": "..."},
    "response_body": "响应体",
    "json_body": {...原始 JSON 对象或 None},
    "json_param_keys": ["a.b", "a.c"],            # 展平后的 key 列表
    "content_type": "application/x-www-form-urlencoded",
    "is_base64_param": {"k": True},              # 标记哪些参数被 Base64 解码过
}
```

特殊键：

- `__XML_BODY__`：XML 请求体作为单一 body 字段
- `__RAW__`：无法识别结构时整段 body 作为单字段

### 4. 漏洞检测

| 函数                         | 说明                                                      | 位置 |
| ---------------------------- | --------------------------------------------------------- | ---- |
| `detect_vuln_type(poc_info)` | 自动检测，返回 `(vuln_type, matched_payload, confidence)` | L682 |


1. File_Upload（multipart 特征唯一）
2. XXE（DOCTYPE ENTITY 唯一）
3. OS_Command → Code_Exec → SQLi → XSS → Dir_Traversal → File_Read → File_Include → SSRF → Template_Injection → Info_Leak
4. 响应特征：3xx + auth 关键词 → Auth_Bypass；有响应体 → Info_Leak

### 5. payload 参数查找

| 函数                                       | 说明                                 | 位置 |
| ------------------------------------------ | ------------------------------------ | ---- |
| `find_payload_params(poc_info, vuln_type)` | 找出含 payload 的具体参数            | L790 |
| `_collect_all_params(poc_info)`            | 收集所有可用 query+body 参数         | L841 |
| `get_all_param_names(poc_info)`            | 提供给前端"选择参数"下拉用的所有名字 | L853 |

返回结构：`[(param_name, param_value, location)]`，location 取值：`query` / `body` / `header` / `name`（payload 在参数名中）/ 特殊 `__XML_BODY__`。

### 6. 编码工具

| 函数                                          | 说明                                               | 位置 |
| --------------------------------------------- | -------------------------------------------------- | ---- |
| `_str_to_hex(s)`                              | 字符串 → hex 串（`'abc'` → `'61 62 63'`）          | L874 |
| `_str_to_pm_mixed(s)`                         | 混合编码：字母数字保留，特殊字符 `\|xx xx\|` 块    | L879 |
| `_extract_response_keywords_list(poc_info)`   | 响应体关键词智能选运算符                           | L911 |
| `_extract_response_header_keywords(poc_info)` | 提取 Set-Cookie / Location / Server / X-Powered-By | L947 |

响应体运算符判定：

- HTML 标签 → `@contains` 混合编码
- 含中文 → `@pm` hex
- 普通英文：所有单词字母长度 > 4 → `@contains`；含短单词 → `@containsWord`

### 7. ModSecurity 规则生成

| 函数                               | 说明                                           | 位置  |
| ---------------------------------- | ---------------------------------------------- | ----- |
| `generate_sec_rules(...)`          | 主入口，按漏洞类型分发                         | L964  |
| `_generate_file_upload_rules(...)` | File_Upload 专用（FILES / MULTIPART_FILENAME） | L1132 |
| `_generate_generic_rule(...)`      | 非文件上传特征时的回退                         | L1180 |
| `_generate_info_leak_rules(...)`   | Info_Leak 专用（响应链）                       | L1205 |
| `_generate_auth_bypass_rules(...)` | Auth_Bypass 专用（响应链）                     | L1291 |

通用规则生成三条分支：

1. **selected_param 分支**（用户手动选参数）：白名单上下文参数优先加入 chain，selected_param 作为 `ARGS:<name> @rx` 关闭链
2. **自动检测分支**（payload_params 非空）：白名单参数优先排前 3 作为 context chain，每个 payload 参数生成 `ARGS:<name> @rx`，最后一个关闭链
3. **fallback 分支**（无 payload_params 且无 selected_param）：参数名匹配正则关键词 + 白名单参数 → context 链；其它参数取第一个做 `ARGS:<name> @rx`

### 8. Suricata 规则生成

| 函数                                                         | 说明                           | 位置  |
| ------------------------------------------------------------ | ------------------------------ | ----- |
| `generate_suricata_rule(poc_info, vuln_type, selected_param, raw_input)` | Suricata 主入口                | L1366 |
| `_generate_suricata_file_upload(poc_info, raw_input)`        | File_Upload 专用 Suricata 规则 | L1338 |

根据 Content-Type 选择 pcre 模板：

- JSON：`\x22<param>\x22\x3a\x22[^\x0a\x0d\x22]*?<regex>/i`
- multipart form-data：`\bname=\x22<param>\x22[\s\S]*?<regex>/i`
- 普通 form：`\b<param>=[^\x0a\x0d\x26]*?<regex>/i`
- query：`\b<param>=[^\x0a\x0d\x26]*?<regex>/i`（带 `url_decode`）

### 9. 格式化输出与入口

| 函数                                                         | 说明                                              | 位置  |
| ------------------------------------------------------------ | ------------------------------------------------- | ----- |
| `format_output(...)`                                         | 拼装最终输出（检测说明 + ModSecurity + Suricata） | L1475 |
| `auto_gen_rule(http_raw, rule_name="")`                      | 自动检测入口                                      | L1507 |
| `auto_gen_rule_with_type(http_raw, vuln_type="", selected_param="", rule_name="")` | 带类型与参数指定的入口（Web 接口使用）            | L1523 |

## 对外 API

```python
from auto_waf_rule import (
    parse_http_input,            # 解析报文
    detect_vuln_type,             # 自动检测漏洞类型
    find_payload_params,          # 找 payload 参数
    get_all_param_names,         # 前端"选择参数"下拉数据源
    generate_sec_rules,          # 生成 ModSecurity SecRule 列表
    generate_suricata_rule,      # 生成 Suricata 单条规则
    auto_gen_rule,               # 一键：自动检测 + 生成
    auto_gen_rule_with_type,     # 带类型指定 + 参数指定 + 规则名
)
```

`auto_gen_rule_with_type` 是 Web 服务使用的入口。

## CLI 用法

```bash
python auto_waf_rule.py
```

交互式输入：

1. 粘贴 HTTP 报文（多行）
2. 输入 `END` 结束
3. 提示输入漏洞类型（回车 = 自动检测）

## 扩展点

### 添加新漏洞类型

1. 在 [REGEX_TEMPLATES](file:///c:/Users/aa/PycharmProjects/pythonProject4/auto_waf_rule.py#L19) 加正则模板
2. 在 [VULN_NAME_MAP](file:///c:/Users/aa/PycharmProjects/pythonProject4/auto_waf_rule.py#L102) 加中文名
3. 在 [TAG_MAP](file:///c:/Users/aa/PycharmProjects/pythonProject4/auto_waf_rule.py#L121) 加 tag
4. 在 [detect_vuln_type](file:///c:/Users/aa/PycharmProjects/pythonProject4/auto_waf_rule.py#L743) 的 detections 列表插入优先级位置

### 添加上下文白名单参数

直接编辑 [L118](file:///c:/Users/aa/PycharmProjects/pythonProject4/auto_waf_rule.py#L118)：

```python
CONTEXT_PARAM_WHITELIST = ("action", "cmd", "topicurl", "do", "page", "module")
```

### 添加危险文件扩展名

修改 [_EXTENSION_GROUPS]或在 [_extract_dangerous_extensions] 的 `all_dangerous += [...]` 列表追加。

## 示例

### 示例 1：SQLi multipart 表单

```python
raw = """POST /wp-admin/admin-ajax.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

action=arm_directory_paging_action&orderby=display_name,IF(1=1,SLEEP(6),0)"""

result = auto_gen_rule_with_type(raw, vuln_type="SQLi", selected_param="orderby", rule_name="wp sqli")
print(result)
```

输出：

```fortran
SecRule REQUEST_FILENAME "@pm /wp-admin/admin-ajax.php" "chain,..."
SecRule "ARGS:action" "@pm arm_directory_paging_action" "chain"
SecRule "ARGS:orderby" "@rx (?i:\b(select|...)" "chain,capture,..."
```

### 示例 2：File_Upload multipart

```python
raw = """POST /wp-admin/admin-ajax.php HTTP/1.1
-----------------------------cf7dndboundary
Content-Disposition: form-data; name="action"

dnd_codedropz_upload
-----------------------------cf7dndboundary
Content-Disposition: form-data; name="upload-file"; filename="shell.php"
Content-Type: application/octet-stream
{{string}}
-----------------------------cf7dndboundary--"""

result = auto_gen_rule_with_type(raw, vuln_type="File_Upload", rule_name="wp file upload")
```

输出：

```fortran
SecRule REQUEST_FILENAME "@pm /wp-admin/admin-ajax.php" "chain,..."
SecRule "ARGS:action" "@pm dnd_codedropz_upload" "chain"
SecRule FILES "@rx (?i:\x2ephp(\x70)?|...)" "capture,..."
```

### 示例 3：Info_Leak 带 query 参数

```python
raw = """GET /?audioigniter_playlist_id= HTTP/1.1

200
[{"title":"x","downloadUrl":"..."}]"""

result = auto_gen_rule_with_type(raw, vuln_type="Info_Leak", rule_name="info leak")
```

FILENAME 无区分度时自动改用 ARGS_NAMES：

```fortran
SecRule ARGS_NAMES "@pm audioigniter_playlist_id" "chain,..."
SecRule &REQUEST_HEADERS:Referer "@eq 0" "chain"
SecRule &REQUEST_COOKIES "@eq 0" "chain"
SecRule RESPONSE_STATUS "@pm 200" "chain"
SecRule RESPONSE_BODY "@contains ..." "capture,..."
```
