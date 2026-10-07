# Plan — 变异测试补杀（源自 2026-10-07 mutmut 首跑）

来源：mutmut 首跑 3386 突变体，杀死 900（26.6%），存活 1759，无测试覆盖 727。
每个工作项以"杀死指定存活/无覆盖突变体"为验收线。

### WI-1: Info_Leak / Auth_Bypass 规则生成行为测试

- 现状：`_generate_info_leak_rules`（171 无测试）、`_generate_auth_bypass_rules`（52 无测试）——自 3c63a48 恢复后零覆盖
- 目标文件：`tests/test_generators.py`（新建）
- 验收标准：
  - Info_Leak 响应 PoC（含 `password=` 响应体）→ `sec_rules` 含 `RESPONSE_BODY` 链且动作含 `setvar:tx.anomaly_score`；链头是路径/参数名链
  - 路径型泄露 PoC（`GET /.git/config`）→ 规则以 `REQUEST_FILENAME` 开头且无响应链（`is_path_leak` 分支）
  - Auth_Bypass（手动指定类型）→ 规则含 `&REQUEST_HEADERS:Referer "@eq 0"` 与 `&REQUEST_COOKIES "@eq 0"` 链
  - 三类用例走 `generate_sec_rules` 公共入口，不 import 私有函数
- 预期杀伤：~223 无覆盖突变体转为被测

### WI-2: Suricata 规则内容级断言

- 现状：`generate_suricata_rule` 172 存活——现有测试只断言 `startswith("alert http")` / `sid:` 存在（接线断言）
- 目标文件：`tests/test_generators.py`（追加）或 `tests/test_detector.py` 旁新建 `tests/test_suricata.py`
- 验收标准：
  - query 参数 PoC → 规则文本包含 `http.uri`、参数名、`url_decode`
  - body 参数 PoC（urlencoded）→ 包含 `http.request_body`、参数名
  - JSON body PoC → pcre 含 `"param":` 结构片段（`\x22param\x22\x3a`）
  - 断言具体内容片段，不是前缀/存在性
- 预期杀伤：`generate_suricata_rule` / `_build_body_pcre` / `_build_uri_pcre` / `_find_param_location` 存活者

### WI-3: 自动检测路径的转义缺陷 + `_find_param_location` 双路径断言

- 现状（2026-10-07 WI-2 复测后更新）：
  - `generators/suricata.py` 的 `_build_auto_payload_rules`（`selected_param=""` 自动检测路径，37 存活 + 无覆盖）存在与 WI-2 修复完全相同的 f-string 单转义缺陷（`\b`→退格符、`\x22`→字面引号破坏 pcre）
  - `_find_param_location` 剩余 8 个存活者
- 目标文件：`tests/test_suricata.py`（追加用例，不动已有断言）
- 验收标准：
  1. **自动检测用例**：`generate_suricata_rule(poc, vuln_type, selected_param="", raw_input=raw)`（不传参数名，走 `_build_auto_payload_rules`）+ query PoC → 断言 pcre 含 `\\b<参数名>=` 且引号结构合法（`\x22` 为字面转义、无双裸引号）。**预期真红**：当前实现有转义 bug
  2. 修复：对齐 WI-2 的双转义约定，最小改动
  3. body 位置路径断言：urlencoded body PoC + 自动检测 → 规则含 `http.request_body` 与参数名（钉死 `_find_param_location` 的 body 分支）
- 预期杀伤：37+8 个存活/无覆盖突变体 + 消灭一个真缺陷

### WI-4: `suricata.py:172-258` 死代码清理

- 现状：`generate_suricata_rule` 的 `return` 之后的不可达代码（Pyright `structurally unreachable` 背书），是 142 个存活突变体的主要来源
- 验收标准：
  1. 删除前逐行读一遍，确认无副作用（纯死代码，不是被字符串/反射引用）
  2. 删除后 53+ 测试全绿
  3. 若发现其中逻辑其实是"应该接回去"的正确实现，停下报告而不是删
- 预期杀伤：直接消掉 ~130 个死代码存活者，得分一步过 35%

### 不立项：`_gen_sid` 存活者（6 个）

随机边界突变（`random.randint` 上下限），语义近似等效——追杀成本大于收益。
记录为已知验证缺口，不进工作项。
