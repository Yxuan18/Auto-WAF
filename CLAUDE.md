# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概览

WAF 规则自动生成器：输入 HTTP 请求/响应报文，自动识别 12 种漏洞类型，生成 ModSecurity SecRule + Suricata 双格式规则。纯 Python 标准库，零运行时依赖。三种调用方式（import / CLI / HTTP 服务），架构详见 `docs/architecture.md`。

## 常用命令

```bash
.venv/bin/python -m pytest -v          # 全量测试（38 个，含迁移后的 legacy 套件）
.venv/bin/python -m pytest "tests/test_legacy.py::TestDetector::test_detect_sqli"   # 单个测试

python main.py                # CLI 交互式
python server.py [--host 127.0.0.1] [--port 8317]   # HTTP 后端服务
```

测试跑在项目 venv（`.venv`，`pip install -r requirements.txt` 建立）。tdd-guardian 已配置（`.claude/tdd-guardian/config.json`）：gate 触发于 taskCompleted/commit，变异测试（mutmut）在 push。

## 架构速览

一条流水线：`parse_http_input` → `detect_vuln_type` → `generate_sec_rules` + `generate_suricata_rule` → `format_output`，`PocInfo` dict 贯穿全程。编排入口是 `main.py` 的 `analyze_http()`（结构化 dict），文本 API 与 HTTP 服务都是它的壳。

两条硬约定（详细版在 `docs/architecture.md`）：

- 正则模板用 `\xNN` hex 转义写法是**刻意的**（规避 WAF 引擎转义问题），不要"顺手规范化"成可读字符
- 模块间用扁平顶层导入（`from parser import ...`），从项目根目录运行；新模块沿用

---

# 代码质量规范（情绪驱动版 v3）

## 核心原则

好代码 ≠ 能跑
好代码 = **让人不烦** + **不怕改** + **不容易炸**

Review 时只问一件事：**这个地方会不会让下一个人骂我？**

---

## 一、从用户情绪倒推代码质量

| 维度 | 用户感受 | 代码要求 | 骂人预警 |
|------|----------|----------|----------|
| 清晰 | 看不懂 | 一眼能懂 | "这写的什么鬼" |
| 稳定 | 怕崩 | 边界完整 | "动不动就炸" |
| 性能 | 很慢 | 响应可预期 | "等半天没反应" |
| 错误 | 报错迷惑 | 错误可读 | "报错看不懂" |
| 文档 | 不会用 | 自解释 | "这怎么用" |

---

## 二、防炸墙（按炸伤程度排序）

### P0 — 严禁碰，碰了会出人命

**Python**
- `except: pass` → 异常被生吞，炸了都不知道
- `print()` → 日志里找不到，上线后是黑盒（CLI 的用户交互输出除外）
- `from __future__ import` → Python 3 冗余声明
- 大文件全量 `.read()` → PCAP/日志直接爆内存

**安全**
- `shell=True` + 字符串拼接命令 → 命令注入，可 RCE
- 密码/Token 硬编码 → 泄露就是泄露
- SQL 字符串拼接 → SQL 注入

**前端**
- DOM 操作不判空 `el.innerText` → 空指针页面崩溃
- `MutationObserver` 里改 DOM → 死循环浏览器卡死

### P1 — 碰了不炸，但会让人烦

- 循环里有 I/O/查库/发请求 → 慢
- 无 `timeout` 的网络请求 → 挂死
- 文件读写不用 `with` → 资源泄漏
- `logger.exception` 用于业务分支 → 日志里全是堆栈，干扰排查

### P2 — 规范问题，不影响功能

- 命名混乱 → 看懂要猜
- 嵌套过深（≥ 3 层）→ 改一处要理半天
- 硬编码数字/URL → 换个环境就报错了
- 注释写"这段代码做什么"而非"为什么这样做" → 形同虚设

---

## 三、必检清单（直接拿去用）

每项有判断标准，不是模糊描述：

```
□ 这个地方会不会让下一个人骂我？
  ├─ 3个月后我还能看懂吗？
  ├─ 改需求会不会痛？（改一处会不会牵扯一堆）
  ├─ 出错了能定位吗？（日志有没有上下文）
  ├─ 有没有更简单的写法？
  └─ 是不是在用"聪明"掩盖"复杂"？
```

---

## 四、Python 语法红线

```
禁止:
  print("msg")                           → logger.info("msg")
  raise Error, "msg"                    → raise Error("msg")
  dict.iteritems()                       → dict.items()
  xrange()                               → range()
  from __future__ import annotations     → 删除
```

---

## 五、规则例外与 Spike（允许打破，但要认账）

以下情况可以不走上面那条路，**但必须写注释说为什么**：

- 性能关键路径：`# 性能原因，benchmark 证明 logger 不可接受`
- 临时调试：`# TODO: 上线前删除`
- 历史遗留：`# 历史遗留，迁移中`
- 平台约束：`# Python 3.8 以下不支持，用兼容写法`

例外不是偷懒的借口，是有记录的权衡。

### Spike（极简验证实现）

想法不确定性高（库能不能用、格式能不能解析、性能够不够）时，先做 Spike：最小可丢弃实现，只验证那一个疑问，两小时出结果，不考虑分发和打磨。

- Spike 免检 P0/P1/P2——属于上面的例外，认账方式：文件名或目录带 `spike_` 前缀。
- **反向规则：spike 代码不允许直接转正。** 验证通过后，生产实现重写或按全量 review 标准过一遍。"能跑的验证脚本"和"生产工具"是两种东西——差的那 99% 工作量（错误处理、日志、边界）就是 P0/P1/P2 存在的原因。

---

## 六、方案讨论规则（防顺从）

AI 默认顺着说话：用户提一个想法，它会用用户的认知范围组织出一套看起来很有道理的论证。方案讨论时要主动跳出来，不顺着走。

- 用户提出方案时，先找反例和已有实现，再评价方案。默认动作是"我不信没有人做过，去找"。强制换视角的手法：禁止按默认分类回答，必须按 Job 分别回答（"它的竞争者是谁"必须包含"手动做"和"不做"）。
- 新工具立项前先过 JTBD 三问：① 什么情境下要完成什么 Job？② 这个 Job 现在怎么解决——手动做、已有脚本、还是干脆不做？③ 新工具比现状好在哪，说不出具体数字就不立项。最大的竞争者往往不是另一个工具，是"手动做"和"不做"。
- 新功能动手前先回答"这个轮子别人造过没有"：仓内 grep 确认无重复 + 仓外找成熟实现（PyPI、现成 CLI）。找到就优先复用；决定不用要写明理由。
- 验收先于实现：动手前先回答"这个结果怎么检验"，把验收方式（自动化测试 / E2E / 手动观察）写下来再写代码。无法验证的选择不做。
- 每个功能定义数字化的验收线（识别率、解析成功率、超时上限）。达不到的部分显式设计降级路径（跳过 + 日志 + 人工处理），不静默吞掉，也不追求完美——97% 达标就按 97% 验收，为剩余的失败率设计手动纠正，比追 100% 更划算。
- 涉及取舍时，列出至少一个被放弃的替代方案及放弃理由——与第五节的"认账"同一条精神。

---

## 七、项目定制（本项目专用）

### 领域术语
接手前先要名词/动词表再读代码：ModSecurity SecRule 语法（chain、`@pm`、`@rx`、`t:urlDecodeUni`、`MATCHED_VAR`）、Suricata 规则语法（`http.uri`、`http.request_body`、pcre sticky buffer）、12 种漏洞类型的缩写体系。

### 风格偏好
禁止赛博朋克/高饱和/密集网格。推荐米白背景 + 低饱和蓝 + 柔和阴影 + 大圆角。

---

## 八、快速参考

| 场景 | 怎么做 |
|------|--------|
| 接手陌生文件 | 从 `main.py` 的 `analyze_http` 入口顺着读，一条流水线读完就懂 |
| 架构/端点/测试细节 | 查 `docs/architecture.md` |
| 接手陌生领域 | 先要该领域的名词/动词表（ModSecurity 规则语法、Suricata 规则语法、漏洞类型术语各有体系），再读代码 |
| 改完报错 | 看 traceback 最后一行，向上找根因 |
| 想法不确定能不能成 | 先做 Spike（`spike_` 前缀最小实现），转正要走全量 review |
| 新增工具/新功能 | 仓内 `grep -r "class.*Manager"` 确认无重复 + 仓外找成熟实现，见第六节 |
| 网络抖动 | 加 timeout，是否重试看业务容错需求 |
| 大文件 | 流式迭代，分片读，不要 `.read()` 全量 |

---

## 执行要求

- 先读文件，再动手。
- 倾向编辑，不倾向重写。
- 不重新读已读过的文件（除非确认已改）。
- 声称完成前必须测试。
- 用户指令始终优先于此文件。
