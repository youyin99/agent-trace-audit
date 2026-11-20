# Agent Trace Audit 工程设计

## 1. 目标

把分散的工具执行事件和接收器回执整理成可检查的审计报告：

- 采集时脱敏；
- 容忍乱序、重复、缺失与格式异常；
- 产生规则告警；
- 建立限定于已记录关联的证据链；
- 不把关联表述为因果证明。

## 2. 组件

```text
agent_trace_audit/
├─ collector.py   事件/回执读取、校验、去重、排序
├─ redaction.py   合成密钥检测与脱敏
├─ rules.py       告警规则
├─ correlate.py   时间线与关联链
├─ report.py      JSON/HTML
└─ cli.py         audit / collect
```

## 3. 事件采集

事件必需字段：

- schema_version、run_id、event_id、timestamp；
- principal、tool、args；
- permission、result。

处理策略：

- 非法 JSON → `malformed_line` 问题，跳过该行；
- 缺字段 → 记录问题；部分字段给出安全默认值；
- 缺 event_id → 生成基于位置的稳定 ID；
- 相同 ID 且规范化后完全相同 → 删除重复；
- 相同 ID 但内容不同 → 保留第一条并记录 high 问题；
- 时间解析失败 → 排到末尾，记录问题；
- 相邻输入时间倒退 → `out_of_order_events`；
- 父事件不存在或自引用 → `missing_parent_event`；
- 最终按 `(timestamp, sequence, event_id)` 排序。

## 4. 回执采集

回执：

- 显式 `sensitive_ids`；
- 可选原始 `content`。

若 `content` 存在：

- 扫描合成密钥；
- 添加发现的敏感标识；
- 记录“明文已脱敏”问题；
- 从输出中删除正文；
- 添加 `content_redacted: true`。

回执按 ID 去重；冲突重复保留第一条并记录问题。

所有采集问题在合并后重新编号，确保 ID 唯一。

## 5. 脱敏

识别：

- `DEMOSECRET-[A-Z0-9]+-[A-Z0-9]{16}`；
- Base64 所在 token 解码后是否含该形态；
- 去零宽字符后的 NFKC 文本；
- 零宽分隔的密钥。

替换为固定 `[REDACTED:synthetic-secret]`。不将明文或可逆编码写入报告。

注意：这是面向合成密钥的脱敏器，不是生产环境的通用凭据扫描器。

## 6. 规则

规则输入为已脱敏事件、回执摘要和采集问题。

重点安全规则：

- AUD-003：injected 来源且外发成功；
- AUD-004：成功外发携带敏感标识；
- AUD-005：拒绝决定但结果成功；
- AUD-006：接收器记录敏感标识。

证据质量规则：

- AUD-001 缺权限决定；
- AUD-007 冲突重复；
- AUD-008 父事件缺失；
- AUD-009 输入明文已脱敏。

AUD-002 记录被拒绝的外发，严重度低，用于展示控制生效。

每条告警有确定 ID、规则 ID、严重度、事件/回执 ID 和结构化证据，不包含明文正文。

## 7. 关联

对每个含敏感标识的回执：

1. 用 receipt.event_id 查找外发事件；
2. 找不到则用外发事件结果 evidence.receipt_id 反向查找；
3. 从父事件和 `derived_from_event_ids` 收集祖先；
4. 选出读取事件，优先外部来源；
5. 提取文档元数据、读取证据；
6. 复制权限决定、执行结果、回执目标；
7. 合并回执显式敏感标识与事件证据中的敏感标识；
8. 写入固定关联声明。

输出字段：

```text
source_document
read_event_id
egress_event_id
permission
execution
receipt
observed_sensitive_ids
correlation_note
```

固定关联声明：

> Associated from recorded parent/event identifiers and receiver evidence. This is not a proof of causation.

## 8. 时间线

每个事件输出：

- 时间戳、事件 ID、运行 ID、序号、父 ID；
- 主体 ID/角色；
- 工具、来源；
- 权限决定/原因码/策略版本；
- 结果状态/摘要。

按采集阶段排序后的顺序。

## 9. 报告

JSON：

- 输入文件名；
- 计数；
- 采集问题；
- 告警；
- 时间线；
- 关联链；
- 规则目录；
- 免责声明；
- 限制。

HTML：

- 概览卡片；
- 告警表；
- 关联链卡片；
- 时间线表；
- 采集问题表；
- 限制。

所有动态文本 HTML 转义；最终 JSON/HTML 都经过统一脱敏。

## 10. 测试

- 乱序、重复、缺字段、缺父事件、冲突重复、非法行；
- 回执正文移除和敏感标识保留；
- 直接/Base64/零宽脱敏；
- 规则触发与严重度；
- 关联字段与固定免责声明；
- 无明文密钥；
- HTML 转义；
- CLI 输出和 `--fail-on-high`。

## 11. 明确不做

- 因果证明；
- 生产凭据扫描；
- 防伪造事件；
- 实时流处理；
- SIEM 集成；
- 对缺失数据的推测式补齐。
