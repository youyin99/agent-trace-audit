# Agent Trace Audit

脱敏事件采集、校验、时间线、规则告警与关联溯源报告。

工具读取 JSONL 执行事件和可选的本地接收器回执，输出版本化 JSON 报告和静态 HTML 报告。处理内容包括：

- 事件乱序；
- 完全重复事件；
- ID 相同但内容冲突；
- 缺字段、缺时间、缺父事件、缺权限决定、缺结果；
- 非法 JSONL；
- 输入中的合成密钥明文（输出前脱敏）；
- 接收器中的敏感证据与相关工具调用；
- “外部文档 → 文件读取 → 外发调用 → 权限决定 → 实际结果 → 接收器回执”的关联链。

报告不会表述为已证明因果关系。

## 安装

需要 Python 3.11–3.13，无运行时第三方依赖。

```bash
python -m pip install -e ".[dev]"
```

## 快速启动

```bash
python -m agent_trace_audit audit \
  --events fixtures/events.jsonl \
  --receipts fixtures/receipts.jsonl \
  --out examples/output
```

预期：

```text
events=7 receipts=1 alerts=10 high=3 critical=0 chains=1 issues=6
```

输出位于 [`examples/output/`](examples/output/)：

- `audit-report.json`
- `audit-report.html`
- `events.redacted.jsonl`
- `receipts.redacted.jsonl`

原始 fixture 故意包含合成密钥以验证脱敏；生成的日志和报告不包含明文密钥。

`--fail-on-high` 在出现 high/critical 告警时以退出码 1 结束。

## 仅采集

```bash
python -m agent_trace_audit collect \
  --events fixtures/events.jsonl \
  --receipts fixtures/receipts.jsonl \
  --out collected
```

输出去重、排序、脱敏后的 JSONL；原始回执正文被移除。

## 规则

| 规则 | 严重度 | 条件 |
|---|---|---|
| AUD-001 | medium | 权限决定缺失/非法 |
| AUD-002 | low | 外发被拒绝 |
| AUD-003 | high | 不可信来源外发成功 |
| AUD-004 | high | 成功外发携带敏感标识 |
| AUD-005 | high | 拒绝决定但有成功结果 |
| AUD-006 | high | 接收器记录敏感标识 |
| AUD-007 | high | 冲突重复事件 |
| AUD-008 | medium | 父事件缺失 |
| AUD-009 | medium | 输入含合成密钥明文并已脱敏 |

## 关联链

对带敏感标识的接收器回执：

1. 通过 `event_id` 或 `receipt_id` 证据找到外发事件；
2. 沿父事件/派生事件找到读取事件；
3. 优先选择证据中标记为外部来源的读取；
4. 复制权限决定（允许/拒绝、原因码、策略版本）；
5. 复制执行状态与摘要；
6. 关联回执、目标、观测到的敏感标识和哈希；
7. 加入固定的关联免责声明。

这是调查辅助，不是完整取证证明；只使用已记录的标识和关系。

## 脱敏

处理：

- `DEMOSECRET-*` 合成值；
- Base64 变体；
- 零宽字符分隔；
- NFKC 变体。

只保留 `synthetic-<hash>` 等不透明标识。采集后的回执移除正文。报告在写盘前再次统一脱敏。

## 测试

```bash
python -m pytest
```

覆盖去重、排序、缺字段/父事件、非法输入、冲突重复、回执清洗、直接/Base64/零宽脱敏、规则、关联字段、免责声明、HTML 转义、CLI 与 `--fail-on-high`。

## 已知限制

- 关联是证据关联，不是因果证明；
- 脱敏器只识别明确的合成密钥形态，不是生产凭据的通用扫描器；
- 信任输入事件如实记录 ID，伪造事件可能误导关联；
- 不包含数据库、搜索索引、实时流或远程日志接入；
- 对缺失顺序歧义不宣称完全覆盖。

## 贡献与安全

见 [`CONTRIBUTING.md`](CONTRIBUTING.md)、[`SECURITY.md`](SECURITY.md)。完整设计见 [`docs/DESIGN.zh-CN.md`](docs/DESIGN.zh-CN.md)。

## 许可

Apache-2.0，见 [`LICENSE`](LICENSE)。
