# acgs-lite — 最小可信 PEP 闭环 Final Goal

> Status: VERIFIED DRAFT（2026-06-10，全部 claim 已经过 file:line 反向取证）
> Scope: `packages/acgs-lite`（嵌套 git 仓库，PyPI 已发布，公共 API 受稳定性约束）
> Goal statement: 把 acgs-lite 从 "beta governance SDK" 推到 "最小可信 PEP"——所有副作用必须先被授权、授权不可重放、证据不可丢、规则不可暗改、身份不可伪造。

## 0. 取证结论（goal 的事实基础）

| Claim | 判定 | 关键证据 |
|---|---|---|
| A 执行边界不统一：`GovernedCallable` receipt-gated，`GovernedAgent.run/arun` 无 receipt | CONFIRMED | `governed.py:709-726` vs `governed.py:318-396`（run() 六步无 receipt）；`invariants.py:122-123` fail-closed 只覆盖 callable 路径 |
| A+ async 漏项（审计未提）：`arun()` 缺 circuit breaker 且不发 CDP | CONFIRMED | `governed.py:535-537`（无 Step 0）；成功/deny 路径无 `_emit_cdp` |
| B receipt 可重放：无 nonce / consumed 状态机 / argument_hash | CONFIRMED | `receipt.py:32-48` frozen dataclass；`single_use` 是死字段（仅 `receipt.py:29`、`signing.py:260`、`selector.py:250,332` 出现，校验路径从不读取）；selector 签发 `expires_at=None` |
| C constitution hash 覆盖不全 | PARTIAL（实质成立） | `constitution.py:119-123` 只纳入 id/text/severity/hardcoded/keywords；排除 patterns/condition/workflow_action/enabled/valid_from/valid_until/category 等；hash 本身截断 16 hex |
| D output validation 在副作用后 | CONFIRMED | `governed.py:352` execute → `:354+` validate；retry 循环（`:390-391`,`:579-580`）每轮先执行再校验 |
| E /validate 为 advisory | CONFIRMED | `server.py:386-391` 显式 `strict=False`；端点只回 JSON，无 server 端阻断 |
| F audit 链偏弱 | CONFIRMED | 链 hash 截断 16 hex（`audit.py:260,370,576`）；默认 in-memory + 10000 条滚动丢弃；`record()` fail-open（`:336-342`，fail-closed 的 `record_atomic` 是 opt-in）；`from_backend` 加载不验链（`:532-559`） |
| G principal 绑定缺失 | CONFIRMED | `maci.py:229-285` 裸字符串 agent_id；`server.py:424` 来自请求 body；唯一认证是共享 X-API-Key，与 agent_id 零绑定 |
| H1 CDP fail-open | PARTIAL | fail-open 成立但非静默（`governed.py:495-502` error 日志）；`GovernanceHaltError` 会重新 raise（`:504-506`） |
| H2 PQC 默认关闭 | CONFIRMED | `audit.py:281` 默认无 signer；`InMemoryPQCSigner` 用硬编码 `b"test-key"`；certificate 签名也截断 `[:32]`（`certificate.py:142`） |

## 1. 硬约束（goal 执行期间不可违反）

1. **公共 API 稳定性**：acgs-lite 已发布 PyPI。任何把 receipt 变为 `GovernedAgent.run()` 硬性前提的改动都是 breaking change。策略（推荐）：新增 `require_receipt: bool` / `receipt_gate=` 参数 + 默认 False + DeprecationWarning，宣布 v3 翻转默认值。决策点归用户。
2. **嵌套仓库纪律**：所有 commit 在 `packages/acgs-lite` 内部完成；父仓库 pointer 更新是独立步骤。
3. **constitutional hash 重算**：AGENTS.md 锚定 `608508a9bd224290`；任何改变 hash 算法的 PR 必须同步重算并更新锚点 + lock 文件，走生成路径而非手改。
4. **claim-safe 文档**：每个 PR 合并前同步降级/升级 docs/CLAIMS.md 相应措辞；hash v2 落地前不得宣称 "cryptographically verifies governance semantics"。
5. **gove-zone 先例可移植**：单次消费 receipt（consumption ledger，keyed on audit_event_hash）已在 gove-zone PR-4b（#114）落地，PR-2 应参考其设计而非从零造。

## 2. Goal criteria（7 项，按闭环依赖排序）

### G1 — 统一 side-effect execution boundary
`GovernedAgent.run/arun`、`GovernedCallable`、server 执行路径共用一个 receipt gate。
验收：no receipt→deny；expired→deny；wrong method/args-hash/actor→deny；sync 与 async 行为一致（含补齐 arun 的 circuit breaker 与 CDP 发射）。
⚠️ 受约束 1 控制：默认行为经 opt-in 参数过渡。

### G2 — single-use receipt 防重放
激活现有 `single_use` 死字段 + consumed store（atomic consume）+ nonce + `argument_hash` 绑定。
验收：同一 receipt 第二次执行 fail-closed；并发双执行仅一个成功；selector 签发的 receipt 不再 `expires_at=None` 且默认 single_use=True。

### G3 — constitution hash v2
canonical JSON 序列化，纳入全部 enforcement 相关字段（patterns/condition/workflow_action/enabled/valid_*/category/metadata…），完整 64-hex SHA-256，版本化格式 + 向后兼容标记。
验收：改 workflow_action/enabled/pattern → hash 变；非语义字段重排 → hash 不变。

### G4 — audit chain 强化
完整 SHA-256 链 hash；`from_backend` 加载时验链；production profile 强制持久化 backend + fail-closed 写入（`record_atomic` 成为 production 默认）。
保留 dev/demo 快速模式，但 production gate 必须显式区分。

### G5 — structured action proposal（execute 前授权）
agent 不直接执行工具：先产出结构化 action proposal（actor/tool/method/resource/arguments_hash/risk_level），PEP 校验 receipt 后才执行副作用；retry 循环每轮重新过 gate。
关键修复点：`governed.py:352` 的 execute-then-validate 顺序与 retry 重复执行。

### G6 — authenticated principal → MACI 绑定
agent_id 从"调用方声明"变为"认证结果映射"：支持 JWT claims / mTLS / workload identity 至少一种，X-API-Key 升级为 per-principal。HTTP body 里的 agent_id 仅作声明、必须与 principal 一致否则 deny。

### G7 — threat model + red-team 回归套件
覆盖：receipt replay、argument substitution、self-approval、audit 写失败、链篡改、hash drift、关键词绕过、async/sync 分歧、server fail-open、agent_id 冒用。每个 G1–G6 的验收测试纳入该套件并在 CI 常驻。

## 3. 降级处理（不进 goal criteria，文档止血）

- PQC 非默认、CDP fail-open（observability 定位下可接受）、合规标签 → docs/CLAIMS.md 措辞修正："mapping only, not certification"；"beta governance SDK with receipt/audit foundations"。
- `/validate` 保留为 advisory PDP，但文档明确它不是安全边界；强 PEP 形态（wrapper/MCP gateway）列入 ROADMAP。

## 4. 禁用叙事（G1–G6 全部完成前）

tamper-proof audit / compliance-ready / regulator-grade evidence / enterprise control plane / "receipt-bound execution"（指 GovernedAgent 时）/ "cryptographically verifies governance semantics"。

可用叙事：receipt-based governed execution prototype；tamper-evident audit chain（截断修复后）；fail-closed SDK path for selected governed calls。
