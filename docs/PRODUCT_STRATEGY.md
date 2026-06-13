# Product Strategy Canvas — ACGS / gove-zone

> **核心不变式 (Core invariant):** *No valid Decision Receipt, no side effect.*
>
> ACGS 不是 agent 框架,而是位于「agent 推理之下、有副作用工具之上」的**执行膜 (execution membrane)**。
> Agent 框架可以规划或请求操作;ACGS 决定执行器是否真的可以运行它们。

**状态 (Status):** 草案 / 早期阶段。本文档对成熟度做诚实标注——**未**声称合规认证、受监管批准或生产就绪;此类声明需发布与外部证据支撑(见 `AGENTS.md` 的 "Forbidden changes")。

**范围 (Scope):** 伞形产品 ACGS / gove-zone(收据门控治理层)。`acgs-lite` 为其 PyPI 面向库,`Acgs-Swarm` / `clinicalguard` 为研究与领域落地抓手。

---

## 1. Vision(愿景)

**让 AI agent 的每一个副作用都可治理、可验证、可追责——默认 fail-closed。**

- **激励 (Inspire):** 当 agent 开始真正执行操作(支付、写库、调外部 API)而非只是聊天时,「它真的被允许这么做吗?谁批准的?能证明吗?」成为不可回避的问题。我们让这个答案变成一张可验证的**决策收据 (Decision Receipt)**。
- **抱负 (Aspire):** 成为 agentic 系统副作用层的事实标准治理膜,如同 TLS 之于传输。
- **价值观 (Values):** fail-closed 优先于便利;可验证证据优先于信任;诚实声明边界优先于营销夸大。

---

## 2. Market Segments(以「问题」而非人口统计定义)

| 优先级 | 细分 | JTBD(待办任务) | 约束 |
|---|---|---|---|
| **S1(首攻)** | **构建 agentic 产品的受监管 / 高风险团队**(金融、医疗、法务工具) | "当我的 agent 执行有真实后果的操作时,我需要先于执行强制策略,并留下能在审计 / 事故时拿得出手的证据" | 必须 fail-closed;审计可追溯;不能拖慢正常路径 |
| S2 | **平台 / 基础设施团队**(给内部多个 agent 团队提供护栏) | "我要给所有团队一个统一的副作用门,而不是每个团队各写各的检查" | 多租户;与现有 agent 框架解耦 |
| S3 | **合规 / 治理负责人**(买方,非直接用户) | "我要能向监管者 / 客户证明 agent 行为受控,而非靠口头保证" | 证据格式可独立验证;防篡改 |

**为什么 S1 先:** 他们有**真实的痛**(执行后果 + 审计压力)、有预算、且对 fail-closed 的「不便」容忍度最高——这正是我们最强、竞品最弱的地方(见 §9)。

---

## 3. Relative Costs(成本定位)

**偏向「独特价值」而非「低成本」**(更接近 Starbucks 而非 Southwest),但有一个关键限定:

- **核心运行时 (gove-zone kernel) 零运行时依赖、可自托管** → 采用成本极低、无供应商锁定担忧 → 这本身是面向开源 / 自建团队的「低摩擦」杠杆。
- **价值溢价**来自:可验证收据 + 防篡改审计 + replay,而非席位数或算力。

---

## 4. Value Proposition(分段价值主张)

### S1 — 受监管 agentic 团队

- **What before:** agent 直接调用有副作用的工具;护栏散落在 prompt 和零散 if 判断里;出事后无法证明「当时为什么允许」。
- **How:** 在执行器与工具之间插入 gove-zone 膜——执行前评估策略,签发绑定了 actor / action / 参数 / 策略 / 审计的 Decision Receipt;无有效收据则执行器拒绝运行。
- **What after:** 每个副作用都有可独立验证、可 replay 的证据链;DENY / ESCALATE 不可被当作可执行结果;审计从「翻日志猜测」变成「出示收据」。
- **Alternatives(今天的替代品):**
  1. 自己写零散检查
  2. 纯审计日志(事后,不阻断)
  3. Microsoft Agent Governance Toolkit(以**审计为中心**)
  4. Guardrails / 输入输出过滤(管内容,不管副作用授权)

> **诚实对比锚点:** 最近的对照物是 **Microsoft Agent Governance Toolkit (AGT)**——它**以审计为中心**;gove-zone **以收据为中心**(决策收据是一等公民,执行器据此 fail-closed)。Entra Agent ID / Purview / Foundry Guardrails 是**互补层**而非直接竞争。详见 `docs/COMPARISON.md`。

---

## 5. Trade-offs(明确不做)

- **不做 agent 框架 / 编排:** 我们不和 LangGraph / CrewAI 竞争,我们坐在它们下面。
- **不做内容审核 / 对齐:** 输入输出安全交给 Guardrails 类产品,我们管的是**副作用授权与证据**。
- **不为便利牺牲 fail-closed:** 不提供「跳过收据」的生产快捷开关。
- **首阶段不追求横向铺满所有框架:** 先把 S1 的深度证据链做到无可辩驳,再谈广度。
- **不声称合规认证 / 生产就绪**(直到有发布与外部证据支撑)。

---

## 6. Key Metrics(关键指标)

- **North Star Metric:** **受门控的有副作用操作数 / 周**(经 gove-zone 签发有效收据后执行的真实操作量)——直接度量「膜真的在关键路径上承载流量」,而非只是被安装。
- **本季 OMTM (One Metric That Matters):** **生产集成数**(把 gove-zone 接入真实执行路径、且有 dispatcher 级集成测试证明 wiring 的团队 / 应用数)。
  - *理由:* 当前阶段最大风险不是采用意愿,而是「装了但没接到真实路径」(handler 未 wiring 是已知失败类,见 `~/.claude/rules/review-handler-wiring.md`)。OMTM 强制度量真实承载,而非 star 数。

---

## 7. Growth(增长)

- **主引擎:Product-Led(开源 + PyPI)。** `acgs-lite`(已上 PyPI)+ 自托管零依赖 kernel = 开发者可零摩擦试用。
- **获客渠道:**
  1. 开源 / 技术内容(决策收据规范、安全模型、tamper demo)
  2. 受监管 AI 社区与会议
  3. 与 agent 框架的集成示例(出现在它们的"治理"推荐位)
- **扩张路径:** 开发者自建试用 → 平台团队标准化 → 合规买方为「可验证证据 + 多租户 + 托管审计」付费(开放核心 / managed 模式)。
- **单位经济:** 核心自托管成本趋零;变现在托管审计存储、多租户管理、企业支持 / 合规对接。

---

## 8. Capabilities(所需能力)

- **必须自建(护城河来源):** Decision Receipt 规范、签名、防篡改审计(Merkle / 链式)、replay、fail-closed 执行器语义、安全模型——这些是产品的灵魂,见 `docs/DECISION_RECEIPT_SPEC.md` / `docs/SECURITY_MODEL.md`。
- **可合作 / 集成:** 与各 agent 框架的适配器、密钥 / 身份基础设施(对接 Entra Agent ID 等,作为**互补**而非重写)、托管存储后端。
- **关键待补能力:**
  1. 一键 wiring + dispatcher 级集成测试模板(降低「装了没接」风险)
  2. 独立可验证收据的第三方校验工具
  3. 真实领域落地证据(`clinicalguard` 是医疗域抓手)

---

## 9. Can't / Won't(防御性)

**为什么竞品难抄:**

- **以收据为中心的架构是设计哲学,不是功能:** 从「审计为中心」改造成「执行前签发不可绕过的决策收据 + 执行器 fail-closed」是地基级改写,不是加个模块。
- **可验证证据格式 + replay** 一旦成为客户审计流程的依赖,迁移成本 (switching cost) 很高。
- **零运行时依赖 + 自托管** 让安全敏感客户敢用,大厂 SaaS 绑定反而是其短板。

**壁垒:** 证据规范若被生态采纳 → 标准 / 网络效应;防篡改审计 + replay → 客户审计流程嵌入式锁定。

**诚实的弱点:** 品牌与分发远不及 Microsoft;领域落地证据仍薄;尚无外部认证。护城河目前是**架构正确性 + 早期信任**,需要尽快用 S1 的真实集成把它转成证据。

---

## 关键假设(必须为真,strategy 才成立)

1. **H1:** 受监管 agentic 团队确实把"副作用授权 + 可验证证据"当作必须项,而非 nice-to-have。
2. **H2:** fail-closed 的「不便」在 S1 是可接受的(甚至是卖点)。
3. **H3:** Decision Receipt 能在不显著拖慢正常执行路径的前提下签发。
4. **H4:** "以收据为中心"相对"以审计为中心"(AGT)在 S1 眼中是有意义、值得迁移的差异。
5. **H5:** 开源核心能把开发者采用转化为平台 / 合规层的付费。

## 低成本验证实验

| 假设 | 实验(最小成本) | 成功信号 |
|---|---|---|
| H1 / H4 | 对 5–8 个 S1 团队做问题访谈:"agent 执行有后果操作时你如何证明授权?" | 多数无满意答案且主动要 demo |
| H2 | 给 1 个真实集成跑 fail-closed,记录团队是否要求"绕过开关" | 不要求绕过 = H2 成立 |
| H3 | 基准测:收据签发对执行路径的延迟开销(已有 tamper / replay demo 可扩展) | p95 开销在可接受阈值内 |
| H4 | 发布诚实对照文(已有 `docs/COMPARISON.md` vs AGT),观察 S1 反馈 | "收据中心"被引用为选择理由 |
| H5 | 在 acgs-lite PyPI 加 managed-audit waitlist | 自建用户中有 X% 表达付费意向 |

---

## 一致性校验

9 个要素相互强化:**愿景(可验证治理膜)→ 价值主张(收据 fail-closed)→ 防御性(收据中心架构难抄 + replay 锁定)→ 指标(度量真实承载而非安装)→ 增长(开源降摩擦后向合规层变现)→ 取舍(不做框架 / 不做内容审核,保住"膜"的纯粹定位)。**

最大张力点是 **§7 增长依赖分发能力,而 §9 承认分发是弱项**——这是首阶段最该用 S1 真实集成证据去对冲的风险。

---

## 复审节奏

每季度复审一次,或在以下事件后立即复审:竞品(尤其 Microsoft AGT)重大变化、首批 S1 集成产生证据、发布里程碑达成。

---

*本文档为战略草案,非工程契约。具体的收据 / 策略 / 审计行为以代码与测试为准:`docs/DECISION_RECEIPT_SPEC.md`、`docs/SECURITY_MODEL.md`、`docs/CLAIMS.md`。*
