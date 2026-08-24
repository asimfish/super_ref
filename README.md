# Super Ref

Super Ref 是一个证据优先、多 agent 交叉核验的参考文献审计与修正系统。它真实下载每篇被引论文的 PDF、论文页元数据、官方 BibTeX 导出和注册库记录，由四个相互隔离、互不可见的独立 agent 逐项核对作者（遗漏/伪造/顺序）、标题、年份、会议，冲突即阻塞；修正必须经作者审批并绑定提案哈希后才允许写回账本。

本仓库从 [asimfish/super_rebuttal](https://github.com/asimfish/super_rebuttal) `3720e4e` 提取为独立项目，包含完整的引用核验子系统与一次真实数据审计运行。

## 核心保证

- **证据优先**：每条引用必须集齐四类来源家族——真实可解析的 PDF、论文落地页、站点引用导出（BibTeX）、注册库元数据（Crossref / arXiv Atom / OpenReview API），缺一即阻塞。
- **权威路由固定**：DOI 走 `doi.org` + Crossref，arXiv 走固定 landing/BibTeX/Atom/PDF 端点，OpenReview 只认 `openreview.net/pdf?id=` 官方路由；标识符与证据双向绑定，配置无法替换权威域。
- **四个隔离 agent**：`pdf_identity` / `website_citation` / `registry_crosscheck` / `adversarial_provenance` 各自只见自己的证据包，在全新临时目录中以只读、短生命周期进程运行，报告封套绑定批次/引用/角色/会话/提示词哈希。
- **冲突即阻塞**：不做多数投票。任一来源家族或任一角色的冲突、UNVERIFIED、缺席都会阻塞该条引用。
- **修正链路可审计**：consensus → propose 生成前后对照预览，作者批准需绑定提案 SHA-256；apply 走 PREPARED/COMMITTED 事务日志，可回滚、可恢复。
- **fail-closed**：无权威标识符、付费墙、反爬挑战、证据哈希漂移，一律保持阻塞，不猜测、不绕过。

## 环境要求

- Python 3.9+（核心零第三方依赖）
- Poppler `pdftotext`（macOS: `brew install poppler`）
- [Codex CLI](https://github.com/openai/codex)（`run-agents` 用它启动四个隔离会话）
- 在线采集需要网络；全部回归测试可离线运行

## 快速开始

```bash
# 1. 准备 workspace：目录 + REFERENCES.json（格式见下）
mkdir -p workspaces/my-audit

# 2. 冻结账本为审计批次
python3 scripts/citationctl init workspaces/my-audit

# 3. 真实下载并解析每条引用的全部证据
python3 scripts/citationctl collect workspaces/my-audit

# 4. 生成四个相互隔离的证据包
python3 scripts/citationctl packetize workspaces/my-audit

# 5. 四个全新 Codex 会话独立核验
python3 scripts/citationctl run-agents workspaces/my-audit

# 6. 共识裁决（哈希、身份、角色、来源一致性、字段一致性）
python3 scripts/citationctl consensus workspaces/my-audit

# 7. 生成修正预览（不改动账本）
python3 scripts/citationctl propose workspaces/my-audit

# 8. 作者过目后，绑定提案哈希批准写回
python3 scripts/citationctl apply workspaces/my-audit --author-approved \
  --replace-ledger --proposal-sha256 '<printed-sha256>'

# 9. 校验证明链
python3 scripts/citationctl doctor workspaces/my-audit
```

单条修复用 `--only REF-ID`；重采/重打包需显式 `--overwrite`；账本变更后用 `init --new-batch`（旧批次自动归档到 `CITATION_AUDIT_ARCHIVE/`）。

## REFERENCES.json 格式

```json
{
  "schema_version": 2,
  "enforce": true,
  "references": [
    {
      "reference_id": "REF-EXAMPLE",
      "citation_key": "vaswani2017attention",
      "entry_type": "inproceedings",
      "authors": ["Ashish Vaswani", "Noam Shazeer"],
      "title": "Attention Is All You Need",
      "venue": "NeurIPS",
      "year": "2017",
      "doi": "10.xxxx/example"
    }
  ]
}
```

标识符三选一：`doi` / `arxiv_id` / `openreview_id`。作者数组按印刷顺序记录「声称值」，审计会对照证据提出修正。

## 网络策略与实战注意

- 默认 `strict` 模式做公网 DNS 与真实对端校验。本机全局代理（如 127.0.0.1:7890 的 Clash 类中继）会触发「actual network peer is not public」，此时在 workspace 的 `PROJECT_CONTEXT.json` 启用受信中继模式并显式列出允许域：

```json
{
  "citation_audit": {
    "network": {
      "resolver_mode": "trusted_proxy",
      "allowed_domains": ["arxiv.org", "openreview.net", "doi.org",
                           "crossref.org", "semanticscholar.org", "aaai.org"]
    }
  }
}
```

- `trusted_proxy` 仍拒绝 IP 直连、内嵌凭据、非 HTTPS 和白名单外重定向；策略地板（四来源家族、四角色、全来源一致、HTTPS）不可配置移除。
- arXiv API（export.arxiv.org）有突发限流（429），逐条采集并保持 ≥15s 间隔即可恢复。
- OpenReview 自 2026 年起对未认证 API/PDF 路由启用浏览器 challenge（HTTP 403 `ChallengeRequiredError`）；系统按规不绕过，请改用 arXiv 等可验证官方替代路由，或等待窗口。
- 会议/期刊口径必须由出版方权威通道证实：arXiv 预印本路由可核作者与标题，但通常无法证实 venue/出版年（预印本各来源年份还会互相冲突），此类引用会按设计阻塞。
- 传输层会按 `Content-Encoding` 声明或 gzip 魔数解压响应（解压后仍受同一字节上限约束）；曾观测到 `ojs.aaai.org` 无视 `Accept-Encoding: identity` 且不声明编码直接返回 gzip 字节。

## 修正链路示例：workspaces/labelfree-correction-demo

单条引用的全链路演示（批次 `b15a13aa`）：AAAI 2017 开放获取论文，声称作者为印刷缩写 `R. Stewart, S. Ermon`。四 agent 共识判定 `CORRECTION_REQUIRED`（0 阻塞），`propose` 已生成前后对照：

```text
authors: ["R. Stewart", "S. Ermon"]  ->  ["Russell Stewart", "Stefano Ermon"]
proposal sha256: 4182b7d51d2a51edf22956fbff3bb0669574e96bec6edebc99aeee6dec0e8122
```

作者审阅 `CITATION_CORRECTIONS.json` 后自行执行：

```bash
python3 scripts/citationctl apply workspaces/labelfree-correction-demo \
  --author-approved --replace-ledger \
  --proposal-sha256 4182b7d51d2a51edf22956fbff3bb0669574e96bec6edebc99aeee6dec0e8122
python3 scripts/citationctl doctor workspaces/labelfree-correction-demo
```

按设计，agent 不得代替作者提供批准标志与哈希。

## 真实数据示例：workspaces/capsat-citation-audit

对一篇 NeurIPS 2026 投稿 rebuttal 中逐字转录的 13 条引用声称做了完整审计（批次 `8f4eb633`）：

- **1 条完成四 agent 共识并要求修正**（AAAI 2017，走 DOI + AAAI OJS 开放获取通道）：印刷缩写 `R. Stewart, S. Ermon` 应修正为论文实印全名 `Russell Stewart, Stefano Ermon`（`authors_missing` + `authors_extra_or_fabricated`）。
- **7 条阻塞于预印本路由**（MUST / SATformer / ImitSAT / Graph-Q-SAT / NSNet / G4SATBench / Survey Propagation）：venue 达不到两来源家族一致；arXiv 落地页与 BibTeX 导出年份互相冲突；其中 MUST 还出现 PDF 与站点引用的作者中间名不一致（Steven Hoi vs Steven C. H. Hoi）。
- **5 条 fail-closed 拒入审计**：ACM 付费墙 + 反爬（SIMON/SPECK），以及四条无任何 DOI/arXiv/OpenReview 标识的经典文献（Selman 1994 / SATLIB 2000 / SAT Competition 2024 solver 描述 / Pearl 1988 专著）——按规范应由作者提供可验证替代来源或删除引用。
- `propose` 被账本中 5 条无裁决条目整体门控：账本存在无法核验的条目时不允许出修正案。

全部证据、隔离包、32 份带哈希绑定的 agent 报告和裁决书都在该 workspace 的 `CITATION_AUDIT/` 下，可用 `citationctl doctor` 复核证明链。

## 回归测试

```bash
python3 evals/run_citation_unit_evals.py    # 226 项单元/属性测试（解析、归一化、策略、传输）
python3 evals/run_citation_evals.py         # 86 项端到端安全与状态机测试（含确定性 fake-codex 生成路径）
```

覆盖假 PDF/登录页拒收、作者遗漏/添加/乱序、来源与字段冲突、BibTeX 歧义、提示注入隔离、包/报告/符号链接篡改、身份复用、权威标识失配、精确提案审批、apply 回滚与事务闭合、gzip 解压上限、并行 agent 下的报告扫描竞态等。
