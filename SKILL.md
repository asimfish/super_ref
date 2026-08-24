---
name: super-ref
description: Use when the user asks to verify, audit, or fix the references/citations of a paper, rebuttal, or bibliography — downloads real PDFs, site BibTeX, and registry metadata, cross-checks authors/title/year/venue with four isolated agents, and only applies corrections after author approval bound to the proposal SHA-256.
---

# Super Ref — 引用核验与修正

## 何时使用

用户要求「核对参考文献 / 检查引用是否有假 / 修正作者名单」等任务时使用。输入可以是 BibTeX 文件、论文引用清单或正文中的引用声称。

## 硬性规则（不可协商）

1. 声称值照原文转录进 `REFERENCES.json`（含缩写与错误），由审计提出修正；禁止你自己"顺手改对"。
2. 每条引用需要 `doi` / `arxiv_id` / `openreview_id` 之一；没有权威标识的引用如实报告为不可核验，让作者提供替代来源或删除，禁止用任意 URL 冒充。
3. 付费墙、反爬 challenge、来源冲突 = 保持阻塞并报告，禁止绕过。
4. `apply` 的 `--author-approved` 与 `--proposal-sha256` 只能由作者本人在过目 `CITATION_CORRECTIONS.json` 后提供；agent 不得代批。
5. 会议/期刊口径必须走出版方权威通道（DOI/OpenReview）；arXiv 预印本路由通常只能证实作者与标题。

## 流程

```bash
mkdir -p workspaces/<name>            # + 写入 REFERENCES.json（格式见 README）
# 本机走全局代理时，在 PROJECT_CONTEXT.json 配 trusted_proxy + 显式域白名单
python3 scripts/citationctl init workspaces/<name>
python3 scripts/citationctl collect workspaces/<name>     # arXiv API 限流则逐条 --only 并间隔 15s+
python3 scripts/citationctl packetize workspaces/<name>
python3 scripts/citationctl run-agents workspaces/<name>  # 需要 codex CLI
python3 scripts/citationctl consensus workspaces/<name>
python3 scripts/citationctl propose workspaces/<name>     # 账本有 BLOCKED 时会被门控，如实报告
# ↓ 作者审阅 CITATION_CORRECTIONS.json 后自行执行
python3 scripts/citationctl apply workspaces/<name> --author-approved --replace-ledger --proposal-sha256 '<sha>'
python3 scripts/citationctl doctor workspaces/<name>
```

## 收工报告必须包含

- 每条引用的裁决（PASS / CORRECTION_REQUIRED / BLOCKED）与具体理由
- 修正提案的前后对照与提案 SHA-256（等作者批准）
- 不可核验条目清单及规范给出的两条出路（替代来源 / 删除引用）
- `doctor` 结论与产物路径
