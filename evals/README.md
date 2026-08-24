# Evals

两套全离线、确定性的回归套件，改动核心代码后必须全绿才可交付。

## run_citation_unit_evals.py（226 项）

单元/属性层：解析（BibTeX、注册库、落地页元数据）、归一化（作者定向、变音符、venue 别名）、策略校验（角色/来源家族地板）、传输安全（URL/DNS/重定向/字节上限、gzip 解码与炸弹拒收）、路径遏制。回归定位到函数级。

```bash
python3 evals/run_citation_unit_evals.py        # 全部
python3 evals/run_citation_unit_evals.py -v     # 详细
python3 evals/run_citation_unit_evals.py GzipBodyDecodingTests  # 单类
```

## run_citation_evals.py（86 项）

端到端安全与状态机层：用结构合法的生成 PDF、离线 fixture 传输和确定性 fake-codex 二进制锁定完整链路——假 PDF/登录页拒收、作者遗漏/添加/乱序、字段与来源冲突、提示注入隔离、包/报告/符号链接篡改、身份与会话复用、权威标识失配、精确提案审批、apply 事务回滚与闭合、并行 agent 报告扫描竞态、fixture 证据不得混入生产门禁。

```bash
python3 evals/run_citation_evals.py
```

两套均只依赖标准库与系统 `pdftotext`，不需要网络与真实 Codex CLI。
