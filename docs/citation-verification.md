# Citation Verification and Correction

This subsystem verifies bibliographic identity from downloaded evidence before a
reference can be used in a strict rebuttal. It is fail-closed: missing evidence,
source disagreement, agent disagreement, stale hashes, or an unapproved
correction blocks finalization.

In a strict workspace, any claim with a non-empty `citation_ids` list activates
this gate. Removing or disabling `PROJECT_CONTEXT.json.citation_audit` cannot
bypass verification.

## 1. What Is Verified

Every cited work must close all four fields:

| Field | Required checks |
|---|---|
| Authors | exact people, missing people, unsupported/possibly fabricated people, and printed order |
| Title | complete title after conservative punctuation/LaTeX normalization |
| Year | explicit publication/version year; unexplained preprint/proceedings conflicts block |
| Venue | actual journal/conference/repository container; common venue aliases normalize only for comparison |

The evidence bundle must contain all four source families:

1. A real paper PDF that passes magic/size checks and can be parsed by
   `pdftotext`.
2. The paper landing page, including its scholarly citation metadata.
3. The citation export provided by that site, normally BibTeX.
4. Bibliographic registry metadata, such as Crossref, arXiv Atom, or OpenReview
   note metadata. Semantic Scholar can be retained as a secondary cross-check.

`%PDF-` alone is not sufficient. HTML challenge pages, padded fake PDFs, empty
identity text, and unparseable files are rejected.

## 2. Reference Input

`REFERENCES.json` uses an ordered author array:

```json
{
  "schema_version": 2,
  "enforce": true,
  "references": [
    {
      "reference_id": "REF-TRANSFORMER",
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

DOI and arXiv adapters derive standard URLs. An OpenReview reference needs only
`openreview_id`: the collector downloads the fixed official forum/PDF/API
routes and derives `citation.bib` from that exact note's official `_bibtex`
field, which is what the OpenReview web UI exposes.
The production adapters bind identifiers to fixed authority routes:

- DOI: `doi.org` resolution/content negotiation plus Crossref metadata;
- arXiv: fixed `arxiv.org` landing/BibTeX/PDF plus the arXiv Atom API;
- OpenReview: fixed forum/PDF/API endpoints plus `_bibtex` from the same
  identifier-bound API note.

DOI, arXiv, and OpenReview authority URLs cannot be replaced through workspace
configuration; an OpenReview `citation_url` field is ignored. Identifier values
found in the site export and registry must match the audited identifier. The `explicit` adapter remains for
offline fixtures and diagnostics only; caller-labelled arbitrary URLs are not
eligible for a production PASS. Add a trusted adapter instead of weakening this
policy for an unsupported registry.

OpenReview PDF acquisition never falls back to a URL declared in note metadata
or landing-page HTML. Only `https://openreview.net/pdf?id=<note>` is eligible;
if that route does not return a valid parseable PDF, collection blocks even when
the note advertises another absolute URL.

Existing BibTeX can be imported only when the ledger is empty:

```bash
python3 scripts/citationctl init <workspace> --bib paper/references.bib
```

The parser preserves citation keys and author order. Unsupported macro
concatenation, duplicate fields/keys, unsafe citation keys, and a paper-specific
site export containing anything other than one entry all block rather than
being evaluated, overwritten, or guessed.

## 3. End-to-End Commands

```bash
# 1. Freeze the current ledger into a new audit batch.
python3 scripts/citationctl init <workspace>

# 2. Actually download and parse every source.
python3 scripts/citationctl collect <workspace>

# 3. Create four mutually isolated evidence packets per reference.
python3 scripts/citationctl packetize <workspace>

# 4. Run four fresh Codex processes; packets contain no prior reports.
python3 scripts/citationctl run-agents <workspace>

# 5. Verify hashes, identities, roles, source agreement, and field agreement.
python3 scripts/citationctl consensus <workspace>

# 6. Produce a before/after preview. REFERENCES.json is unchanged.
python3 scripts/citationctl propose <workspace>

# 7. Only when fields change: review them and bind approval to propose's SHA.
python3 scripts/citationctl apply <workspace> --author-approved --replace-ledger \
  --proposal-sha256 '<printed-sha256>'

# 8. Check the proof chain and the rebuttal final gate.
python3 scripts/citationctl doctor <workspace>
python3 scripts/rebuttalctl lint <workspace>

# Recovery only: use this when doctor reports apply=PREPARED.
python3 scripts/citationctl recover <workspace>
```

Use `--only REF-ID` on collect, packetize, run-agents, or consensus while
repairing one item. Recollection and re-packetization require explicit
`--overwrite`. A changed ledger requires a new batch:

```bash
python3 scripts/citationctl init <workspace> --new-batch
```

The old batch is moved to `CITATION_AUDIT_ARCHIVE/`; it is not silently erased.
When `propose` reports zero changes, its PASS summary already binds the current
ledger and no empty `apply` is needed. A PREPARED apply transaction must be
recovered before starting another apply or audit batch.

Citation gates are activated by the contract's `citation_ids`, not by
`RESPONSE_STYLE.json`. Disabling or misspelling a presentation profile cannot
skip audit, draft blocking, or References binding.

## 4. Independent Agent Chain

| Role | Evidence visible to that process | Required result |
|---|---|---|
| `pdf_identity` | PDF hash and extracted identity pages only | printed authors in order and exact title |
| `website_citation` | landing metadata and site BibTeX only | reconcile site page/export for all fields |
| `registry_crosscheck` | registry observations only | independently report all registry fields/conflicts |
| `adversarial_provenance` | original record, structured observations, URLs, hashes | try to falsify the claimed reference |

Each `run-agents` worker runs in a fresh temporary directory. The complete
packet is embedded directly in that process's standard input, so no shell/file
read is needed; only the response schema and output path exist in the temporary
directory. Codex user config and repository rules are ignored, the inherited
environment is allowlisted, and the process is ephemeral/read-only.
Before any subprocess starts, both the CLI selector and runner independently
require the canonical `packets/<reference>/<role>.json` path, reject path escape
and symlink components, and recheck the manifest hash plus batch/reference/role/
evidence bindings on the exact bytes embedded in the prompt.
Its report envelope binds:

- audit batch, reference, role, unique agent id, unique Codex session id, and
  invocation id;
- packet, evidence, report-body, runner-binary, schema, and exact embedded-prompt SHA-256;
- read-only/ephemeral/packet-embedded process-isolation receipt and environment policy;
- exact artifact ids used for every field.

The report-body hash is recalculated both before consensus and at the final
offline gate. A report whose assessment changed after recording is rejected,
even if another local artifact still contains its old receipt.

The consensus reducer requires exactly one report for every role and rejects
reused agent or Codex session identities. These are independently executed,
mutually blind processes, not claims of four separately authenticated human
principals. It never resolves a conflict by majority vote. A 3:1 source or
agent split remains `BLOCKED`.

`record-report` exists for external diagnostics and interoperability. A report
recorded without a verified process-isolation receipt is intentionally
ineligible for final consensus; it cannot be used to manufacture quorum.

## 5. Evidence and Decisions

```text
CITATION_AUDIT/
|-- manifest.json
|-- evidence/<reference-id>/
|   |-- original-reference.json
|   |-- paper.pdf
|   |-- paper.first-pages.txt
|   |-- landing.html
|   |-- citation.bib
|   |-- registry-*.json
|   `-- evidence.json
|-- packets/<reference-id>/<role>.json
|-- reports/<reference-id>/<role>--<agent-id>.json
|-- decisions/<reference-id>.json
`-- agent-logs/<reference-id>/<role>.log
```

Workspace-level outputs:

- `CITATION_AUDIT_SUMMARY.json`: final offline gate bound to the exact current
  `REFERENCES.json` hash.
- `CITATION_CORRECTIONS.json`: field-level before/after proposal and discrepancy
  codes.
- `REFERENCES.corrected.json` / `.bib`: reviewable previews.
- `REFERENCES.pre-citation-audit.<timestamp>.json`: automatic backup created
  before approved replacement.

Discrepancy codes distinguish `authors_missing`,
`authors_extra_or_fabricated`, `authors_order_mismatch`, `title_mismatch`,
`year_mismatch`, and `venue_mismatch`.

## 6. Network and Content Safety

Production fetching uses HTTPS, bounded response sizes, bounded per-request and
aggregate body-read time, capped redirect chains, redirect/final-URL
revalidation, public DNS and actual-peer checks, cross-host credential
stripping, no URL credentials, and structured argv for PDF extraction.
Some hosts compress responses even for `Accept-Encoding: identity`; declared or
magic-detected gzip bodies are decoded with the same per-kind byte cap applied
to the decoded output, and any other content encoding is rejected.
Registries burst-limit consecutive collects (observed: HTTP 429 from
`export.arxiv.org`). The transport paces same-host requests at a minimum
interval and retries HTTP 429 — plus 503 only when the origin commits to a
`Retry-After` window — under a clamped retry count and total wait budget;
exhausting either bound fails closed like any other fetch error, and retried
results carry an `x-citation-audit-rate-limit-retries` header marker. The
pacing interval, retry count, and wait budgets are configurable only within
hard caps, so configuration cannot turn waiting into an unbounded stall.
Downloaded files are never executed.
`pdftotext` is restricted to identity pages, CPU time, output bytes, a minimal
environment, and memory on platforms that support `RLIMIT_AS` (macOS records
that the memory cap is unavailable and still enforces the other bounds).

PDF/HTML/BibTeX/registry text is untrusted evidence. All textual source types
are scanned before packetization; a prompt-injection indicator blocks automatic
processing for manual quarantine. Any role that independently flags injection
also blocks consensus.

Default DNS policy is `strict`. Some managed environments resolve public hosts
to relay-only synthetic addresses. In that case, use `trusted_proxy` only with
an explicit domain allowlist:

```json
{
  "citation_audit": {
    "network": {
      "resolver_mode": "trusted_proxy",
      "allowed_domains": [
        "doi.org",
        "api.crossref.org",
        "api.semanticscholar.org",
        "publisher.example"
      ]
    }
  }
}
```

`trusted_proxy` still rejects IP literals, embedded credentials, non-HTTPS
schemes, and redirects outside the allowlist. Use it only when the execution
environment provides the trusted egress relay; it is not a general workaround
for SSRF failures.

The policy floor is not configurable away: HTTPS, all four roles, every
field-specific role, all four source families, full-source agreement, PDF
minimums, resource ceilings, and bounded agent concurrency are validated at
initialization, adjudication, and the final offline gate. Workspace settings may
further restrict domains or resources, but cannot reduce these requirements.

Offline `FixtureTransport` is available only through `collect --fixture-dir`
for tests. Fixture evidence and test agent receipts are rejected by the
production final gate even if their internal hashes are correct.

## 7. Field Conflict Policy

- Empty source values do not vote.
- At least two independent source families must agree on every field.
- Every field-specific required agent role must return the same normalized
  value. `UNVERIFIED`, `CONFLICT`, or a missing role blocks.
- Author comparison preserves order. Primary sources must supply the complete
  identity. A secondary registry's abbreviated given names are advisory-only
  when count, order, surnames, and initials align with complete primary-source
  names; they never replace the complete value. Comparison normalizes explicit
  `Family, Given` orientation and diacritic-only spelling variants, while the
  canonical display names still come from the primary source. Any incompatible
  initial, surname, count, or order blocks.
- Common venue labels such as NIPS/NeurIPS and full conference names normalize
  for comparison, while the site citation's display value is preserved.
- Preprint year, online year, and proceedings year disagreements are surfaced;
  the system does not choose one without evidence.

## 8. Human Checkpoint and Recovery

Before `apply`, inspect each correction and its evidence paths. The approval
flag plus `--proposal-sha256` means the author has accepted that exact
before/after proposal; an agent must not supply either autonomously. A stale or
different hash is rejected. Apply independently re-derives the unique complete
target bytes from the frozen source ledger, decisions, evidence, and proposal
timestamp; editing the target or proposal semantics cannot authorize deleted or
altered references. Replacement uses a PREPARED/COMMITTED recovery
journal and hashed backups for both `REFERENCES.json` and the prior summary. Any
ordinary write failure rolls both files back immediately. A process crash leaves
`apply=PREPARED`; final lint blocks until `citationctl recover` restores the
pre-apply bytes. Without `--replace-ledger`, apply leaves the preview separate
and final lint remains blocked.

For an applied correction, the final gate requires `applied=true`, the exact
proposal hash in both author approval and a `COMMITTED` journal, current ledger
and summary after-hashes, and an intact pre-apply backup. It then re-derives the
unique corrected bytes from that backup, current decisions/evidence, and the
proposal timestamp. `doctor` reports a non-blocking `WARN` when an unused
correction preview exists but is stale; an applied stale chain is blocking.

If a source is paywalled, unavailable, contradictory, or has no site citation
export, keep the item blocked. Supply a verifiable official alternative or
remove the citation. Do not mark a manually typed record as verified to bypass
the gate.

After any edit to `REFERENCES.json`, report, packet, evidence file, or decision,
run `citationctl doctor`. Hash drift invalidates the proof chain. A local
operator with unrestricted write access can still forge an entire local
workspace; defending against that actor would require externally signed,
append-only attestations and is outside this local repository's trust model.

`rebuttalctl lint` also binds reviewer-visible References blocks to the
verified ledger. Each managed block must use contiguous `[1]...[N]` numbering;
every entry must normalize exactly to one cited ledger record; duplicates,
altered fields, and extra/unmapped entries fail. The union of all blocks must
cover every `citation_ids` record. This gate runs even before `PASTE_READY.txt`
exists, and `draft` is blocked until the underlying citation audit passes.
When `citation_ids` is empty, an undeclared reviewer-visible References entry is
still rejected rather than silently bypassing verification.

## 9. Verification

```bash
python3 -m py_compile scripts/citationctl scripts/citation_audit/*.py
python3 evals/run_citation_evals.py
python3 evals/run_citation_unit_evals.py
python3 evals/run_lint_evals.py
```

The 86-case citation integration suite uses a structurally valid generated PDF
and an offline transport. It covers fake PDF/login HTML rejection, author
omission/addition/order, field/source conflict, secondary-name abbreviations
(compatible and incompatible), BibTeX ambiguity, prompt injection,
inherited-secret exclusion, missing roles, single-role policy downgrade,
duplicate identities, packet/report/symlink tampering, DOI/OpenReview identity
and authority mismatch, fake explicit authority, exact-proposal approval,
semantic target re-derivation, apply rollback, committed-journal closure,
path containment before agent spawn, fixture exclusion, stale summary/preview
detection, stage-ordering violations, unknown `--only` selection, crash
recovery through `recover`, venue-alias and diacritic end-to-end equivalence,
CLI argument surfaces, `pdftotext` extraction boundaries, and a deterministic
fake-codex binary that exercises the real parallel `run-agents` spawn path:
attestation hash binding, environment allowlisting, argv lockdown flags,
missing-session/exit/output/JSON/timeout rejections, and shared-session
blocking under production evidence. The 240-test unit/property suite
(`run_citation_unit_evals.py`) locks every parsing, normalization, policy,
identifier-binding, report-validation, URL/SSRF, redirect, and path-guard
function at the module boundary, plus seeded round-trip and hash-sensitivity
properties. The 177-case main lint suite separately locks exact References
sets — numbering, duplicates, stray bibliography lines, split-block coverage,
wrapped entries, prepared-transaction blocking — and the full
disabled/missing/typo-style × lint/draft/export citation-gate matrix.

Relevant primary API documentation:
[Crossref REST](https://www.crossref.org/documentation/retrieve-metadata/rest-api/),
[Crossref content negotiation](https://www.crossref.org/documentation/retrieve-metadata/content-negotiation/),
[arXiv API manual](https://info.arxiv.org/help/api/user-manual.html),
[Semantic Scholar Academic Graph API](https://api.semanticscholar.org/api-docs/),
and [OpenReview API v2 PDF/notes](https://docs.openreview.net/reference/api-v2/openapi-definition).
