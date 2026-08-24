"""Command-line interface for the citation audit state machine."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

from .pipeline import (
    AuditError,
    apply_corrections,
    audit_status,
    collect_all,
    decide_all,
    init_audit,
    load_manifest,
    load_verified_packet,
    packetize_all,
    propose_corrections,
    recover_apply,
    record_report,
    validate_audit_summary,
)
from .runner import run_agents


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def cmd_init(args) -> int:
    manifest = init_audit(args.workspace, bib_path=args.bib, new_batch=args.new_batch)
    print(f"[citation:init] batch {manifest['batch_id']} initialized with {len(manifest['references'])} reference(s)")
    print("  next: citationctl collect <workspace>")
    return 0


def cmd_collect(args) -> int:
    results = collect_all(args.workspace, fixture_dir=args.fixture_dir, overwrite=args.overwrite, only=args.only)
    blocked = [item["reference_id"] for item in results if item.get("status") != "READY"]
    for item in results:
        print(f"  {item['reference_id']}: {item['status']} ({len(item.get('artifacts') or [])} artifacts, {len(item.get('errors') or [])} errors)")
        for error in item.get("errors") or []:
            print("    BLOCK", error)
    print(f"[citation:collect] {len(results) - len(blocked)}/{len(results)} reference(s) evidence-ready")
    if blocked:
        print("  blocked:", ", ".join(blocked))
        return 1
    print("  next: citationctl packetize <workspace>")
    return 0


def cmd_packetize(args) -> int:
    paths = packetize_all(args.workspace, overwrite=args.overwrite, only=args.only)
    print(f"[citation:packetize] wrote {len(paths)} isolated packet(s)")
    for path in paths:
        print(" ", os.path.relpath(path, args.workspace))
    print("  next: citationctl run-agents <workspace>")
    print("  note: record-report is diagnostic only and cannot satisfy the production gate")
    return 0


def _selected_packet_paths(workspace: str, only: list[str]) -> list[str]:
    manifest = load_manifest(workspace)
    selected = set(only or [])
    paths = []
    for item in manifest.get("references") or []:
        if selected and item["reference_id"] not in selected:
            continue
        for role in sorted((item.get("packets") or {})):
            path, _, _ = load_verified_packet(
                workspace,
                item["reference_id"],
                role,
                manifest=manifest,
            )
            paths.append(path)
    if not paths:
        raise AuditError("no packets selected")
    return paths


def cmd_run_agents(args) -> int:
    paths = _selected_packet_paths(args.workspace, args.only)
    reports = run_agents(args.workspace, paths, overwrite_roles=args.overwrite_roles)
    print(f"[citation:run-agents] recorded {len(reports)} independent report(s)")
    for report in reports:
        print(f"  {report['reference_id']}/{report['role']}: {report['agent_id']}")
    print("  next: citationctl consensus <workspace>")
    return 0


def cmd_record_report(args) -> int:
    path = record_report(args.workspace, args.packet, args.body, args.agent_id, overwrite_role=args.overwrite_role)
    print(f"[citation:record-report] wrote {path}")
    return 0


def cmd_consensus(args) -> int:
    decisions = decide_all(args.workspace, overwrite=args.overwrite, only=args.only)
    blocked = [item["reference_id"] for item in decisions if item.get("status") == "BLOCKED"]
    corrections = [item["reference_id"] for item in decisions if item.get("status") == "CORRECTION_REQUIRED"]
    for item in decisions:
        print(f"  {item['reference_id']}: {item['status']} ({len(item.get('discrepancies') or [])} discrepancies, {len(item.get('blocking_errors') or [])} blockers)")
    print(f"[citation:consensus] {len(decisions) - len(blocked)}/{len(decisions)} adjudicated without blockers")
    if blocked:
        print("  blocked:", ", ".join(blocked))
        return 1
    if corrections:
        print("  correction required:", ", ".join(corrections))
    print("  next: citationctl propose <workspace>")
    return 0


def cmd_propose(args) -> int:
    proposal = propose_corrections(args.workspace, overwrite=args.overwrite)
    changed = [item for item in proposal["corrections"] if item["changed_fields"]]
    print(f"[citation:propose] {len(changed)} reference(s) need correction; source ledger was not modified")
    print(f"  review {os.path.join(args.workspace, 'CITATION_CORRECTIONS.json')}")
    proposal_path = os.path.join(args.workspace, "CITATION_CORRECTIONS.json")
    with open(proposal_path, "rb") as handle:
        proposal_hash = hashlib.sha256(handle.read()).hexdigest()
    print(f"  proposal sha256: {proposal_hash}")
    if changed:
        print(
            "  next: citationctl apply <workspace> --author-approved --replace-ledger "
            f"--proposal-sha256 {proposal_hash}"
        )
    else:
        print("  no ledger change needs approval; next: citationctl doctor <workspace>")
    return 0


def cmd_apply(args) -> int:
    summary = apply_corrections(
        args.workspace,
        author_approved=args.author_approved,
        replace_ledger=args.replace_ledger,
        proposal_sha256=args.proposal_sha256,
    )
    print(f"[citation:apply] summary status={summary['status']} applied={summary['applied']}")
    if not args.replace_ledger:
        print("  preview remains separate; final lint stays blocked until --replace-ledger is explicitly approved")
        return 1 if summary.get("status") != "PASS" else 0
    print("  REFERENCES.json updated with a timestamped backup; run citationctl doctor and rebuttalctl lint")
    return 0 if summary.get("status") == "PASS" else 1


def cmd_recover(args) -> int:
    journal = recover_apply(args.workspace)
    print(f"[citation:recover] transaction status={journal['status']}; original ledger and summary restored")
    print("  next: citationctl doctor <workspace>")
    return 0


def cmd_doctor(args) -> int:
    status = audit_status(args.workspace)
    gate_errors = validate_audit_summary(args.workspace) if status.get("summary_status") != "MISSING" else ["summary is missing"]
    if args.json:
        _print_json({**status, "gate_errors": gate_errors})
    else:
        print(
            f"[citation:doctor] batch={status.get('batch_id') or 'none'} "
            f"manifest={status['manifest_status']} summary={status['summary_status']} "
            f"apply={status['apply_transaction_status']}"
        )
        for item in status["references"]:
            print(f"  {item['reference_id']}: evidence={item['evidence_status']} reports={item['reports']} roles={','.join(item['roles']) or '-'} decision={item['decision_status']}")
        for warning in status.get("warnings") or []:
            print("  WARN", warning)
        for error in gate_errors:
            print("  BLOCK", error)
        print("[citation:doctor] verdict:", "HEALTHY" if not gate_errors else "NEEDS ATTENTION")
    return 0 if not gate_errors else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="citationctl", description="Evidence-first, independent-agent citation verification")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init"); init.add_argument("workspace"); init.add_argument("--bib"); init.add_argument("--new-batch", action="store_true"); init.set_defaults(func=cmd_init)
    collect = sub.add_parser("collect"); collect.add_argument("workspace"); collect.add_argument("--fixture-dir"); collect.add_argument("--overwrite", action="store_true"); collect.add_argument("--only", action="append", default=[]); collect.set_defaults(func=cmd_collect)
    packetize = sub.add_parser("packetize"); packetize.add_argument("workspace"); packetize.add_argument("--overwrite", action="store_true"); packetize.add_argument("--only", action="append", default=[]); packetize.set_defaults(func=cmd_packetize)
    agents = sub.add_parser("run-agents"); agents.add_argument("workspace"); agents.add_argument("--only", action="append", default=[]); agents.add_argument("--overwrite-roles", action="store_true"); agents.set_defaults(func=cmd_run_agents)
    record = sub.add_parser("record-report"); record.add_argument("workspace"); record.add_argument("--packet", required=True); record.add_argument("--body", required=True); record.add_argument("--agent-id", required=True); record.add_argument("--overwrite-role", action="store_true"); record.set_defaults(func=cmd_record_report)
    consensus = sub.add_parser("consensus"); consensus.add_argument("workspace"); consensus.add_argument("--overwrite", action="store_true"); consensus.add_argument("--only", action="append", default=[]); consensus.set_defaults(func=cmd_consensus)
    propose = sub.add_parser("propose"); propose.add_argument("workspace"); propose.add_argument("--overwrite", action="store_true"); propose.set_defaults(func=cmd_propose)
    apply = sub.add_parser("apply"); apply.add_argument("workspace"); apply.add_argument("--author-approved", action="store_true"); apply.add_argument("--replace-ledger", action="store_true"); apply.add_argument("--proposal-sha256"); apply.set_defaults(func=cmd_apply)
    recover = sub.add_parser("recover"); recover.add_argument("workspace"); recover.set_defaults(func=cmd_recover)
    doctor = sub.add_parser("doctor"); doctor.add_argument("workspace"); doctor.add_argument("--json", action="store_true"); doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    args.workspace = os.path.abspath(args.workspace)
    try:
        return int(args.func(args) or 0)
    except (AuditError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[citation:{args.command}] ERROR: {exc}", file=sys.stderr)
        return 2
