"""SARIF 2.1.0 serializer for CI and GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from secpol_audit import __version__
from secpol_audit.ir import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

RULE_DESCRIPTIONS: dict[str, tuple[str, str]] = {
    "ESCALATION_CHAIN": (
        "Transitive privilege escalation chain across settypeid/transition edges",
        "A lower-privilege QNX security type can transition transitively via settypeid, derive_type, "
        "or default_spawn_type to a high-privilege sink.",
    ),
    "PRE_SECPOLPUSH_LAUNCH": (
        "Service launched before secpolpush in build.ifs",
        "Daemons started before secpolpush run unconfined without QNX security policy enforcement.",
    ),
    "MISSING_SECPOLPUSH": (
        "Missing secpolpush invocation in build.ifs startup-script",
        "The IFS startup script launches services without invoking secpolpush to load the policy.",
    ),
    "DUPLICATE_SECPOLPUSH": (
        "Duplicate secpolpush invocation in build.ifs",
        "secpolpush is invoked more than once in the startup script.",
    ),
    "UNTYPED_IFS_SERVICE": (
        "Service launched without on -T <type> in build.ifs",
        "A daemon started after secpolpush without `on -T <type>` runs unconfined.",
    ),
    "UNDEFINED_IFS_TYPE": (
        "IFS on -T references an undeclared security type",
        "The security type passed to `on -T` in build.ifs is not declared in the .secpol policy.",
    ),
    "UNLOCKED_PRIVILEGED_ABILITY": (
        "Privileged QNX ability marked unlock/unlocked",
        "Marking a privileged ability as unlock/unlocked permits runtime modification of the ability.",
    ),
    "WILDCARD_FTYPE_ATTACH": (
        "Wildcard file-type prefix '*' in allow_attach",
        "Using '*' as a file-type prefix in allow_attach broadens attachment permissions unnecessarily.",
    ),
    "UNREACHABLE_ATTACHED_SERVER": (
        "Attached /dev/* server has no permitted channel connect clients",
        "A type attaches a /dev/* path, but no other type has channel connect permission to reach it.",
    ),
    "DANGLING_CONNECT_TARGET": (
        "channel connect target is undeclared or lacks allow_attach",
        "A channel connect rule points to a type that is undeclared or never attaches a path.",
    ),
    "DANGLING_SETTYPEID_TARGET": (
        "settypeid references an undeclared target type",
        "A settypeid ability references a security type not declared in the policy.",
    ),
    "UNDECLARED_TYPE_REFERENCE": (
        "Rule references an undeclared type or attribute",
        "A policy rule references a type or attribute that was never declared.",
    ),
    "DANGLING_DERIVE_TYPE": (
        "derive_type lacks matching settypeid permission",
        "A derive_type rule exists without a corresponding settypeid ability on the source type.",
    ),
    "RUNTIME_UNTYPED_PROCESS": (
        "Runtime process executing without a QNX security type",
        "Observed pidin -f a_n snapshot shows a userland process running untyped.",
    ),
    "RUNTIME_TYPE_MISMATCH": (
        "Runtime process type differs from build.ifs on -T binding",
        "Observed runtime security type does not match the static build.ifs launch configuration.",
    ),
    "RUNTIME_UNDECLARED_TYPE": (
        "Runtime process running under a type undeclared in .secpol",
        "Observed runtime security type does not exist in the audited .secpol source policy.",
    ),
    "RUNTIME_MISSING_SERVICE": (
        "Expected build.ifs service not observed in runtime snapshot",
        "A service configured in build.ifs did not appear in the pidin -f a_n process snapshot.",
    ),
}


def findings_to_sarif(
    findings: list[Finding],
    *,
    default_uri: str = "",
) -> dict[str, Any]:
    """Build a valid SARIF 2.1.0 dictionary from a list of `Finding` objects."""
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rid = finding.rule_id
        if rid not in rules_seen:
            short_desc, full_desc = RULE_DESCRIPTIONS.get(
                rid,
                (rid, finding.remediation or finding.message),
            )
            rules_seen[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": short_desc},
                "fullDescription": {"text": full_desc},
                "defaultConfiguration": {"level": finding.severity.sarif_level},
            }

        uri = finding.span.file if finding.span else (default_uri or "unknown")
        start_line = max(1, finding.span.line) if finding.span else 1
        start_col = max(1, finding.span.col) if finding.span else 1

        region: dict[str, Any] = {
            "startLine": start_line,
            "startColumn": start_col,
        }
        if finding.span and finding.span.end_line and finding.span.end_line >= start_line:
            region["endLine"] = finding.span.end_line
        if finding.span and finding.span.snippet:
            region["snippet"] = {"text": finding.span.snippet}

        result_obj: dict[str, Any] = {
            "ruleId": rid,
            "level": finding.severity.sarif_level,
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": region,
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "remediation": finding.remediation,
            },
        }
        results.append(result_obj)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secpol-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/anshika-lamba/secpol-audit",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def findings_to_sarif_json(findings: list[Finding], *, default_uri: str = "") -> str:
    """Serialize findings into pretty-printed SARIF 2.1.0 JSON."""
    return json.dumps(findings_to_sarif(findings, default_uri=default_uri), indent=2)
