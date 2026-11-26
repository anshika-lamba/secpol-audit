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
    "KERNEL_TRACE_ESCALATION_OBSERVED": (
        "Transitive privilege escalation chain confirmed by live QNX libsecpolev kernel trace",
        "Observed QNX Neutrino 8.0 libsecpolev microkernel security events confirmed that settypeid "
        "transition hops in a static escalation chain actually succeeded at runtime.",
    ),
    "SECPOLEV_DROPPED_EVENTS": (
        "QNX libsecpolev kernel telemetry dropped security events",
        "secpolev_get_dropped_count() reported non-zero dropped events, indicating incomplete trace coverage.",
    ),
    "UNEXPECTED_RUNTIME_DENIAL": (
        "Declared service denied a capability permitted by static policy",
        "libsecpolev recorded a DENIED verdict on a declared service type for an ability, attach path, "
        "or custom permission that is explicitly granted in the audited .secpol policy.",
    ),
    "CHILD_ABILITY_INHERITANCE_LEAK": (
        "Privileged type leaks inheritable abilities to spawned child processes",
        "A privileged QNX type holding mem_phys, io, mac_policy, prot_exec, able_create, setuid, or "
        "pathspace can spawn children without marking those abilities `noinherit` or setting `default_spawn_type`.",
    ),
    "ROOT_SERVICE_WITHOUT_UID_DROP": (
        "IFS service runs as uid=0 root unnecessarily",
        "A typed `on -T <type>` service launch in build.ifs omits `-u <uid:gid>` or explicitly runs as uid=0.",
    ),
    "NONROOT_MOUNT_ACL_MISMATCH": (
        "Non-root IFS service blocked by mount_point ACL (predicted silent EACCES)",
        "Cross-referencing a non-root `on -T <type> -u <uid:gid>` service against `mount_point` permissions "
        "and its `allow_attach`/`channel connect`/`allow_link` targets shows the service lacks required access bits.",
    ),
    "HIGH_PRIV_UNHARDENED_ELF": (
        "Privileged QNX service binary missing ELF64 hardening mitigations",
        "An ELF64 binary launched under a privileged QNX security type lacks PIE (ET_DYN), "
        "non-executable stack (PT_GNU_STACK without PF_X), or RELRO (PT_GNU_RELRO).",
    ),
    "UNREACHABLE_TRANSITION_API": (
        "Binary imports libsecpol transition APIs without matching policy settypeid grants",
        "An ELF64 binary dynamically references secpol_transition_type or secpol_posix_spawnattr_settypeid, "
        "but its bound QNX security type has no settypeid transition permissions.",
    ),
    "UNUSED_SETTYPEID_SURFACE": (
        "Policy grants settypeid to a type whose binary never imports transition APIs",
        "The .secpol policy grants settypeid transition capability to a type, but its ELF64 binary does not "
        "link libsecpol or import secpol_transition_type/secpol_posix_spawnattr_settypeid (dead attack surface).",
    ),
    "MUTABLE_COMPILED_POLICY": (
        "Compiled secpol binary reports mutable policy state (secpolcompile -m)",
        "secpolinfo output indicates a mutable compiled policy, which should be disabled in production builds.",
    ),
    "ZERO_POLICY_ID": (
        "Compiled secpol binary has zero policy ID",
        "secpolinfo reports policy ID 0, indicating unversioned/untracked compiled security policy artifacts.",
    ),
    "POLICY_SOURCE_DRIFT": (
        "Source .secpol does not match compiled secpol binary metadata",
        "Compiled policy binary or secpolinfo metadata diverges from the audited source .secpol file.",
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
