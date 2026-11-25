"""Static policy & cross-file `build.ifs` wiring checks for QNX Neutrino 8.0."""

from __future__ import annotations

from collections import defaultdict

from secpol_audit.ir import (
    RESERVED_TYPES,
    Finding,
    IfsIR,
    PathAnalysisResult,
    PolicyIR,
    Severity,
)
from secpol_audit.paths import analyze_paths, collect_type_attaches

UNLOCK_PRIVILEGED_ABILITIES = frozenset(
    {
        "mem_phys",
        "prot_exec",
        "mac_policy",
        "pathspace",
        "setuid",
        "io",
        "gain_priv",
    }
)


def run_ifs_checks(ifs: IfsIR, policy: PolicyIR | None = None) -> list[Finding]:
    """Run QNX 8.0 `build.ifs` startup-script security wiring checks."""
    findings: list[Finding] = []

    if not ifs.has_startup_script:
        return findings

    has_typed_launch = any(cmd.on_type is not None for cmd in ifs.commands)
    has_service_launch = any(not cmd.is_builtin for cmd in ifs.commands)

    # 1. MISSING_SECPOLPUSH
    if not ifs.secpolpush_lines and (policy is not None or has_typed_launch or has_service_launch):
        first_span = ifs.commands[0].span if ifs.commands else None
        findings.append(
            Finding(
                rule_id="MISSING_SECPOLPUSH",
                severity=Severity.CRITICAL,
                message=(
                    f"IFS startup-script '{ifs.source_path}' launches services without invoking "
                    "'secpolpush' to load the QNX security policy"
                ),
                span=first_span,
                remediation="Add 'secpolpush' near the top of startup-script before launching any daemons.",
            )
        )

    # 2. DUPLICATE_SECPOLPUSH
    if len(ifs.secpolpush_lines) > 1:
        push_cmds = [c for c in ifs.commands if c.is_secpolpush]
        for extra_cmd in push_cmds[1:]:
            findings.append(
                Finding(
                    rule_id="DUPLICATE_SECPOLPUSH",
                    severity=Severity.WARNING,
                    message=(
                        f"Duplicate 'secpolpush' invocation at line {extra_cmd.span.line} "
                        f"(first invoked at line {ifs.secpolpush_lines[0]})"
                    ),
                    span=extra_cmd.span,
                    remediation="Invoke 'secpolpush' exactly once during early boot before daemon startup.",
                    metadata={"first_line": ifs.secpolpush_lines[0], "duplicate_line": extra_cmd.span.line},
                )
            )

    first_push_line = ifs.first_secpolpush_line

    for cmd in ifs.commands:
        if cmd.is_secpolpush or cmd.is_builtin:
            continue

        # 3. PRE_SECPOLPUSH_LAUNCH
        if first_push_line is not None and cmd.span.line < first_push_line:
            findings.append(
                Finding(
                    rule_id="PRE_SECPOLPUSH_LAUNCH",
                    severity=Severity.HIGH,
                    message=(
                        f"Service '{cmd.executable}' launched at line {cmd.span.line} BEFORE "
                        f"'secpolpush' (line {first_push_line}); it will run unconfined without security policy enforcement"
                    ),
                    span=cmd.span,
                    remediation=(
                        f"Move '{cmd.executable}' after 'secpolpush' (line {first_push_line}) and launch it via 'on -T <type>'."
                    ),
                    metadata={"executable": cmd.executable, "secpolpush_line": first_push_line},
                )
            )
        else:
            # 4. UNTYPED_IFS_SERVICE (launched after secpolpush, or when secpolpush is missing, without on -T)
            if cmd.on_type is None:
                findings.append(
                    Finding(
                        rule_id="UNTYPED_IFS_SERVICE",
                        severity=Severity.HIGH,
                        message=(
                            f"Service '{cmd.executable}' launched without 'on -T <type>' at line {cmd.span.line}; "
                            "process inherits unconfined boot/root type"
                        ),
                        span=cmd.span,
                        remediation=f"Launch '{cmd.executable}' with 'on -T <declared_type> {cmd.executable}'.",
                        metadata={"executable": cmd.executable},
                    )
                )

        # 5. UNDEFINED_IFS_TYPE
        if cmd.on_type is not None and policy is not None:
            if cmd.on_type not in policy.types:
                extra = (
                    " (note: this identifier is declared as an attribute, not a concrete type)"
                    if cmd.on_type in policy.attributes
                    else ""
                )
                findings.append(
                    Finding(
                        rule_id="UNDEFINED_IFS_TYPE",
                        severity=Severity.ERROR,
                        message=(
                            f"IFS command launches '{cmd.executable}' with undefined security type "
                            f"'-T {cmd.on_type}' (not declared in '{policy.source_path}'){extra}"
                        ),
                        span=cmd.span,
                        remediation=(
                            f"Fix the '-T {cmd.on_type}' typo or declare 'type {cmd.on_type};' in '{policy.source_path}'."
                        ),
                        metadata={"executable": cmd.executable, "type": cmd.on_type},
                    )
                )

    return findings


def run_policy_checks(policy: PolicyIR) -> list[Finding]:
    """Run QNX 8.0 `.secpol` static consistency and security checks."""
    findings: list[Finding] = []

    # Check undeclared attributes on `type foo, attr;`
    for tname, tdecl in sorted(policy.types.items()):
        for attr in tdecl.attributes:
            if attr not in policy.attributes:
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"Type '{tname}' references undeclared attribute '{attr}'",
                        span=tdecl.span,
                        remediation=f"Declare 'attribute {attr};' before using it on type '{tname}'.",
                        metadata={"type": tname, "attribute": attr},
                    )
                )

    # Collect which types/channel_types have allow_attach
    attaches_by_type = collect_type_attaches(policy)
    channel_types_attached: set[str] = set()
    for arule in policy.attach_rules:
        if arule.channel_type:
            channel_types_attached.add(arule.channel_type)

    # Check attach rules: undeclared type refs + WILDCARD_FTYPE_ATTACH
    for arule in policy.attach_rules:
        for t in arule.types:
            if not policy.is_declared_identifier(t):
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"allow_attach references undeclared type or attribute '{t}'",
                        span=arule.span,
                        remediation=f"Declare 'type {t};' or fix the typo in allow_attach.",
                        metadata={"identifier": t},
                    )
                )
        if arule.channel_type and not policy.is_declared_identifier(arule.channel_type):
            findings.append(
                Finding(
                    rule_id="UNDECLARED_TYPE_REFERENCE",
                    severity=Severity.ERROR,
                    message=f"allow_attach channel type override '{arule.channel_type}' is undeclared",
                    span=arule.span,
                    remediation=f"Declare 'type {arule.channel_type};' or fix the channel_type in allow_attach.",
                    metadata={"identifier": arule.channel_type},
                )
            )
        for ap in arule.paths:
            if ap.ftype == "*":
                findings.append(
                    Finding(
                        rule_id="WILDCARD_FTYPE_ATTACH",
                        severity=Severity.MEDIUM,
                        message=(
                            f"allow_attach for '{', '.join(arule.types)}' uses wildcard file-type prefix "
                            f"'*' on '{ap.raw}'"
                        ),
                        span=arule.span,
                        remediation=(
                            "Replace wildcard '*' file-type prefix with an explicit QNX file type "
                            "(e.g., 'mount:', 'mount+:', or an unqualified device path)."
                        ),
                        metadata={"types": list(arule.types), "path": ap.raw},
                    )
                )

    # Check allow_link undeclared references
    for lrule in policy.link_rules:
        for t in lrule.types:
            if not policy.is_declared_identifier(t):
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"allow_link references undeclared type or attribute '{t}'",
                        span=lrule.span,
                        remediation=f"Declare 'type {t};' or fix the typo in allow_link.",
                        metadata={"identifier": t},
                    )
                )

    # Check derive_type & default_spawn_type undeclared references
    for drule in policy.derive_rules:
        for role, ident in (("source", drule.src_type), ("destination", drule.dst_type)):
            if not policy.is_declared_identifier(ident):
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"derive_type references undeclared {role} type '{ident}'",
                        span=drule.span,
                        remediation=f"Declare 'type {ident};' or remove the invalid derive_type rule.",
                        metadata={"identifier": ident, "role": role},
                    )
                )

    for srule in policy.default_spawn_rules:
        for role, ident in (("source", srule.src_type), ("destination", srule.dst_type)):
            if not policy.is_declared_identifier(ident):
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"default_spawn_type references undeclared {role} type '{ident}'",
                        span=srule.span,
                        remediation=f"Declare 'type {ident};' or remove the invalid default_spawn_type rule.",
                        metadata={"identifier": ident, "role": role},
                    )
                )

    # Track all connected targets (expanded to concrete types) for UNREACHABLE_ATTACHED_SERVER
    connected_concrete_targets: set[str] = set()

    def _target_has_attach(target_ident: str) -> bool:
        if target_ident in RESERVED_TYPES:
            return True
        if target_ident in channel_types_attached:
            return True
        if target_ident in policy.types:
            return len(attaches_by_type.get(target_ident, [])) > 0
        if target_ident in policy.attributes:
            members = policy.types_for_attribute(target_ident)
            return any(len(attaches_by_type.get(m, [])) > 0 or m in channel_types_attached for m in members)
        return False

    # Check ability rules: undeclared refs, UNLOCKED_PRIVILEGED_ABILITY, DANGLING_SETTYPEID_TARGET, channel_connect targets
    for arule in policy.ability_rules:
        for src in arule.sources:
            if not policy.is_declared_identifier(src):
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"allow ability rule references undeclared source '{src}'",
                        span=arule.span,
                        remediation=f"Declare 'type {src};' or 'attribute {src};' before referencing it.",
                        metadata={"identifier": src},
                    )
                )
        for tgt in arule.targets:
            if not policy.is_declared_identifier(tgt):
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"allow ability rule references undeclared target '{tgt}'",
                        span=arule.span,
                        remediation=f"Use 'self' or declare '{tgt}' before referencing it.",
                        metadata={"identifier": tgt},
                    )
                )

        for spec in arule.abilities:
            if spec.has_unlock and spec.name in UNLOCK_PRIVILEGED_ABILITIES:
                findings.append(
                    Finding(
                        rule_id="UNLOCKED_PRIVILEGED_ABILITY",
                        severity=Severity.HIGH,
                        message=(
                            f"Privileged ability '{spec.canonical()}' granted to '{', '.join(arule.sources)}' "
                            "is marked unlock/unlocked, allowing runtime ability modification"
                        ),
                        span=spec.span,
                        remediation=(
                            f"Remove the 'unlock'/'unlocked' modifier from '{spec.name}' so the ability remains locked."
                        ),
                        metadata={"sources": list(arule.sources), "ability": spec.canonical()},
                    )
                )

            if spec.name == "settypeid":
                for target in spec.args:
                    if target not in policy.types and target not in policy.attributes:
                        findings.append(
                            Finding(
                                rule_id="DANGLING_SETTYPEID_TARGET",
                                severity=Severity.ERROR,
                                message=(
                                    f"Ability 'settypeid:{target}' on '{', '.join(arule.sources)}' "
                                    f"references undeclared target type '{target}'"
                                ),
                                span=spec.span,
                                remediation=f"Fix the typo in 'settypeid:{target}' or declare 'type {target};'.",
                                metadata={"sources": list(arule.sources), "target": target},
                            )
                        )

            if spec.name == "channel_connect":
                for target in spec.args:
                    if not policy.is_declared_identifier(target):
                        findings.append(
                            Finding(
                                rule_id="DANGLING_CONNECT_TARGET",
                                severity=Severity.ERROR,
                                message=(
                                    f"Ability 'channel_connect:{target}' on '{', '.join(arule.sources)}' "
                                    f"references undeclared target '{target}'"
                                ),
                                span=spec.span,
                                remediation=f"Fix the typo in 'channel_connect:{target}' or declare 'type {target};'.",
                                metadata={"sources": list(arule.sources), "target": target},
                            )
                        )
                    else:
                        if target != "self" and not _target_has_attach(target):
                            findings.append(
                                Finding(
                                    rule_id="DANGLING_CONNECT_TARGET",
                                    severity=Severity.WARNING,
                                    message=(
                                        f"Ability 'channel_connect:{target}' targets declared type '{target}' "
                                        "which has no matching 'allow_attach' rule"
                                    ),
                                    span=spec.span,
                                    remediation=(
                                        f"Add an 'allow_attach {target} /dev/...;' rule or remove the stale connect rule."
                                    ),
                                    metadata={"sources": list(arule.sources), "target": target},
                                )
                            )
                        for concrete_t, _ in policy.expand_subject(target, allow_default_rules=False):
                            connected_concrete_targets.add(concrete_t)

    # Check custom class allow rules for undeclared sources/targets
    for clrule in policy.class_rules:
        for role, idents in (("source", clrule.sources), ("target", clrule.targets)):
            for ident in idents:
                if not policy.is_declared_identifier(ident):
                    findings.append(
                        Finding(
                            rule_id="UNDECLARED_TYPE_REFERENCE",
                            severity=Severity.ERROR,
                            message=(
                                f"allow '{clrule.class_name}' rule references undeclared {role} '{ident}'"
                            ),
                            span=clrule.span,
                            remediation=f"Declare 'type {ident};' or 'attribute {ident};' before referencing it.",
                            metadata={"identifier": ident, "class": clrule.class_name, "role": role},
                        )
                    )

    # Check channel connect rules
    for crule in policy.connect_rules:
        for src in crule.sources:
            if not policy.is_declared_identifier(src):
                findings.append(
                    Finding(
                        rule_id="UNDECLARED_TYPE_REFERENCE",
                        severity=Severity.ERROR,
                        message=f"channel connect rule references undeclared source '{src}'",
                        span=crule.span,
                        remediation=f"Declare 'type {src};' or 'attribute {src};' before referencing it.",
                        metadata={"identifier": src},
                    )
                )
        for tgt in crule.targets:
            if not policy.is_declared_identifier(tgt):
                findings.append(
                    Finding(
                        rule_id="DANGLING_CONNECT_TARGET",
                        severity=Severity.ERROR,
                        message=(
                            f"channel connect rule from '{', '.join(crule.sources)}' references "
                            f"undeclared target '{tgt}'"
                        ),
                        span=crule.span,
                        remediation=f"Fix the typo in target '{tgt}' or declare 'type {tgt};'.",
                        metadata={"sources": list(crule.sources), "target": tgt},
                    )
                )
            else:
                if tgt not in RESERVED_TYPES and not _target_has_attach(tgt):
                    findings.append(
                        Finding(
                            rule_id="DANGLING_CONNECT_TARGET",
                            severity=Severity.WARNING,
                            message=(
                                f"channel connect rule from '{', '.join(crule.sources)}' targets '{tgt}', "
                                "which has no matching 'allow_attach' rule"
                            ),
                            span=crule.span,
                            remediation=f"Add an 'allow_attach {tgt} /dev/...;' rule or remove the unused connect rule.",
                            metadata={"sources": list(crule.sources), "target": tgt},
                        )
                    )
                for concrete_t, _ in policy.expand_subject(tgt, allow_default_rules=False):
                    connected_concrete_targets.add(concrete_t)

    # Check UNREACHABLE_ATTACHED_SERVER: type attaches `/dev/*` but zero types have `channel connect` to it
    attached_dev_by_type: dict[str, list[tuple[str, str | None]]] = defaultdict(list)
    for tname, attaches in attaches_by_type.items():
        for _ftype, path, raw, chan_type in attaches:
            if path.startswith("/dev/"):
                attached_dev_by_type[tname].append((raw, chan_type))

    for tname, dev_list in sorted(attached_dev_by_type.items()):
        reachable = tname in connected_concrete_targets
        if not reachable:
            for _raw, chan_type in dev_list:
                if chan_type and chan_type in connected_concrete_targets:
                    reachable = True
                    break
        if not reachable:
            paths_str = ", ".join(r for r, _ in dev_list)
            # Locate the attach rule span for this type if possible
            span = policy.types[tname].span if tname in policy.types else None
            for arule in policy.attach_rules:
                expanded = {
                    ct for t in arule.types for ct, _ in policy.expand_subject(t, allow_default_rules=False)
                }
                if tname in expanded and any(ap.path.startswith("/dev/") for ap in arule.paths):
                    span = arule.span
                    break
            findings.append(
                Finding(
                    rule_id="UNREACHABLE_ATTACHED_SERVER",
                    severity=Severity.INFO,
                    message=(
                        f"Type '{tname}' attaches device path(s) ({paths_str}) but zero types have "
                        f"'channel connect' permission to '{tname}'"
                    ),
                    span=span,
                    remediation=(
                        f"Verify whether '{tname}' should accept clients via 'allow <client> {tname} : channel connect;' "
                        "or if this attach rule is stale."
                    ),
                    metadata={"type": tname, "paths": [r for r, _ in dev_list]},
                )
            )

    return findings


def run_all_checks(
    policy: PolicyIR,
    *,
    ifs: IfsIR | None = None,
    include_paths: bool = True,
) -> tuple[list[Finding], PathAnalysisResult]:
    """Run all static policy checks, optional IFS wiring checks, and escalation path analysis."""
    findings: list[Finding] = []
    findings.extend(run_policy_checks(policy))
    if ifs is not None:
        findings.extend(run_ifs_checks(ifs, policy))

    path_result = analyze_paths(policy, ifs=ifs)
    if include_paths:
        findings.extend(path_result.findings)

    findings.sort(
        key=lambda f: (
            f.severity.rank,
            f.span.file if f.span else "",
            f.span.line if f.span else 0,
            f.rule_id,
            f.message,
        )
    )
    return findings, path_result
