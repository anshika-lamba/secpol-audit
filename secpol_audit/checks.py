"""Static policy & cross-file `build.ifs` wiring checks for QNX Neutrino 8.0."""

from __future__ import annotations

from collections import defaultdict
import re

from secpol_audit.ir import (
    RESERVED_TYPES,
    Finding,
    IfsIR,
    MountPointRule,
    PathAnalysisResult,
    PolicyIR,
    Severity,
)
from secpol_audit.paths import analyze_paths, collect_type_abilities, collect_type_attaches

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

INHERITABLE_PRIV_ABILITIES = frozenset(
    {
        "mem_phys",
        "io",
        "mac_policy",
        "prot_exec",
        "able_create",
        "setuid",
        "pathspace",
    }
)


def _parse_uid_gid(spec: str | None) -> tuple[int | None, int | None]:
    """Parse a QNX `on -u <uid>[:<gid>]` or `mount_point <uid>:<gid>` identity."""
    if not spec:
        return None, None
    parts = spec.strip().split(":", 1)
    uid_s = parts[0].strip()
    gid_s = parts[1].strip() if len(parts) > 1 else ""

    def _to_id(val: str) -> int | None:
        if not val:
            return None
        if val == "root":
            return 0
        if val.isdigit():
            return int(val)
        return None

    uid = _to_id(uid_s)
    gid = _to_id(gid_s) if gid_s else uid
    return uid, gid


def _octal_digit_to_rwx(digit: int) -> str:
    return (
        ("r" if digit & 4 else "")
        + ("w" if digit & 2 else "")
        + ("x" if digit & 1 else "")
    )


def _eval_mount_acl(mp: MountPointRule, client_uid: int, client_gid: int) -> str | None:
    """Return effective rwx characters for `(client_uid, client_gid)` under `mp`, or None if unparseable."""
    owner_uid, owner_gid = _parse_uid_gid(mp.owner)
    if owner_uid is None:
        return None
    if owner_gid is None:
        owner_gid = owner_uid

    perms = mp.perms.strip()
    # 1. QNX ACL block: `{ u::rwx g::rx u:25:rw o::--- }`
    # (Parser may join tokens with spaces around `:`, e.g. `{ u : : rwx g : : rx o : : rx }`)
    if perms.startswith("{") and perms.endswith("}"):
        inner = re.sub(r"\s*:\s*", ":", perms[1:-1].strip())
        u_default = ""
        g_default = ""
        o_default = ""
        u_named: dict[int, str] = {}
        g_named: dict[int, str] = {}
        for tok in inner.split():
            m = re.match(r"^([ugo]):([^:]*):([rwx-]+)$", tok)
            if not m:
                continue
            tag, ident, bits = m.group(1), m.group(2), m.group(3).replace("-", "")
            if tag == "u":
                if ident == "":
                    u_default = bits
                elif ident.isdigit():
                    u_named[int(ident)] = bits
                elif ident == "root":
                    u_named[0] = bits
            elif tag == "g":
                if ident == "":
                    g_default = bits
                elif ident.isdigit():
                    g_named[int(ident)] = bits
                elif ident == "root":
                    g_named[0] = bits
            elif tag == "o":
                o_default = bits
        if client_uid == owner_uid:
            return u_default
        if client_uid in u_named:
            return u_named[client_uid]
        if client_gid == owner_gid:
            return g_default
        if client_gid in g_named:
            return g_named[client_gid]
        return o_default

    # 2. 9-character symbolic POSIX mode: `rwxr-x---`, `r--r--r--`
    if re.fullmatch(r"[r-][w-][xsStT-][r-][w-][xsStT-][r-][w-][xtT-]", perms):
        u_bits = "".join(c for c in perms[0:3] if c in "rwx")
        g_bits = "".join(c for c in perms[3:6] if c in "rwx")
        o_bits = "".join(c for c in perms[6:9] if c in "rwx")
        if client_uid == owner_uid:
            return u_bits
        if client_gid == owner_gid:
            return g_bits
        return o_bits

    # 3. Octal POSIX mode: `0700`, `750`, `640`
    if re.fullmatch(r"0?[0-7]{3}", perms):
        digits = [int(ch) for ch in perms[-3:]]
        if client_uid == owner_uid:
            return _octal_digit_to_rwx(digits[0])
        if client_gid == owner_gid:
            return _octal_digit_to_rwx(digits[1])
        return _octal_digit_to_rwx(digits[2])

    return None


def _path_under_or_equal(target_path: str, mount_path: str) -> tuple[bool, bool]:
    """Return `(matches, is_strict_child)` for `target_path` relative to `mount_path`."""
    t = target_path.rstrip("/") or "/"
    m = mount_path.rstrip("/") or "/"
    if t == m:
        return True, False
    if m == "/":
        return True, True
    if t.startswith(m + "/"):
        return True, True
    return False, False


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
    abilities_by_type = collect_type_abilities(policy) if policy is not None else {}
    attaches_by_type = collect_type_attaches(policy) if policy is not None else {}

    # Track non-root IFS service identities per declared type for mount ACL checks
    nonroot_services_by_type: dict[str, list[tuple[int, int, str, object]]] = defaultdict(list)

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
            else:
                # 6. ROOT_SERVICE_WITHOUT_UID_DROP
                uid, gid = _parse_uid_gid(cmd.on_user)
                if uid is None or uid == 0:
                    type_specs = [spec for spec, _ in abilities_by_type.get(cmd.on_type, [])]
                    requires_root = any(
                        spec.name == "setuid"
                        and ("nonroot" not in spec.modifiers)
                        and (not spec.args or any(a == "0" or a.startswith("0-") for a in spec.args))
                        for spec in type_specs
                    )
                    if not requires_root:
                        reason_txt = (
                            "omits '-u <uid:gid>'"
                            if cmd.on_user is None
                            else f"runs as root ('-u {cmd.on_user}')"
                        )
                        findings.append(
                            Finding(
                                rule_id="ROOT_SERVICE_WITHOUT_UID_DROP",
                                severity=Severity.HIGH,
                                message=(
                                    f"Service '{cmd.executable}' (type '{cmd.on_type}') at line {cmd.span.line} "
                                    f"{reason_txt} and runs as uid=0 root unnecessarily"
                                ),
                                span=cmd.span,
                                remediation=(
                                    f"Drop root privileges by adding '-u <uid>:<gid>' (e.g., '-u 25:25') to "
                                    f"'on -T {cmd.on_type} {cmd.executable}' and ensuring required abilities use 'nonroot'."
                                ),
                                metadata={
                                    "executable": cmd.executable,
                                    "type": cmd.on_type,
                                    "on_user": cmd.on_user,
                                },
                            )
                        )
                else:
                    nonroot_services_by_type[cmd.on_type].append(
                        (uid, gid if gid is not None else uid, cmd.executable or "", cmd.span)
                    )

    # 7. NONROOT_MOUNT_ACL_MISMATCH: cross-reference non-root IFS services vs mount_point ACLs
    if policy is not None and policy.mount_point_rules and nonroot_services_by_type:
        # Collect concrete channel-connect targets per client type
        client_targets: dict[str, set[str]] = defaultdict(set)
        for crule in policy.connect_rules:
            for src in crule.sources:
                for c_src, _ in policy.expand_subject(src):
                    if c_src not in policy.types:
                        continue
                    for tgt in crule.targets:
                        expanded_tgts = (
                            [(c_src, None)]
                            if tgt == "self"
                            else policy.expand_subject(tgt, allow_default_rules=False)
                        )
                        for c_tgt, _ in expanded_tgts:
                            if c_tgt in policy.types:
                                client_targets[c_src].add(c_tgt)

        # Collect allow_link paths per concrete type
        links_by_type: dict[str, list[str]] = defaultdict(list)
        for lrule in policy.link_rules:
            for t in lrule.types:
                for c_t, _ in policy.expand_subject(t, allow_default_rules=False):
                    if c_t in policy.types:
                        links_by_type[c_t].extend(lrule.paths)

        seen_acl_findings: set[tuple[str, str, int, int]] = set()
        for mp in policy.mount_point_rules:
            for mp_path in mp.paths:
                for tname, svc_list in sorted(nonroot_services_by_type.items()):
                    # Paths this non-root type needs to access via channel connect, allow_link, or attach
                    accessed_paths: list[tuple[str, str]] = []  # (role, path)
                    for srv_t in sorted(client_targets.get(tname, set())):
                        for _ft, ap_path, _raw, _ct in attaches_by_type.get(srv_t, []):
                            matches, _ = _path_under_or_equal(ap_path, mp_path)
                            if matches:
                                accessed_paths.append(
                                    (f"channel connect to '{srv_t}' ({ap_path})", ap_path)
                                )
                    for lpath in links_by_type.get(tname, []):
                        matches, _ = _path_under_or_equal(lpath, mp_path)
                        if matches:
                            accessed_paths.append((f"allow_link ({lpath})", lpath))
                    for _ft, ap_path, _raw, _ct in attaches_by_type.get(tname, []):
                        matches, is_child = _path_under_or_equal(ap_path, mp_path)
                        if matches and is_child:
                            accessed_paths.append((f"allow_attach ({ap_path})", ap_path))

                    if not accessed_paths:
                        continue

                    for uid, gid, exe_name, cmd_span in svc_list:
                        eff = _eval_mount_acl(mp, uid, gid)
                        if eff is None:
                            continue
                        for role_desc, target_path in accessed_paths:
                            _, is_child = _path_under_or_equal(target_path, mp_path)
                            # Traversing a parent mount directory requires `x`; accessing the exact mount requires any r/w/x
                            denied = ("x" not in eff) if is_child else (eff == "")
                            if denied:
                                dedup_key = (tname, mp_path, uid, gid)
                                if dedup_key in seen_acl_findings:
                                    continue
                                seen_acl_findings.add(dedup_key)
                                need_bits = "rx" if is_child else "r"
                                findings.append(
                                    Finding(
                                        rule_id="NONROOT_MOUNT_ACL_MISMATCH",
                                        severity=Severity.MEDIUM,
                                        message=(
                                            f"Non-root service '{exe_name}' (type '{tname}', -u {uid}:{gid}) accesses "
                                            f"{role_desc} under mount_point '{mp_path}' ({mp.owner} {mp.perms}), "
                                            f"which grants effective '{eff or '---'}' — statically predicted silent EACCES"
                                        ),
                                        span=mp.span,
                                        remediation=(
                                            f"Grant uid {uid}:gid {gid} access on '{mp_path}', e.g. "
                                            f"'mount_point {mp.owner} {{ u::rwx g::rx u:{uid}:{need_bits} o::--- }} {mp_path};' "
                                            f"or align the service gid with {mp.owner}."
                                        ),
                                        metadata={
                                            "executable": exe_name,
                                            "type": tname,
                                            "uid": uid,
                                            "gid": gid,
                                            "mount_path": mp_path,
                                            "mount_owner": mp.owner,
                                            "mount_perms": mp.perms,
                                            "effective_perms": eff or "---",
                                            "target_path": target_path,
                                            "ifs_location": cmd_span.format_loc(),
                                        },
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

    # Check CHILD_ABILITY_INHERITANCE_LEAK: privileged type that can spawn children
    # (`settypeid` or `spawn`) without `noinherit` or `default_spawn_type`
    types_with_default_spawn: set[str] = set()
    for srule in policy.default_spawn_rules:
        for concrete_src, _ in policy.expand_subject(srule.src_type, allow_default_rules=False):
            types_with_default_spawn.add(concrete_src)

    abilities_by_type = collect_type_abilities(policy)
    for tname in sorted(policy.types):
        if tname in types_with_default_spawn:
            continue
        specs = [spec for spec, _ in abilities_by_type.get(tname, [])]
        can_spawn = any(spec.name in ("settypeid", "spawn") for spec in specs)
        if not can_spawn:
            continue
        leaked_specs = [
            spec
            for spec in specs
            if spec.name in INHERITABLE_PRIV_ABILITIES and "noinherit" not in spec.modifiers
        ]
        if leaked_specs:
            leaked_names = sorted({spec.canonical() for spec in leaked_specs})
            findings.append(
                Finding(
                    rule_id="CHILD_ABILITY_INHERITANCE_LEAK",
                    severity=Severity.HIGH,
                    message=(
                        f"Privileged type '{tname}' can spawn children without 'default_spawn_type' and "
                        f"lacks 'noinherit' on privileged ability(ies): {', '.join(leaked_names)}"
                    ),
                    span=leaked_specs[0].span,
                    remediation=(
                        f"Mark privileged abilities on '{tname}' with 'noinherit' (e.g., 'noinherit {leaked_specs[0].name}') "
                        f"or declare 'default_spawn_type {tname} <restricted_child_t>;' so spawned children do not inherit them."
                    ),
                    metadata={
                        "type": tname,
                        "leaked_abilities": leaked_names,
                    },
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
