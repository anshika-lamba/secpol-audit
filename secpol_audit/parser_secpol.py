"""Scoped, deterministic, fail-closed QNX Neutrino 8.0 `.secpol` parser."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from secpol_audit.ir import (
    RESERVED_TYPES,
    AbilityRule,
    AbilitySpec,
    AttachPath,
    AttachRule,
    AttributeDecl,
    ChannelConnectRule,
    DefaultSpawnTypeRule,
    DeriveTypeRule,
    LinkRule,
    MountPointRule,
    ParseDiagnostic,
    PolicyIR,
    SourceSpan,
    TypeDecl,
)

ABILITY_MODIFIERS = frozenset({"nonroot", "noinherit", "unlock", "unlocked"})
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
ABILITY_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_./-]*$")
ABILITY_ARG_RE = re.compile(r"^[A-Za-z0-9_./*+-]+$")

SINGLE_CHAR_TOKENS = {
    "{": "LBRACE",
    "}": "RBRACE",
    ";": "SEMI",
    ",": "COMMA",
    ":": "COLON",
}


@dataclass(frozen=True)
class Token:
    kind: str  # WORD, STRING, LBRACE, RBRACE, SEMI, COMMA, COLON, EOF
    value: str
    line: int
    col: int
    end_col: int
    preceded_by_ws: bool


def _line_snippet(lines: list[str], line: int) -> str:
    if 1 <= line <= len(lines):
        return lines[line - 1].rstrip("\r\n")
    return ""


def tokenize_secpol(text: str, source_path: str) -> tuple[list[Token], list[str]]:
    """Tokenize QNX 8.0 secpol text with exact 1-indexed line/column tracking."""
    lines = text.splitlines()
    tokens: list[Token] = []
    n = len(text)
    i = 0
    line = 1
    col = 1
    saw_ws = True

    while i < n:
        ch = text[i]

        if ch in (" ", "\t", "\r"):
            i += 1
            col += 1
            saw_ws = True
            continue

        if ch == "\n":
            i += 1
            line += 1
            col = 1
            saw_ws = True
            continue

        if ch == "#":
            # Line comment (valid anywhere, including inside `{ ... }` blocks)
            while i < n and text[i] != "\n":
                i += 1
                col += 1
            saw_ws = True
            continue

        if ch in SINGLE_CHAR_TOKENS:
            tokens.append(
                Token(
                    kind=SINGLE_CHAR_TOKENS[ch],
                    value=ch,
                    line=line,
                    col=col,
                    end_col=col + 1,
                    preceded_by_ws=saw_ws,
                )
            )
            i += 1
            col += 1
            saw_ws = False
            continue

        if ch in ('"', "'"):
            quote = ch
            start_line, start_col = line, col
            i += 1
            col += 1
            buf: list[str] = []
            closed = False
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    col += 2
                    continue
                if c == "\n":
                    break
                if c == quote:
                    closed = True
                    i += 1
                    col += 1
                    break
                buf.append(c)
                i += 1
                col += 1
            if not closed:
                span = SourceSpan(
                    file=source_path,
                    line=start_line,
                    col=start_col,
                    snippet=_line_snippet(lines, start_line),
                )
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Unterminated string literal starting with {quote}",
                    span,
                )
            tokens.append(
                Token(
                    kind="STRING",
                    value="".join(buf),
                    line=start_line,
                    col=start_col,
                    end_col=col,
                    preceded_by_ws=saw_ws,
                )
            )
            saw_ws = False
            continue

        # WORD token
        start_col = col
        start_i = i
        while i < n:
            c = text[i]
            if c in (" ", "\t", "\r", "\n", "#", '"', "'") or c in SINGLE_CHAR_TOKENS:
                break
            i += 1
            col += 1
        word = text[start_i:i]
        tokens.append(
            Token(
                kind="WORD",
                value=word,
                line=line,
                col=start_col,
                end_col=col,
                preceded_by_ws=saw_ws,
            )
        )
        saw_ws = False

    tokens.append(
        Token(
            kind="EOF",
            value="",
            line=line,
            col=col,
            end_col=col,
            preceded_by_ws=True,
        )
    )
    return tokens, lines


class SecpolParser:
    """Recursive-descent fail-closed parser for QNX 8.0 security policies."""

    def __init__(self, tokens: list[Token], lines: list[str], source_path: str) -> None:
        self.tokens = tokens
        self.lines = lines
        self.source_path = source_path
        self.pos = 0

    def peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        if idx >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[idx]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        if tok.kind != "EOF":
            self.pos += 1
        return tok

    def span_of(self, start_tok: Token, end_tok: Token | None = None) -> SourceSpan:
        et = end_tok if end_tok is not None else start_tok
        return SourceSpan(
            file=self.source_path,
            line=start_tok.line,
            col=start_tok.col,
            end_line=et.line,
            end_col=et.end_col,
            snippet=_line_snippet(self.lines, start_tok.line),
        )

    def raw_slice(self, start_tok: Token, end_tok: Token) -> str:
        start_l = max(1, start_tok.line)
        end_l = min(len(self.lines), end_tok.line)
        if start_l == end_l:
            return _line_snippet(self.lines, start_l).strip()
        joined = " ".join(self.lines[i].strip() for i in range(start_l - 1, end_l) if self.lines[i].strip())
        return joined

    def error(self, code: str, message: str, tok: Token | None = None) -> ParseDiagnostic:
        t = tok if tok is not None else self.peek()
        return ParseDiagnostic(code, message, self.span_of(t))

    def expect(self, kind: str, desc: str | None = None) -> Token:
        tok = self.peek()
        if tok.kind != kind:
            expected = desc or kind
            got = "end of file" if tok.kind == "EOF" else f"'{tok.value}'"
            raise self.error("PARSE_ERROR", f"Expected {expected}, got {got}", tok)
        return self.advance()

    def _validate_ident(self, tok: Token, role: str, *, allow_reserved: bool = False) -> str:
        if tok.kind != "WORD" or not IDENT_RE.match(tok.value):
            raise self.error("PARSE_ERROR", f"Invalid {role} identifier '{tok.value}'", tok)
        if not allow_reserved and tok.value in RESERVED_TYPES:
            raise self.error(
                "PARSE_ERROR",
                f"Reserved identifier '{tok.value}' cannot be used as a {role} declaration",
                tok,
            )
        return tok.value

    def parse(self) -> PolicyIR:
        ir = PolicyIR(source_path=self.source_path)

        while self.peek().kind != "EOF":
            tok = self.peek()
            if tok.kind != "WORD":
                raise self.error(
                    "PARSE_ERROR",
                    f"Unexpected token '{tok.value}' at top level",
                    tok,
                )

            kw = tok.value
            if kw == "attribute":
                self._parse_attribute(ir)
            elif kw == "type":
                self._parse_type(ir)
            elif kw == "allow":
                self._parse_allow(ir)
            elif kw == "allow_attach":
                self._parse_allow_attach(ir)
            elif kw == "allow_link":
                self._parse_allow_link(ir)
            elif kw == "derive_type":
                self._parse_derive_type(ir)
            elif kw == "default_spawn_type":
                self._parse_default_spawn_type(ir)
            elif kw == "mount_point":
                self._parse_mount_point(ir)
            else:
                raise self.error(
                    "UNSUPPORTED_CONSTRUCT",
                    f"Unsupported QNX secpol top-level construct '{kw}'",
                    tok,
                )

        return ir

    def _parse_attribute(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'attribute'
        name_tok = self.expect("WORD", "attribute name")
        name = self._validate_ident(name_tok, "attribute")
        end = self.expect("SEMI", "';'")

        if name in ir.attributes:
            raise self.error(
                "PARSE_ERROR",
                f"Duplicate attribute declaration '{name}' (previously declared at line {ir.attributes[name].span.line})",
                name_tok,
            )
        if name in ir.types:
            raise self.error(
                "PARSE_ERROR",
                f"Conflicting declaration: '{name}' already declared as a type at line {ir.types[name].span.line}",
                name_tok,
            )

        ir.attributes[name] = AttributeDecl(name=name, span=self.span_of(start, end))

    def _parse_type(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'type'
        name_tok = self.expect("WORD", "type name")
        name = self._validate_ident(name_tok, "type")

        attrs: list[str] = []
        while self.peek().kind == "COMMA":
            self.advance()
            attr_tok = self.expect("WORD", "attribute name after ','")
            attr_name = self._validate_ident(attr_tok, "attribute")
            if attr_name not in attrs:
                attrs.append(attr_name)

        end = self.expect("SEMI", "';'")

        if name in ir.types:
            raise self.error(
                "PARSE_ERROR",
                f"Duplicate type declaration '{name}' (previously declared at line {ir.types[name].span.line})",
                name_tok,
            )
        if name in ir.attributes:
            raise self.error(
                "PARSE_ERROR",
                f"Conflicting declaration: '{name}' already declared as an attribute at line {ir.attributes[name].span.line}",
                name_tok,
            )

        ir.types[name] = TypeDecl(
            name=name,
            attributes=tuple(attrs),
            span=self.span_of(start, end),
        )

    def _parse_ident_or_set(self, role: str) -> tuple[str, ...]:
        tok = self.peek()
        if tok.kind == "LBRACE":
            open_brace = self.advance()
            items: list[str] = []
            while self.peek().kind != "RBRACE":
                cur = self.peek()
                if cur.kind == "EOF":
                    raise self.error("PARSE_ERROR", "Unterminated '{' block", open_brace)
                if cur.kind != "WORD":
                    raise self.error(
                        "PARSE_ERROR",
                        f"Expected {role} identifier inside '{{ ... }}', got '{cur.value}'",
                        cur,
                    )
                self.advance()
                items.append(self._validate_ident(cur, role, allow_reserved=True))
            self.advance()  # '}'
            if not items:
                raise self.error("PARSE_ERROR", f"Empty '{{}}' set for {role}", open_brace)
            return tuple(items)

        if tok.kind == "WORD":
            self.advance()
            return (self._validate_ident(tok, role, allow_reserved=True),)

        raise self.error("PARSE_ERROR", f"Expected {role} identifier or '{{ ... }}' set, got '{tok.value}'", tok)

    def _parse_allow(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'allow'
        sources = self._parse_ident_or_set("source type")
        targets = self._parse_ident_or_set("target type")
        self.expect("COLON", "':'")

        class_tok = self.expect("WORD", "permission class ('channel' or 'ability')")
        if class_tok.value == "channel":
            self._parse_allow_channel(ir, start, sources, targets)
        elif class_tok.value == "ability":
            self._parse_allow_ability(ir, start, sources, targets)
        else:
            raise self.error(
                "UNSUPPORTED_CONSTRUCT",
                f"Unsupported allow class '{class_tok.value}' (supported: 'channel', 'ability')",
                class_tok,
            )

    def _parse_allow_channel(
        self,
        ir: PolicyIR,
        start: Token,
        sources: tuple[str, ...],
        targets: tuple[str, ...],
    ) -> None:
        if self.peek().kind == "LBRACE":
            open_brace = self.advance()
            perms: list[str] = []
            while self.peek().kind != "RBRACE":
                cur = self.peek()
                if cur.kind == "EOF":
                    raise self.error("PARSE_ERROR", "Unterminated '{' in channel permission set", open_brace)
                if cur.kind != "WORD":
                    raise self.error("PARSE_ERROR", f"Unexpected token '{cur.value}' in channel permission set", cur)
                self.advance()
                if cur.value != "connect":
                    raise self.error(
                        "UNSUPPORTED_CONSTRUCT",
                        f"Unsupported channel permission '{cur.value}' (supported: 'connect')",
                        cur,
                    )
                perms.append(cur.value)
            self.advance()
            if not perms:
                raise self.error("PARSE_ERROR", "Empty channel permission set '{}'", open_brace)
        else:
            perm_tok = self.expect("WORD", "'connect'")
            if perm_tok.value != "connect":
                raise self.error(
                    "UNSUPPORTED_CONSTRUCT",
                    f"Unsupported channel permission '{perm_tok.value}' (supported: 'connect')",
                    perm_tok,
                )

        end = self.expect("SEMI", "';'")
        ir.connect_rules.append(
            ChannelConnectRule(
                sources=sources,
                targets=targets,
                span=self.span_of(start, end),
                raw=self.raw_slice(start, end),
            )
        )

    def _parse_single_ability(self, pending_modifiers: list[str]) -> AbilitySpec:
        name_tok = self.peek()
        if name_tok.kind != "WORD":
            raise self.error(
                "PARSE_ERROR",
                f"Malformed ability token '{name_tok.value}'",
                name_tok,
            )
        if not ABILITY_NAME_RE.match(name_tok.value):
            raise self.error(
                "PARSE_ERROR",
                f"Invalid ability name '{name_tok.value}'",
                name_tok,
            )
        self.advance()

        args: list[str] = []
        raw_arg: str | None = None
        end_tok = name_tok

        if self.peek().kind == "COLON":
            colon_tok = self.advance()
            arg_tok = self.peek()
            if arg_tok.kind != "WORD" or arg_tok.line != colon_tok.line:
                raise self.error(
                    "PARSE_ERROR",
                    f"Malformed ability '{name_tok.value}:': missing parameter after ':'",
                    colon_tok,
                )
            if not ABILITY_ARG_RE.match(arg_tok.value):
                raise self.error(
                    "PARSE_ERROR",
                    f"Invalid parameter '{arg_tok.value}' for ability '{name_tok.value}'",
                    arg_tok,
                )
            self.advance()
            args.append(arg_tok.value)
            end_tok = arg_tok

            while self.peek().kind == "COMMA":
                comma_tok = self.advance()
                next_arg = self.peek()
                if next_arg.kind != "WORD" or next_arg.line != comma_tok.line:
                    raise self.error(
                        "PARSE_ERROR",
                        f"Malformed ability '{name_tok.value}': missing parameter after ','",
                        comma_tok,
                    )
                if not ABILITY_ARG_RE.match(next_arg.value):
                    raise self.error(
                        "PARSE_ERROR",
                        f"Invalid parameter '{next_arg.value}' for ability '{name_tok.value}'",
                        next_arg,
                    )
                self.advance()
                args.append(next_arg.value)
                end_tok = next_arg

            # Reject double colon like `settypeid:a:b` unless part of range? Colon isn't in hex ranges.
            if self.peek().kind == "COLON":
                raise self.error(
                    "PARSE_ERROR",
                    f"Unexpected ':' in ability '{name_tok.value}'",
                    self.peek(),
                )
            raw_arg = ",".join(args)

        spec = AbilitySpec(
            name=name_tok.value,
            args=tuple(args),
            raw_arg=raw_arg,
            modifiers=tuple(pending_modifiers),
            span=self.span_of(name_tok, end_tok),
            raw=f"{' '.join(pending_modifiers)} {name_tok.value}{(':' + raw_arg) if raw_arg else ''}".strip(),
        )
        return spec

    def _parse_allow_ability(
        self,
        ir: PolicyIR,
        start: Token,
        sources: tuple[str, ...],
        targets: tuple[str, ...],
    ) -> None:
        abilities: list[AbilitySpec] = []

        if self.peek().kind == "LBRACE":
            open_brace = self.advance()
            pending_mods: list[str] = []
            while self.peek().kind != "RBRACE":
                cur = self.peek()
                if cur.kind == "EOF":
                    raise self.error("PARSE_ERROR", "Unterminated '{' in ability block", open_brace)
                if cur.kind != "WORD":
                    raise self.error(
                        "PARSE_ERROR",
                        f"Unexpected token '{cur.value}' inside ability block",
                        cur,
                    )
                if cur.value in ABILITY_MODIFIERS:
                    # Reject modifier with colon like `unlock:foo`
                    if self.peek(1).kind == "COLON":
                        raise self.error(
                            "PARSE_ERROR",
                            f"Ability modifier '{cur.value}' cannot take a ':' parameter",
                            cur,
                        )
                    pending_mods.append(cur.value)
                    self.advance()
                    continue

                spec = self._parse_single_ability(pending_mods)
                pending_mods = []
                abilities.append(spec)

            close_brace = self.advance()  # '}'
            if pending_mods:
                raise self.error(
                    "PARSE_ERROR",
                    f"Dangling ability modifier(s) '{' '.join(pending_mods)}' without an ability",
                    close_brace,
                )
            if not abilities:
                raise self.error("PARSE_ERROR", "Empty ability block '{}'", open_brace)
        else:
            pending_mods = []
            while self.peek().kind == "WORD" and self.peek().value in ABILITY_MODIFIERS:
                if self.peek(1).kind == "COLON":
                    raise self.error(
                        "PARSE_ERROR",
                        f"Ability modifier '{self.peek().value}' cannot take a ':' parameter",
                        self.peek(),
                    )
                pending_mods.append(self.advance().value)
            if self.peek().kind == "SEMI":
                raise self.error(
                    "PARSE_ERROR",
                    "Missing ability name before ';'",
                    self.peek(),
                )
            abilities.append(self._parse_single_ability(pending_mods))

        end = self.expect("SEMI", "';'")
        ir.ability_rules.append(
            AbilityRule(
                sources=sources,
                targets=targets,
                abilities=tuple(abilities),
                span=self.span_of(start, end),
                raw=self.raw_slice(start, end),
            )
        )

    def _parse_attach_path_item(self) -> AttachPath:
        tok = self.peek()
        if tok.kind not in ("WORD", "STRING"):
            raise self.error("PARSE_ERROR", f"Expected attach path, got '{tok.value}'", tok)
        self.advance()

        # Check for `<ftype>:<path>` syntax such as `mount+:/system`, `mount:/dev/fs`, `*:/dev/foo`
        if tok.kind == "WORD" and self.peek().kind == "COLON":
            colon = self.advance()
            path_tok = self.peek()
            if path_tok.kind not in ("WORD", "STRING") or path_tok.line != colon.line:
                raise self.error(
                    "PARSE_ERROR",
                    f"Expected path after '{tok.value}:'",
                    colon,
                )
            self.advance()
            return AttachPath(
                raw=f"{tok.value}:{path_tok.value}",
                ftype=tok.value,
                path=path_tok.value,
            )

        return AttachPath(raw=tok.value, ftype=None, path=tok.value)

    def _parse_attach_path_or_set(self) -> tuple[AttachPath, ...]:
        if self.peek().kind == "LBRACE":
            open_brace = self.advance()
            items: list[AttachPath] = []
            while self.peek().kind != "RBRACE":
                if self.peek().kind == "EOF":
                    raise self.error("PARSE_ERROR", "Unterminated '{' in attach path set", open_brace)
                items.append(self._parse_attach_path_item())
            self.advance()
            if not items:
                raise self.error("PARSE_ERROR", "Empty '{}' path set in allow_attach", open_brace)
            return tuple(items)
        return (self._parse_attach_path_item(),)

    def _parse_allow_attach(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'allow_attach'
        types = self._parse_ident_or_set("type")
        paths = self._parse_attach_path_or_set()

        channel_type: str | None = None
        if self.peek().kind == "WORD":
            ct_tok = self.advance()
            channel_type = self._validate_ident(ct_tok, "channel type", allow_reserved=True)

        end = self.expect("SEMI", "';'")
        ir.attach_rules.append(
            AttachRule(
                types=types,
                paths=paths,
                channel_type=channel_type,
                span=self.span_of(start, end),
                raw=self.raw_slice(start, end),
            )
        )

    def _parse_path_or_set(self, rule_name: str) -> tuple[str, ...]:
        if self.peek().kind == "LBRACE":
            open_brace = self.advance()
            items: list[str] = []
            while self.peek().kind != "RBRACE":
                if self.peek().kind == "EOF":
                    raise self.error("PARSE_ERROR", f"Unterminated '{{' in {rule_name} path set", open_brace)
                ap = self._parse_attach_path_item()
                items.append(ap.raw)
            self.advance()
            if not items:
                raise self.error("PARSE_ERROR", f"Empty '{{}}' path set in {rule_name}", open_brace)
            return tuple(items)
        ap = self._parse_attach_path_item()
        return (ap.raw,)

    def _parse_allow_link(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'allow_link'
        types = self._parse_ident_or_set("type")
        paths = self._parse_path_or_set("allow_link")
        end = self.expect("SEMI", "';'")
        ir.link_rules.append(
            LinkRule(
                types=types,
                paths=paths,
                span=self.span_of(start, end),
                raw=self.raw_slice(start, end),
            )
        )

    def _parse_derive_type(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'derive_type'
        src_tok = self.expect("WORD", "source type in derive_type")
        src = self._validate_ident(src_tok, "source type", allow_reserved=True)
        name_tok = self.expect("WORD", "transition name in derive_type")
        dst_tok = self.expect("WORD", "destination type in derive_type")
        dst = self._validate_ident(dst_tok, "destination type", allow_reserved=True)
        end = self.expect("SEMI", "';'")
        ir.derive_rules.append(
            DeriveTypeRule(
                src_type=src,
                name=name_tok.value,
                dst_type=dst,
                span=self.span_of(start, end),
                raw=self.raw_slice(start, end),
            )
        )

    def _parse_default_spawn_type(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'default_spawn_type'
        src_tok = self.expect("WORD", "source type in default_spawn_type")
        src = self._validate_ident(src_tok, "source type", allow_reserved=True)
        dst_tok = self.expect("WORD", "destination type in default_spawn_type")
        dst = self._validate_ident(dst_tok, "destination type", allow_reserved=True)
        end = self.expect("SEMI", "';'")
        ir.default_spawn_rules.append(
            DefaultSpawnTypeRule(
                src_type=src,
                dst_type=dst,
                span=self.span_of(start, end),
                raw=self.raw_slice(start, end),
            )
        )

    def _parse_mount_point(self, ir: PolicyIR) -> None:
        start = self.advance()  # 'mount_point'
        uid_tok = self.expect("WORD", "uid in mount_point")
        self.expect("COLON", "':' between uid and gid in mount_point")
        gid_tok = self.expect("WORD", "gid in mount_point")
        owner = f"{uid_tok.value}:{gid_tok.value}"

        if self.peek().kind == "LBRACE":
            open_brace = self.advance()
            parts: list[str] = []
            while self.peek().kind != "RBRACE":
                cur = self.peek()
                if cur.kind == "EOF":
                    raise self.error("PARSE_ERROR", "Unterminated '{' in mount_point ACL block", open_brace)
                self.advance()
                parts.append(cur.value)
            self.advance()
            if not parts:
                raise self.error("PARSE_ERROR", "Empty ACL block in mount_point", open_brace)
            perms = "{ " + " ".join(parts) + " }"
        else:
            perm_tok = self.expect("WORD", "permissions or ACL block in mount_point")
            perms = perm_tok.value

        paths = self._parse_path_or_set("mount_point")
        end = self.expect("SEMI", "';'")
        ir.mount_point_rules.append(
            MountPointRule(
                owner=owner,
                perms=perms,
                paths=paths,
                span=self.span_of(start, end),
                raw=self.raw_slice(start, end),
            )
        )


def parse_secpol_text(text: str, source_path: str = "<memory>") -> PolicyIR:
    """Parse QNX 8.0 `.secpol` policy text into `PolicyIR`."""
    tokens, lines = tokenize_secpol(text, source_path)
    parser = SecpolParser(tokens, lines, source_path)
    return parser.parse()


def parse_secpol_file(path: str | Path) -> PolicyIR:
    """Read and parse a `.secpol` file into `PolicyIR`."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"Unable to read policy file: {exc}",
            SourceSpan(file=str(p), line=1, col=1),
        ) from exc
    return parse_secpol_text(text, str(p))
