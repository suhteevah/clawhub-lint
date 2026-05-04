#!/usr/bin/env bash
# DesignLint -- DESIGN.md format hygiene
# Each pattern: REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Targets `DESIGN.md` files (Google Labs design.md format,
# https://github.com/google-labs-code/design.md). The full DESIGN.md spec
# lints via `npx @google/design.md lint` — including WCAG contrast checks
# that require parsing color math. This analyzer covers the syntactic /
# structural issues we can catch with pure grep, complementing the upstream
# CLI rather than replacing it.
#
# To run the full lint: `npx @google/design.md lint DESIGN.md`
# To run this analyzer:  `clawhub-lint scan <repo> --tools designlint`
#
# IMPORTANT: All regexes use POSIX ERE syntax (grep -E compatible).

set -euo pipefail

# ============================================================================
# 1. TOKEN REFERENCE SYNTAX (DL-001 through DL-005)
# ============================================================================

declare -a DESIGNLINT_TOKEN_REF_PATTERNS=()

DESIGNLINT_TOKEN_REF_PATTERNS+=(
  # Whitespace inside curly-brace token refs — DESIGN.md token refs are tight.
  '\{[[:space:]]+[a-zA-Z]+\.|\{[a-zA-Z][^{}]*[[:space:]]+\}|high|DL-001|Whitespace inside DESIGN.md token reference (use {colors.brand}, not { colors.brand })|Remove all whitespace inside curly braces; the spec rejects spaced refs'

  # Single-brace pseudo-refs — common typo.
  '[^{]\{[a-zA-Z]+\.[a-zA-Z]+\}[^}]|medium|DL-002|Single-braced token reference looks malformed (DESIGN.md uses single { } pairs but they must be balanced)|Verify the brace balance; consider quoting the value if it should be a literal'

  # Token ref with three-part path — design.md spec is two-level (group.name).
  '\{[a-zA-Z]+\.[a-zA-Z]+\.[a-zA-Z]+\.[a-zA-Z]|medium|DL-003|Deeply nested token reference (more than 2 levels)|design.md tokens compose at 1-2 levels; flatten the structure or verify the spec supports your depth'

  # Empty token ref.
  '\{\}|high|DL-004|Empty token reference|Remove or fill in the reference; empty {} blocks fail the linter'

  # Unmatched opening brace at end of value.
  ':[[:space:]]*"\{[a-zA-Z][^"}]*"$|high|DL-005|Unclosed token reference inside quoted value|Add the closing brace before the closing quote'
)

# ============================================================================
# 2. RAW VALUES WHERE TOKEN REFS BELONG (DL-010 through DL-014)
# ============================================================================

declare -a DESIGNLINT_RAW_VALUE_PATTERNS=()

DESIGNLINT_RAW_VALUE_PATTERNS+=(
  # Hex color directly in component property (background/color/border) —
  # components should reference tokens, not hardcode hex.
  '^[[:space:]]+(background|color|border|fill|stroke|hoverBackground|activeBackground):[[:space:]]+"#[0-9a-fA-F]{3,8}"|medium|DL-010|Raw hex color in component property (should reference a token instead)|Define the color in the colors: section and reference it via {colors.<name>}'

  # rgb()/rgba()/hsl()/oklch() inline in component property.
  '^[[:space:]]+(background|color|border|fill|stroke|hoverBackground|activeBackground):[[:space:]]+"(rgb|rgba|hsl|hsla|oklch)\(|medium|DL-011|Raw color function in component property (should reference a token instead)|Move the color literal to the colors: section and reference via curly-brace syntax'

  # Numeric pixel values in component spacing/padding/margin — should use spacing.scale.
  '^[[:space:]]+(padding|margin|gap|paddingX|paddingY|marginX|marginY):[[:space:]]+[0-9]+([[:space:]]|$)|low|DL-012|Raw numeric spacing value in component (should reference spacing.scale)|Use {spacing.scale.<index>} or define a named spacing token'
)

# ============================================================================
# 3. STRUCTURAL ISSUES (DL-020 through DL-024)
# ============================================================================

declare -a DESIGNLINT_STRUCTURAL_PATTERNS=()

DESIGNLINT_STRUCTURAL_PATTERNS+=(
  # YAML frontmatter not at top — DESIGN.md requires --- on line 1.
  # (Detect by --- appearing past line 1 without one on line 1; this is
  #  approximate via grep alone — flag --- preceded by content.)
  '^[^[:space:]-].*\n---$|low|DL-020|YAML frontmatter delimiter not at file start (DESIGN.md requires --- on line 1)|Move the YAML frontmatter to the top of the file before any prose'

  # TODO/FIXME inside frontmatter — should not ship.
  '(TODO|FIXME|XXX|HACK):|low|DL-021|TODO/FIXME marker in DESIGN.md (design system should be intentional, not provisional)|Resolve the TODO before committing or move the note to a separate planning doc'

  # Empty section headings inside body.
  '^##[[:space:]]+$|low|DL-022|Empty H2 heading in DESIGN.md body|Either fill in the section content or remove the heading'

  # Lorem ipsum / placeholder content.
  '(?i)lorem ipsum|placeholder text|TBD\b|TBA\b|low|DL-023|Placeholder content in DESIGN.md body|Replace placeholder text with actual design rationale before shipping'
)

# ============================================================================
# 4. ANTI-PATTERNS (DL-030 through DL-034)
# ============================================================================

declare -a DESIGNLINT_ANTIPATTERN_PATTERNS=()

DESIGNLINT_ANTIPATTERN_PATTERNS+=(
  # !important in component definitions — design tokens shouldn't need it.
  '!important|medium|DL-030|!important in DESIGN.md (token system shouldn'"'"'t need specificity overrides)|Remove the !important; if you need specificity it indicates a design system gap'

  # CSS class names embedded as token values — the system speaks tokens, not classes.
  ':[[:space:]]+"\.[a-zA-Z][a-zA-Z0-9_-]*"|low|DL-031|CSS class name as a token value (DESIGN.md tokens are values, not classes)|Replace the class reference with the underlying value or token reference'

  # Vendor prefixes in values — tokens are abstract; let the export layer prefix.
  '-(webkit|moz|ms|o)-|low|DL-032|Vendor prefix in DESIGN.md value (let the export layer add prefixes; keep tokens abstract)|Remove the vendor prefix; the Tailwind/DTCG exporter handles browser compatibility'
)

# Aggregate so dispatcher can iterate.
declare -a DESIGNLINT_PATTERNS=(
  "${DESIGNLINT_TOKEN_REF_PATTERNS[@]}"
  "${DESIGNLINT_RAW_VALUE_PATTERNS[@]}"
  "${DESIGNLINT_STRUCTURAL_PATTERNS[@]}"
  "${DESIGNLINT_ANTIPATTERN_PATTERNS[@]}"
)

# Designlint targets DESIGN.md files specifically. The dispatcher honors
# this via FILE_GLOB; analyzers that don't set it scan the whole tree.
DESIGNLINT_FILE_GLOB="DESIGN.md"
