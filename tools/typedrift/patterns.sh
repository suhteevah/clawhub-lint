#!/usr/bin/env bash
# TypeDrift — Erosion Pattern Definitions
# Each pattern: REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Severity levels:
#   critical — Direct type safety violation or complete suppression
#   high     — Significant lint/check bypass
#   medium   — Minor quality erosion, needs review
#   low      — Style concern, informational
#
# IMPORTANT: All regexes must use POSIX ERE syntax (grep -E compatible).
# - Use [[:space:]] instead of \s
# - Use literal quotes instead of \x27
# - Avoid Perl-only features (\d, \w, etc.)

set -euo pipefail

# ─── Pattern registry ──────────────────────────────────────────────────────
#
# Format: "regex|severity|check_id|description|recommendation"
# Patterns use POSIX extended grep regex (ERE) syntax.
# Organized by language category.

declare -a TYPEDRIFT_PATTERNS=()

# ═══════════════════════════════════════════════════════════════════════════
# 1. TypeScript / JavaScript — Type Assertion Escape Hatches (Critical)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  'as[[:space:]]+any|critical|TS001|Type assertion to any — bypasses entire type system|Replace with a proper type or use a type guard'
  'as[[:space:]]+unknown|high|TS002|Type assertion to unknown — weaker escape hatch|Narrow the type with a type guard instead'
  '<any>|critical|TS003|Generic type assertion to any (angle bracket syntax)|Use proper typed generics'
  '<unknown>|high|TS004|Generic type assertion to unknown (angle bracket syntax)|Narrow with type guards'
)

# ═══════════════════════════════════════════════════════════════════════════
# 2. TypeScript / JavaScript — TypeScript Suppressions (Critical)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '@ts-ignore|critical|TS010|@ts-ignore suppresses TypeScript error on next line|Fix the type error or use @ts-expect-error with explanation'
  '@ts-nocheck|critical|TS011|@ts-nocheck disables TypeScript checking for entire file|Remove and fix all type errors in the file'
  '@ts-expect-error|high|TS012|@ts-expect-error suppresses expected TypeScript error|Add a comment explaining why and create a ticket to fix'
)

# ═══════════════════════════════════════════════════════════════════════════
# 3. TypeScript / JavaScript — ESLint Suppressions (High)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '//[[:space:]]*eslint-disable-next-line|high|TS020|ESLint rule disabled for next line|Fix the lint error or configure the rule properly'
  '//[[:space:]]*eslint-disable[[:space:]]|high|TS021|ESLint rules disabled inline|Fix the lint errors instead of suppressing them'
  '/\*[[:space:]]*eslint-disable[[:space:]]|high|TS022|ESLint rules disabled via block comment|Fix the lint errors instead of suppressing them'
  '/\*[[:space:]]*eslint-disable[[:space:]]*\*/|critical|TS023|ESLint completely disabled for rest of file|Remove and fix all lint errors in the file'
  '//[[:space:]]*eslint-disable-line|high|TS024|ESLint rule disabled for current line|Fix the lint error or configure the rule properly'
)

# ═══════════════════════════════════════════════════════════════════════════
# 4. TypeScript / JavaScript — any in Type Signatures (Critical)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  ':[[:space:]]*any[[:space:]]*[,)=;]|critical|TS030|Parameter typed as any — no type safety|Use a specific type, generic, or unknown with narrowing'
  ':[[:space:]]*any[[:space:]]*$|critical|TS031|Variable or property typed as any|Use a specific type or interface'
  ':[[:space:]]*any\[|critical|TS032|Array of any — untyped array|Use a typed array like string[] or T[]'
  'Promise<any>|critical|TS033|Promise resolving to any|Type the Promise with the expected resolved type'
  'Array<any>|critical|TS034|Array generic with any|Use Array<SpecificType> instead'
  'Record<string,[[:space:]]*any>|high|TS035|Record with any values|Define a proper value type for the Record'
  'Map<[^>]*,[[:space:]]*any>|high|TS036|Map with any values|Define a proper value type for the Map'
  '\)[[:space:]]*:[[:space:]]*any[[:space:]]*[{]|critical|TS037|Function return type is any|Specify the actual return type'
  '\)[[:space:]]*:[[:space:]]*any[[:space:]]*=>|critical|TS038|Arrow function return type is any|Specify the actual return type'
)

# ═══════════════════════════════════════════════════════════════════════════
# 5. TypeScript / JavaScript — Non-null Assertions (Medium)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '[a-zA-Z0-9_\])]![.;,)\]]|medium|TS040|Non-null assertion operator (!) — assumes value is not null|Use optional chaining (?.) or proper null checks'
  '[a-zA-Z0-9_\])]!![[:space:]]*[^=]|low|TS041|Double-bang coercion to boolean|Use Boolean() or explicit comparison for clarity'
)

# ═══════════════════════════════════════════════════════════════════════════
# 6. TypeScript / JavaScript — Other Quality Erosion (Medium/Low)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  'Function[[:space:]]*[,;)>]|high|TS050|Using Function type — no parameter or return type safety|Use a specific function signature type'
  'Object[[:space:]]*[,;)>]|medium|TS051|Using Object type — too broad|Use Record<string, unknown> or a specific interface'
  '\{[[:space:]]*\}[[:space:]]*[,;)]|low|TS052|Empty object type {} — matches any non-nullish value|Use Record<string, never> or a specific type'
  'eval[[:space:]]*\(|high|TS053|eval() usage — code injection risk and no type safety|Refactor to avoid eval; use safer alternatives'
  'require[[:space:]]*\([[:space:]]*["\x27]|low|TS054|CommonJS require() in TypeScript — loses type information|Use ES module import syntax instead'
)

# ═══════════════════════════════════════════════════════════════════════════
# 7. Python — Type Check Suppressions (Critical)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '#[[:space:]]*type:[[:space:]]*ignore|critical|PY001|type: ignore suppresses mypy/pyright error|Fix the type error or add a specific error code'
  '@no_type_check|critical|PY002|@no_type_check disables type checking for function|Remove and add proper type annotations'
  '#[[:space:]]*type:[[:space:]]*ignore\[|high|PY003|type: ignore with specific error code|Fix the underlying type error'
)

# ═══════════════════════════════════════════════════════════════════════════
# 8. Python — Lint Suppressions (High)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '#[[:space:]]*noqa|high|PY010|noqa suppresses flake8/ruff warning|Fix the lint error instead of suppressing it'
  '#[[:space:]]*noqa:[[:space:]]*[A-Z]|high|PY011|noqa with specific error code|Fix the specific lint error'
  '#[[:space:]]*pylint:[[:space:]]*disable|high|PY012|pylint: disable suppresses Pylint warning|Fix the Pylint error or configure in pylintrc'
  '#[[:space:]]*noinspection|medium|PY013|noinspection suppresses PyCharm/IntelliJ warning|Fix the inspection warning'
  '#[[:space:]]*pragma:[[:space:]]*no[[:space:]]*cover|medium|PY014|pragma: no cover excludes from coverage|Ensure the code is actually tested'
)

# ═══════════════════════════════════════════════════════════════════════════
# 9. Python — Unsafe Typing (Critical)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  'typing\.Any|critical|PY020|typing.Any — opts out of type checking|Use a specific type, Union, or Protocol'
  'from[[:space:]]+typing[[:space:]]+import.*\bAny\b|critical|PY021|Importing Any from typing|Use specific types instead of Any'
  'cast[[:space:]]*\([[:space:]]*Any|critical|PY022|cast(Any, ...) — forces type erasure|Cast to a specific type instead'
  ':[[:space:]]*Any[[:space:]]*[=,)]|critical|PY023|Parameter or variable annotated as Any|Use a specific type annotation'
  '->[[:space:]]*Any|critical|PY024|Function return type annotated as Any|Specify the actual return type'
  'Dict\[str,[[:space:]]*Any\]|high|PY025|Dict with Any values|Use TypedDict or a specific value type'
  'List\[Any\]|high|PY026|List of Any|Use List[SpecificType] instead'
  'Optional\[Any\]|high|PY027|Optional[Any] is redundant and unsafe|Use Optional[SpecificType]'
)

# ═══════════════════════════════════════════════════════════════════════════
# 10. Java — Warning Suppressions (High)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '@SuppressWarnings|high|JV001|@SuppressWarnings suppresses compiler warnings|Fix the warning or document why suppression is necessary'
  '@SuppressWarnings[[:space:]]*\([[:space:]]*"unchecked"|critical|JV002|Unchecked cast suppression — hides type safety issues|Add proper generic types to avoid unchecked casts'
  '@SuppressWarnings[[:space:]]*\([[:space:]]*"rawtypes"|critical|JV003|Raw types suppression — bypasses generics|Parameterize the generic types properly'
  '@SuppressWarnings[[:space:]]*\([[:space:]]*"deprecation"|medium|JV004|Deprecation suppression — using outdated APIs|Migrate to the recommended replacement API'
  '@SuppressWarnings[[:space:]]*\([[:space:]]*"all"|critical|JV005|Suppressing ALL warnings — extremely dangerous|Remove and fix each warning individually'
)

# ═══════════════════════════════════════════════════════════════════════════
# 11. Java — Raw Types and Unsafe Casts (Medium)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  'ArrayList[[:space:]]*[^<(]|medium|JV010|Raw ArrayList without generic type parameter|Use ArrayList<SpecificType>'
  'HashMap[[:space:]]*[^<(]|medium|JV011|Raw HashMap without generic type parameter|Use HashMap<KeyType, ValueType>'
  'List[[:space:]]*[^<(].*=[[:space:]]*new|medium|JV012|Raw List assignment without generics|Use List<SpecificType>'
  '\(Object\)|medium|JV013|Cast to Object — erases type information|Use proper generic types or specific casts'
  '\(Object\[\]\)|medium|JV014|Cast to Object[] — loses array type safety|Use properly typed arrays'
)

# ═══════════════════════════════════════════════════════════════════════════
# 12. Kotlin — Suppressions (High)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '@Suppress[[:space:]]*\(|high|KT001|@Suppress annotation — suppresses Kotlin compiler warning|Fix the underlying issue instead'
  '@Suppress[[:space:]]*\([[:space:]]*"UNCHECKED_CAST"|critical|KT002|Unchecked cast suppression in Kotlin|Use reified generics or safe casts (as?)'
  'as![[:space:]]|medium|KT003|Unsafe cast operator (as!) — throws on failure|Use safe cast (as?) with null check'
  '@SuppressLint|high|KT010|@SuppressLint suppresses Android lint warning|Fix the lint issue or document the suppression reason'
)

# ═══════════════════════════════════════════════════════════════════════════
# 13. Go — Lint Suppressions (High)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '//nolint|high|GO001|//nolint suppresses golangci-lint warning|Fix the lint issue or add specific nolint directive with reason'
  '//nolint:[a-z]|high|GO002|//nolint with specific linter — suppresses targeted check|Fix the specific lint issue'
  '//lint:ignore|high|GO003|//lint:ignore suppresses staticcheck/lint warning|Fix the lint issue instead of ignoring it'
)

# ═══════════════════════════════════════════════════════════════════════════
# 14. Go — Unsafe Typing and Error Suppression (Critical/Medium)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  'interface[[:space:]]*\{[[:space:]]*\}|medium|GO010|Empty interface{} — equivalent to any, no type safety|Use a specific interface or generics (Go 1.18+)'
  '\bany\b[[:space:]]*[,);]|medium|GO011|any type alias (Go 1.18+) — no type constraints|Use specific type constraints or interfaces'
  '_[[:space:]]*=[[:space:]]*err|critical|GO020|Error assigned to blank identifier — silently discarded|Handle the error: log, return, or wrap it'
  '_[[:space:]]*=[[:space:]]*[a-zA-Z]+\.|high|GO021|Return value assigned to blank identifier|Handle or check the return value'
  'unsafe\.|high|GO030|unsafe package usage — bypasses Go type system|Avoid unsafe; use safe alternatives where possible'
)

# ═══════════════════════════════════════════════════════════════════════════
# 15. Ruby — Lint Suppressions (High)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  '#[[:space:]]*rubocop:disable|high|RB001|rubocop:disable suppresses RuboCop warning|Fix the RuboCop offense or configure in .rubocop.yml'
  '#[[:space:]]*rubocop:disable[[:space:]]+all|critical|RB002|rubocop:disable all — suppresses ALL RuboCop checks|Remove and fix each offense individually'
  '#[[:space:]]*:reek:|medium|RB010|Reek suppression — hiding code smell|Refactor to eliminate the code smell'
  '#[[:space:]]*:nocov:|medium|RB011|:nocov: excludes code from coverage|Ensure the code is actually tested'
)

# ═══════════════════════════════════════════════════════════════════════════
# 16. Cross-language — Generic Quality Erosion (Low/Medium)
# ═══════════════════════════════════════════════════════════════════════════

TYPEDRIFT_PATTERNS+=(
  'TODO.*HACK|low|GEN001|TODO/HACK marker — known workaround left in code|Create a ticket and refactor the workaround'
  'FIXME|low|GEN002|FIXME marker — known issue left in code|Create a ticket and fix the issue'
  'XXX|low|GEN003|XXX marker — dangerous or broken code marker|Investigate and fix immediately'
  'HACK[[:space:]]*:|low|GEN004|HACK marker — intentional workaround|Document the reason and create a ticket to fix'
)

# ═══════════════════════════════════════════════════════════════════════════
# Language -> File Extension Mapping
# ═══════════════════════════════════════════════════════════════════════════

declare -A TYPEDRIFT_LANG_EXTENSIONS=(
  [typescript]="ts tsx mts cts"
  [javascript]="js jsx mjs cjs"
  [python]="py pyi"
  [java]="java"
  [kotlin]="kt kts"
  [go]="go"
  [ruby]="rb rake"
)

# Check ID -> Language mapping (prefix-based)
declare -A TYPEDRIFT_CHECK_LANG=(
  [TS]="typescript javascript"
  [PY]="python"
  [JV]="java"
  [KT]="kotlin"
  [GO]="go"
  [RB]="ruby"
  [GEN]="all"
)

# ─── Utility: get pattern count ──────────────────────────────────────────

typedrift_pattern_count() {
  echo "${#TYPEDRIFT_PATTERNS[@]}"
}

# ─── Utility: list patterns by severity ──────────────────────────────────

typedrift_list_patterns() {
  local filter_severity="${1:-all}"

  for entry in "${TYPEDRIFT_PATTERNS[@]}"; do
    IFS='|' read -r regex severity check_id description recommendation <<< "$entry"
    if [[ "$filter_severity" == "all" || "$filter_severity" == "$severity" ]]; then
      printf "%-10s %-8s %s\n" "$severity" "$check_id" "$description"
    fi
  done
}

# ─── Utility: list patterns by language ──────────────────────────────────

typedrift_list_patterns_by_lang() {
  local filter_lang="${1:-all}"

  for entry in "${TYPEDRIFT_PATTERNS[@]}"; do
    IFS='|' read -r regex severity check_id description recommendation <<< "$entry"
    local prefix="${check_id%%[0-9]*}"
    local lang="${TYPEDRIFT_CHECK_LANG[$prefix]:-unknown}"

    if [[ "$filter_lang" == "all" || "$lang" == *"$filter_lang"* ]]; then
      printf "%-10s %-8s %s\n" "$severity" "$check_id" "$description"
    fi
  done
}

# ─── Utility: severity to numeric level ──────────────────────────────────

severity_to_level() {
  case "$1" in
    critical) echo 4 ;;
    high)     echo 3 ;;
    medium)   echo 2 ;;
    low)      echo 1 ;;
    *)        echo 0 ;;
  esac
}

# ─── Utility: severity to score deduction ────────────────────────────────

severity_to_deduction() {
  case "$1" in
    critical) echo 5 ;;
    high)     echo 3 ;;
    medium)   echo 1 ;;
    low)      echo 0 ;;
    *)        echo 0 ;;
  esac
}

# ─── Default exclude directories ─────────────────────────────────────────

TYPEDRIFT_EXCLUDE_DIRS=(
  ".git"
  "node_modules"
  "dist"
  "build"
  "vendor"
  "__pycache__"
  ".venv"
  "venv"
  ".tox"
  ".mypy_cache"
  ".pytest_cache"
  "target"
  ".next"
  ".nuxt"
  "coverage"
  ".terraform"
  ".gradle"
  ".idea"
  ".vscode"
  "pkg"
  "bin"
)

# ─── Default binary extensions to skip ───────────────────────────────────

TYPEDRIFT_BINARY_EXTENSIONS=(
  "png" "jpg" "jpeg" "gif" "bmp" "ico" "svg"
  "woff" "woff2" "ttf" "eot" "otf"
  "pdf" "zip" "tar" "gz" "bz2" "xz" "7z" "rar"
  "exe" "dll" "so" "dylib" "bin"
  "mp3" "mp4" "avi" "mov" "mkv" "wav" "flac"
  "pyc" "pyo" "class" "o" "obj"
  "wasm" "map" "lock"
)

# ─── Source extensions we scan ───────────────────────────────────────────

TYPEDRIFT_SOURCE_EXTENSIONS=(
  "ts" "tsx" "mts" "cts"
  "js" "jsx" "mjs" "cjs"
  "py" "pyi"
  "java"
  "kt" "kts"
  "go"
  "rb" "rake"
)
