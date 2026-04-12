#!/usr/bin/env bash
# StyleGuard -- Code Style & Naming Convention Patterns
# Each pattern: REGEX | SEVERITY | CHECK_ID | DESCRIPTION | RECOMMENDATION
#
# Categories: NAMING, FUNCTION, MAGIC, IMPORT, COMMENT, CONSISTENCY
# Severities: critical, high, medium, low
# Patterns are grep -E compatible (POSIX ERE)
#
# Scoring weights: critical=25, high=15, medium=8, low=3

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# NAMING CONVENTIONS (22 patterns: NM-001 through NM-022)
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Mixed Case Detection ────────────────────────────────────────────────────

STYLEGUARD_NAMING_PATTERNS=(
  # NM-001: snake_case variable in camelCase-dominant file (JS/TS/Java)
  '(let|const|var)\s+[a-z]+_[a-z]+\s*=|high|NM-001|snake_case variable in JS/TS/Java file -- expected camelCase|Rename to camelCase: user_name -> userName'

  # NM-002: camelCase variable in snake_case-dominant file (Python/Ruby)
  '^\s+[a-z]+[A-Z][a-z]+\s*=|high|NM-002|camelCase variable in Python/Ruby file -- expected snake_case|Rename to snake_case: userName -> user_name'

  # NM-003: Non-PascalCase class name
  'class\s+[a-z][a-zA-Z]*[^(:]|high|NM-003|Class name not PascalCase -- classes should start with uppercase|Rename class to PascalCase: userService -> UserService'

  # NM-004: Non-PascalCase React component (function)
  'function\s+[a-z][a-zA-Z]*\s*\([^)]*\)\s*\{.*return\s.*<|high|NM-004|React component function not PascalCase|Component names must be PascalCase: myComponent -> MyComponent'

  # NM-005: Non-PascalCase React component (arrow)
  'const\s+[a-z][a-zA-Z]+\s*=\s*\([^)]*\)\s*=>.*<|high|NM-005|React arrow component not PascalCase|Component names must be PascalCase: myComponent -> MyComponent'

  # NM-006: Non-UPPER_CASE constant in JS/TS
  'const\s+[a-z][a-z_]*\s*=\s*[0-9]+\s*;|medium|NM-006|Numeric constant not UPPER_SNAKE_CASE|Rename constant to UPPER_CASE: maxRetries -> MAX_RETRIES'

  # NM-007: Non-UPPER_CASE constant in Python
  '^[A-Z_]*[a-z]+[A-Z_]*\s*=\s*[0-9]+$|medium|NM-007|Module-level numeric constant not UPPER_SNAKE_CASE in Python|Rename to UPPER_SNAKE_CASE: maxRetries -> MAX_RETRIES'

  # NM-008: Single-letter variable (not in for/while loop head)
  '(let|const|var)\s+[a-df-hj-np-z]\s*=|medium|NM-008|Single-letter variable name outside loop -- reduces readability|Use descriptive name: x -> coordinateX, d -> document, t -> timestamp'

  # NM-009: Single-letter Python variable
  '^\s+[a-df-hj-np-z]\s*=\s*[^=]|medium|NM-009|Single-letter variable name in Python -- reduces readability|Use descriptive name: d -> data, t -> total, n -> count'

  # NM-010: Boolean without is/has/should/can prefix
  '(let|const|var)\s+(active|enabled|visible|disabled|loading|ready|valid|checked|open|closed|done|complete|empty|full|locked)\s*=\s*(true|false)|medium|NM-010|Boolean variable without is/has/should/can prefix|Prefix booleans: active -> isActive, enabled -> isEnabled'

  # NM-011: Boolean without is/has/should/can prefix (Python)
  '^\s+(active|enabled|visible|disabled|loading|ready|valid|checked|done|complete|empty|locked)\s*=\s*(True|False)|medium|NM-011|Boolean variable without is_/has_ prefix in Python|Prefix booleans: active -> is_active, enabled -> is_enabled'

  # NM-012: Hungarian notation remnants (str prefix)
  '(let|const|var)\s+str[A-Z][a-zA-Z]+\s*=|low|NM-012|Hungarian notation (str prefix) -- not idiomatic in modern code|Remove type prefix: strName -> name, strValue -> value'

  # NM-013: Hungarian notation remnants (int/num prefix)
  '(let|const|var)\s+(int|num|i|n)[A-Z][a-zA-Z]+\s*=|low|NM-013|Hungarian notation (int/num prefix) -- not idiomatic|Remove type prefix: intCount -> count, numItems -> itemCount'

  # NM-014: Hungarian notation remnants (b/bool prefix)
  '(let|const|var)\s+(b|bool)[A-Z][a-zA-Z]+\s*=|low|NM-014|Hungarian notation (bool prefix) -- not idiomatic|Remove type prefix: bActive -> isActive, boolEnabled -> isEnabled'

  # NM-015: Hungarian notation remnants (arr/lst prefix)
  '(let|const|var)\s+(arr|lst)[A-Z][a-zA-Z]+\s*=|low|NM-015|Hungarian notation (arr/lst prefix) -- not idiomatic|Remove type prefix: arrItems -> items, lstUsers -> users'

  # NM-016: Hungarian notation remnants (obj prefix)
  '(let|const|var)\s+obj[A-Z][a-zA-Z]+\s*=|low|NM-016|Hungarian notation (obj prefix) -- not idiomatic|Remove type prefix: objConfig -> config, objSettings -> settings'

  # NM-017: Event handler inconsistency (handle vs on)
  'on[A-Z][a-zA-Z]+\s*=\s*\(\s*\)\s*=>|medium|NM-017|Event handler uses on- prefix inline -- prefer handle- for implementation|Use handleClick for implementation, onClick for props: onClick -> handleClick'

  # NM-018: Mixed event handler naming (both handle and on in same file)
  'handle[A-Z][a-zA-Z]+\s*=.*\n.*on[A-Z][a-zA-Z]+\s*=|medium|NM-018|Mixed event handler naming -- both handle- and on- prefixes in same file|Standardize: use handle- for functions, on- for props consistently'

  # NM-019: Acronym casing inconsistency (URL vs Url)
  '(get|set|fetch|load|parse|format)(Url|Uri|Api|Xml|Html|Css|Json|Sql|Http|Ftp|Ssh|Dns|Tcp|Udp)[A-Z]|medium|NM-019|Acronym casing inconsistency -- mixing URL vs Url style|Standardize acronyms: use getURL or getUrl consistently, not both'

  # NM-020: Acronym all-caps in middle of camelCase (XMLParser vs XmlParser)
  '[a-z](URL|URI|API|XML|HTML|CSS|JSON|SQL|HTTP|FTP|SSH|DNS|TCP|UDP)[A-Z]|medium|NM-020|ALL_CAPS acronym in camelCase -- inconsistent with standard naming|Use consistent acronym casing: fetchURLData -> fetchUrlData or fetch_url_data'

  # NM-021: Private method without underscore prefix (Python convention)
  'def\s+[a-z][a-z_]+\s*\(self.*\).*#\s*private|medium|NM-021|Python method marked private in comment but lacks underscore prefix|Use leading underscore for private methods: method -> _method'

  # NM-022: Interface/type not prefixed with I (Go/Java convention detection)
  'type\s+[a-z][a-zA-Z]+\s+interface|medium|NM-022|Interface name not exported (lowercase) in Go|Export interface names with PascalCase in Go: reader -> Reader'
)

# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION QUALITY (18 patterns: FQ-001 through FQ-018)
# ═══════════════════════════════════════════════════════════════════════════════

STYLEGUARD_FUNCTION_PATTERNS=(
  # FQ-001: Function with too many parameters (>5) - JS/TS
  'function\s+\w+\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)|high|FQ-001|Function has 6+ parameters -- hard to call correctly and maintain|Use an options object: function create(opts: CreateOpts) instead of positional args'

  # FQ-002: Function with too many parameters (>5) - Python
  'def\s+\w+\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)|high|FQ-002|Function has 6+ parameters -- hard to call correctly|Use a dataclass or TypedDict for options: def create(opts: CreateOpts)'

  # FQ-003: Deep nesting (5+ levels of indentation in JS/TS)
  '^\s{20,}(if|for|while|switch|try)\s|critical|FQ-003|Code nested 5+ levels deep -- high cyclomatic complexity|Extract inner logic into helper functions or use early returns to reduce nesting'

  # FQ-004: Deep nesting in Python (5+ levels = 20+ spaces)
  '^\s{20,}(if|for|while|try|with)\s|critical|FQ-004|Python code nested 5+ levels deep -- hard to read and maintain|Extract inner logic into helper functions or use early returns'

  # FQ-005: Callback hell pattern (nested callbacks >3 deep)
  '\)\s*=>\s*\{[^}]*\)\s*=>\s*\{[^}]*\)\s*=>\s*\{|critical|FQ-005|Callback hell -- 3+ levels of nested callbacks|Refactor with async/await or extract callbacks into named functions'

  # FQ-006: Deeply nested callback pattern (classic style)
  'function\s*\([^)]*\)\s*\{[^}]*function\s*\([^)]*\)\s*\{[^}]*function|critical|FQ-006|Deeply nested function declarations -- callback hell pattern|Refactor with Promises, async/await, or extract into named functions'

  # FQ-007: Deep else chain (multiple else if/elif)
  'else\s+if\s*\(.*\)\s*\{.*\n.*else\s+if\s*\(.*\)\s*\{.*\n.*else\s+if|medium|FQ-007|Deep else-if chain -- consider early returns or switch/match|Use guard clauses with early returns to flatten the control flow'

  # FQ-008: Deep elif chain in Python
  '^\s+elif\s.*:\s*\n\s+.*\n\s+elif\s.*:\s*\n\s+.*\n\s+elif|medium|FQ-008|Deep elif chain in Python -- reduces readability|Use guard clauses with early returns or a dispatch dictionary'

  # FQ-009: Arrow function vs function declaration inconsistency
  'export\s+function\s+\w+\s*\(|low|FQ-009|Export uses function declaration -- check if arrow functions used elsewhere|Standardize: use either arrow functions or declarations consistently across exports'

  # FQ-010: Arrow function with body for simple return
  '=>\s*\{\s*return\s+[^;{]+;\s*\}|low|FQ-010|Arrow function with block body for single return|Simplify: (x) => { return x + 1; } -> (x) => x + 1'

  # FQ-011: Function returning multiple types (JS/TS hint)
  'return\s+null.*\n.*return\s+\{|medium|FQ-011|Function returns both null and object -- inconsistent return type|Return a consistent type: use undefined, empty object, or Optional/Maybe pattern'

  # FQ-012: Function returning mixed string/number (JS/TS)
  'return\s+["\x27].*\n.*return\s+[0-9]|medium|FQ-012|Function returns both string and number -- unpredictable for callers|Return a consistent type or use discriminated unions'

  # FQ-013: God function indicator - too many assignments
  '^\s*(const|let|var)\s+\w+\s*=.*\n.*\n.*\n.*\n.*(const|let|var)\s+\w+\s*=.*\n.*\n.*\n.*\n.*(const|let|var)\s+\w+\s*=|critical|FQ-013|Function has many local variables -- may have too many responsibilities|Split into smaller focused functions, each handling one responsibility'

  # FQ-014: Go function with too many parameters
  'func\s+\w+\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)|high|FQ-014|Go function has 6+ parameters|Use a struct for options: func Create(opts CreateOpts) error'

  # FQ-015: Java method with too many parameters
  '(public|private|protected)\s+\w+\s+\w+\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)|high|FQ-015|Java method has 6+ parameters|Use a builder pattern or parameter object'

  # FQ-016: Ruby method with too many parameters
  'def\s+\w+\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*\)|high|FQ-016|Ruby method has 6+ parameters|Use keyword arguments or an options hash'

  # FQ-017: Deeply nested ternary
  '\?\s*[^:]+\?\s*[^:]+:|medium|FQ-017|Nested ternary expressions -- hard to read|Extract into if/else or a helper function for clarity'

  # FQ-018: Multiple nested try blocks
  'try\s*\{[^}]*try\s*\{|medium|FQ-018|Nested try blocks -- overly complex error handling|Extract inner try into a separate function with its own error handling'
)

# ═══════════════════════════════════════════════════════════════════════════════
# MAGIC NUMBERS & STRINGS (14 patterns: MN-001 through MN-014)
# ═══════════════════════════════════════════════════════════════════════════════

STYLEGUARD_MAGIC_PATTERNS=(
  # MN-001: Magic number in conditional (not 0, 1, -1, 2)
  'if\s*\(.*[=<>!]+\s*[3-9][0-9]+|medium|MN-001|Magic number in conditional -- unclear what this value represents|Extract to a named constant: const MAX_RETRIES = 10; if (retries >= MAX_RETRIES)'

  # MN-002: Magic number in Python conditional
  'if\s+.*[=<>!]+\s*[3-9][0-9]+|medium|MN-002|Magic number in Python conditional -- reduces readability|Extract to constant: MAX_RETRIES = 10; if retries >= MAX_RETRIES'

  # MN-003: Hardcoded timeout/delay value (JS/TS)
  'setTimeout\s*\([^,]+,\s*[0-9]{3,}\s*\)|medium|MN-003|Hardcoded timeout value -- magic number in setTimeout|Extract to constant: const DEBOUNCE_MS = 300; setTimeout(fn, DEBOUNCE_MS)'

  # MN-004: Hardcoded sleep value (Python)
  'time\.sleep\s*\(\s*[0-9]+\.?[0-9]*\s*\)|medium|MN-004|Hardcoded sleep value -- magic number in time.sleep()|Extract to constant: RETRY_DELAY_SECS = 5; time.sleep(RETRY_DELAY_SECS)'

  # MN-005: Hardcoded URL in logic (not config/env)
  '(https?://[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-z]{2,})["\x27]|high|MN-005|Hardcoded URL in source code -- fragile and hard to update|Move URL to environment variable or config file: process.env.API_URL'

  # MN-006: Hardcoded file path
  '["\x27](/[a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+["\x27])|high|MN-006|Hardcoded file path in source code -- fragile across environments|Move path to configuration or use path.join() with configurable base'

  # MN-007: Magic array index (>2)
  '\[\s*[3-9]\s*\]|\[\s*[1-9][0-9]+\s*\]|low|MN-007|Magic array index -- unclear what position represents|Use named constants or destructuring: const [,,, thirdItem] = arr'

  # MN-008: Hardcoded hex color in logic (not CSS/SCSS)
  '#[0-9a-fA-F]{6}["\x27]|low|MN-008|Hardcoded hex color code in logic file -- belongs in stylesheet or theme|Move to CSS variables, theme file, or design token: var(--primary-color)'

  # MN-009: Numeric HTTP status code without constant
  '(status|statusCode|code)\s*[=!]==?\s*(200|201|204|301|302|400|401|403|404|409|500|502|503)|medium|MN-009|Numeric HTTP status code -- use named constant for clarity|Use named constants: HTTP_OK, HTTP_NOT_FOUND, HTTP_INTERNAL_ERROR'

  # MN-010: HTTP status in response (JS/TS)
  '\.status\s*\(\s*(200|201|204|301|400|401|403|404|409|500|502|503)\s*\)|medium|MN-010|Magic HTTP status in .status() call|Use constants: res.status(HTTP_OK) or res.status(StatusCodes.OK)'

  # MN-011: Hardcoded port number
  'port\s*[=:]\s*[0-9]{4,5}|medium|MN-011|Hardcoded port number -- should be configurable|Use environment variable: process.env.PORT or config.port'

  # MN-012: Hardcoded retry count
  '(retry|retries|attempts|maxRetries)\s*[=<>]\s*[0-9]+|medium|MN-012|Hardcoded retry count -- should be configurable|Extract to config: const MAX_RETRIES = 3 or use environment variable'

  # MN-013: Magic number 86400 (seconds in day)
  '86400|medium|MN-013|Magic number 86400 (seconds in a day) -- use named constant|Define: SECONDS_PER_DAY = 86400 or DAY_IN_SECONDS = 24 * 60 * 60'

  # MN-014: Magic number 3600 (seconds in hour)
  '3600|medium|MN-014|Magic number 3600 (seconds in an hour) -- use named constant|Define: SECONDS_PER_HOUR = 3600 or HOUR_IN_SECONDS = 60 * 60'
)

# ═══════════════════════════════════════════════════════════════════════════════
# IMPORT & MODULE ORGANIZATION (16 patterns: IM-001 through IM-016)
# ═══════════════════════════════════════════════════════════════════════════════

STYLEGUARD_IMPORT_PATTERNS=(
  # IM-001: Mixed require and import in same file
  'require\s*\(["\x27]|high|IM-001|require() found -- mixing CommonJS and ES modules in same file|Standardize on import/export: replace require("x") with import x from "x"'

  # IM-002: Wildcard import (JS/TS)
  'import\s+\*\s+as\s+\w+\s+from|medium|IM-002|Wildcard import (import *) -- prevents tree-shaking and pollutes namespace|Import only what you need: import { specific } from "module"'

  # IM-003: Wildcard import (Python)
  'from\s+\w+\s+import\s+\*|medium|IM-003|Wildcard import (from x import *) -- pollutes namespace and hides origins|Import explicitly: from module import specific_function, AnotherThing'

  # IM-004: Deep relative import (3+ levels)
  'from\s+["\x27]\.\./\.\./\.\./|medium|IM-004|Deep relative import (3+ levels up) -- fragile and hard to follow|Use path aliases: import { x } from "@/components/x" or "~/components/x"'

  # IM-005: Deep relative import (Python)
  'from\s+\.\.\.\.|medium|IM-005|Deep relative import in Python (3+ levels) -- hard to navigate|Use absolute imports: from mypackage.module import thing'

  # IM-006: Circular import hint (importing from parent in child)
  'from\s+["\x27]\.\.\/index|critical|IM-006|Importing from parent index -- possible circular dependency|Restructure modules to avoid circular imports or use lazy imports'

  # IM-007: Circular import hint (Python __init__)
  'from\s+\.\s+import|critical|IM-007|Importing from package __init__ in submodule -- possible circular dependency|Use absolute imports or restructure to break the cycle'

  # IM-008: Side-effect import not at top (JS/TS)
  '^import\s+["\x27][^"]+["\x27]\s*;?\s*$|medium|IM-008|Side-effect import (import "module") -- should be at the top of imports|Move side-effect imports to the very top of the import block'

  # IM-009: Dynamic require (non-conditional)
  'require\s*\(\s*[^"\x27\s]|medium|IM-009|Dynamic require() with variable -- prevents static analysis and bundling|Use static import or dynamic import() with a string literal'

  # IM-010: Import after code (non-import at top)
  '^(const|let|var|function)\s.*\n.*^import\s|high|IM-010|Import statement after code -- all imports should be at the top|Move all import statements to the top of the file'

  # IM-011: Unused import indicator (imported but not found elsewhere)
  'import\s+\{\s*\w+\s+as\s+\w+\s*\}|low|IM-011|Aliased import -- verify the alias is actually used, not the original name|Ensure aliased name is used consistently; remove unused aliases'

  # IM-012: Python import not at top of file
  '^[^#\n].*\nimport\s|high|IM-012|Python import not at top of file -- PEP 8 requires imports at the top|Move all imports to the top of the file per PEP 8'

  # IM-013: Go dot import
  'import\s+\.\s+"|medium|IM-013|Go dot import -- pollutes local namespace and obscures origins|Use named imports: import "package" and qualify usage'

  # IM-014: Java star import
  'import\s+[a-z]+(\.[a-z]+)*\.\*\s*;|medium|IM-014|Java wildcard import -- unclear what is imported and may cause conflicts|Import specific classes: import java.util.List instead of java.util.*'

  # IM-015: Ruby require_relative deep path
  'require_relative\s+["\x27]\.\./\.\./\.\./|medium|IM-015|Deep require_relative path (3+ levels) in Ruby|Consider restructuring gem layout or using absolute require paths'

  # IM-016: Duplicate import pattern (same module imported twice)
  'import.*from\s+["\x27](\w+)["\x27].*\n.*import.*from\s+["\x27]\1["\x27]|high|IM-016|Same module imported on multiple lines -- merge imports|Combine into single import: import { a, b } from "module"'
)

# ═══════════════════════════════════════════════════════════════════════════════
# COMMENT & DOCUMENTATION STYLE (12 patterns: CM-001 through CM-012)
# ═══════════════════════════════════════════════════════════════════════════════

STYLEGUARD_COMMENT_PATTERNS=(
  # CM-001: TODO accumulation
  'TODO|medium|CM-001|TODO marker found -- accumulated TODOs indicate deferred work|Address or create a ticket for this TODO, then remove the marker'

  # CM-002: FIXME marker
  'FIXME|medium|CM-002|FIXME marker found -- indicates known bug or broken code|Fix the issue and remove the FIXME marker'

  # CM-003: HACK marker
  'HACK|medium|CM-003|HACK marker found -- indicates intentional workaround or technical debt|Refactor the hack into a proper solution or document why it is necessary'

  # CM-004: XXX marker
  'XXX|medium|CM-004|XXX marker found -- indicates problematic or dangerous code|Address the concern and remove the XXX marker'

  # CM-005: Commented-out code (JS/TS pattern)
  '^\s*//\s*(const|let|var|function|if|for|while|return|import)\s|medium|CM-005|Commented-out code -- dead code in comments clutters the file|Remove commented-out code; use version control to recover old code'

  # CM-006: Commented-out code (Python)
  '^\s*#\s*(def|class|import|from|if|for|while|return|try)\s|medium|CM-006|Commented-out Python code -- dead code in comments|Remove commented-out code; use git history to recover old versions'

  # CM-007: @ts-ignore usage
  '@ts-ignore|high|CM-007|@ts-ignore suppresses TypeScript type checking -- masks real type errors|Fix the type error instead of suppressing it; use @ts-expect-error if truly needed'

  # CM-008: @ts-expect-error without description
  '@ts-expect-error$|high|CM-008|@ts-expect-error without justification comment|Add explanation: @ts-expect-error -- reason why this suppression is needed'

  # CM-009: eslint-disable without justification
  'eslint-disable[^-]|medium|CM-009|eslint-disable without specific rule or justification|Use eslint-disable-next-line with specific rule: // eslint-disable-next-line no-unused-vars'

  # CM-010: Empty catch block (JS/TS)
  'catch\s*\([^)]*\)\s*\{\s*\}|high|CM-010|Empty catch block -- silently swallowing errors hides bugs|Log the error, re-throw, or add a comment explaining why it is intentionally ignored'

  # CM-011: Empty except block (Python)
  'except.*:\s*\n\s+pass\s*$|high|CM-011|Empty except/pass -- silently swallowing exceptions hides bugs|Log the exception, re-raise, or add a comment explaining the intentional suppression'

  # CM-012: Excessive inline comments (noise indicator)
  '^\s*\w.*\s+//\s+\w|low|CM-012|Inline comment -- excessive inline comments may indicate unclear code|Consider renaming variables or extracting logic to make code self-documenting'
)

# ═══════════════════════════════════════════════════════════════════════════════
# CODE CONSISTENCY (10 patterns: CC-001 through CC-010)
# ═══════════════════════════════════════════════════════════════════════════════

STYLEGUARD_CONSISTENCY_PATTERNS=(
  # CC-001: Mixed single and double quotes (JS/TS -- detection heuristic)
  'const\s+\w+\s*=\s*"[^"]+"|medium|CC-001|Double-quoted string -- check if single quotes used elsewhere in file|Standardize quote style across the file (prefer single quotes in JS/TS)'

  # CC-002: Mixed equality operators (== vs ===)
  '[^!=]==[^=]|high|CC-002|Loose equality (==) in JS/TS -- allows type coercion and unexpected behavior|Use strict equality (===) consistently throughout the codebase'

  # CC-003: != vs !== inconsistency
  '[^!]!=[^=]|high|CC-003|Loose inequality (!=) in JS/TS -- allows type coercion|Use strict inequality (!==) consistently'

  # CC-004: Mixed async patterns - callback with promise
  '\.then\s*\(.*\n.*callback\s*\(|high|CC-004|Mixed async patterns -- .then() and callback in same flow|Standardize on async/await: replace callbacks and .then() chains'

  # CC-005: Mixed async patterns - callback with async/await
  'async\s+function.*\n.*callback\s*\(|high|CC-005|Mixed async patterns -- async function using callbacks|Use await instead of callback pattern in async functions'

  # CC-006: Inconsistent null checks (null vs undefined vs falsy)
  '=== null|medium|CC-006|Explicit null check -- verify undefined is also handled|Use == null to check both null and undefined, or handle both explicitly'

  # CC-007: Inconsistent undefined check
  '=== undefined|medium|CC-007|Explicit undefined check -- may miss null values|Use == null to check both null and undefined, or use typeof === "undefined"'

  # CC-008: Mixed var and let/const
  '\bvar\s+\w+\s*=|high|CC-008|var declaration found -- var has function scope and hoisting issues|Replace var with const (preferred) or let for block-scoped declarations'

  # CC-009: Inconsistent trailing comma (object literal without trailing comma after last property)
  '[a-zA-Z0-9"]\s*\n\s*\}|low|CC-009|Object/array may lack trailing comma on last item|Add trailing commas for cleaner git diffs: { a: 1, b: 2, }'

  # CC-010: Inconsistent error handling (throw string vs Error)
  'throw\s+["\x27]|medium|CC-010|Throwing a string instead of Error object -- loses stack trace|Throw Error objects: throw new Error("message") for proper stack traces'
)
