#!/usr/bin/env bash
# SerdeLint -- Data Serialization & Encoding Anti-Pattern Definitions
# 90 patterns across 6 categories, 15 patterns each.
#
# Format per line:
#   REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Severity levels:
#   critical -- Immediate data integrity or security risk
#   high     -- Significant serialization problem requiring prompt attention
#   medium   -- Moderate concern that should be addressed in current sprint
#   low      -- Best practice suggestion or informational finding
#
# IMPORTANT: All regexes use POSIX ERE syntax (grep -E compatible).
# - Use [[:space:]] instead of \s
# - Use [[:alnum:]] instead of \w
# - NEVER use pipe (|) for alternation inside regex -- it conflicts with
#   the field delimiter. Use separate patterns or character classes instead.
# - Use \b-free alternatives where boundary assertions are unavailable
#
# Categories:
#   UP (Unsafe Parsing)        -- 15 patterns (UP-001 to UP-015)
#   EM (Encoding Mismatches)   -- 15 patterns (EM-001 to EM-015)
#   DL (Data Loss Patterns)    -- 15 patterns (DL-001 to DL-015)
#   SV (Schema Validation)     -- 15 patterns (SV-001 to SV-015)
#   FI (Format Interop)        -- 15 patterns (FI-001 to FI-015)
#   SO (Serialization Output)  -- 15 patterns (SO-001 to SO-015)

set -euo pipefail

# ============================================================================
# 1. UNSAFE PARSING (UP-001 through UP-015)
#    Detects JSON.parse without try/catch, eval() for parsing, yaml.load
#    without safe loader, XML parsing without entity disabled, pickle.loads
#    on untrusted data, unchecked deserialization.
# ============================================================================

declare -a SERDELINT_UP_PATTERNS=()

SERDELINT_UP_PATTERNS+=(
  # UP-001: JSON.parse without surrounding try/catch (bare call ending with semicolon)
  'JSON\.parse\([^)]*\)[[:space:]]*;|critical|UP-001|JSON.parse() without try/catch error handling|Wrap JSON.parse() in try/catch to handle malformed input gracefully'

  # UP-002: yaml.load() without Loader= parameter (Python unsafe YAML)
  'yaml\.load\([^)]*\)[[:space:]]*$|critical|UP-002|yaml.load() without Loader parameter (unsafe YAML deserialization)|Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) to prevent arbitrary code execution'

  # UP-003: pickle.load or pickle.loads (arbitrary code execution)
  'pickle\.loads\?[[:space:]]*\(|critical|UP-003|pickle.load/loads used for deserialization (arbitrary code execution risk)|Replace pickle with json, msgpack, or another safe serialization format for untrusted data'

  # UP-004: eval() used to parse data (code injection)
  'eval\([[:space:]]*[a-zA-Z_][[:alnum:]_]*[[:space:]]*\)|critical|UP-004|eval() used to parse data (code injection risk)|Replace eval() with JSON.parse(), yaml.safe_load(), or a proper parser'

  # UP-005: xml.etree parsing without defusedxml (XXE risk)
  'xml\.etree\.ElementTree|critical|UP-005|xml.etree.ElementTree used without defusedxml (XXE vulnerability)|Use defusedxml.ElementTree instead of xml.etree.ElementTree to prevent XXE attacks'

  # UP-006: DOMParser or parseFromString without sanitization
  'DOMParser\(\)\.parseFromString\(|high|UP-006|DOMParser.parseFromString() without input sanitization|Sanitize XML/HTML input before parsing with DOMParser to prevent injection attacks'

  # UP-007: xml2js or fast-xml-parser without entity expansion limits
  'xml2js\.parseString\(|high|UP-007|xml2js.parseString() without entity expansion protection|Configure xml2js with explicitArray and strict mode to prevent billion laughs attacks'

  # UP-008: yaml.load with FullLoader (partially unsafe)
  'yaml\.load\([^)]*FullLoader|high|UP-008|yaml.load() with FullLoader (partially unsafe deserialization)|Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) for untrusted input'

  # UP-009: Unvalidated JSON from request body parsed directly
  'JSON\.parse\([[:space:]]*req\.body|high|UP-009|JSON.parse() on raw request body without validation|Validate request body schema before parsing; use express.json() middleware with size limits'

  # UP-010: marshal.load in Ruby (unsafe deserialization)
  'Marshal\.load\(|critical|UP-010|Marshal.load() used for deserialization (arbitrary code execution in Ruby)|Use JSON.parse or MessagePack for untrusted data instead of Marshal'

  # UP-011: XMLReader without disabling external entities
  'XMLReader\(\)|high|UP-011|XMLReader instantiated without disabling external entity processing|Disable external entities: reader.setFeature(XMLReader.FEATURE_EXTERNAL_ENTITIES, false)'

  # UP-012: unserialize in PHP (object injection)
  'unserialize\([[:space:]]*\$|critical|UP-012|PHP unserialize() on user input (object injection vulnerability)|Use json_decode() instead of unserialize() for untrusted data'

  # UP-013: fromJson or JsonConvert without type constraints
  'JsonConvert\.DeserializeObject\([[:space:]]*[^<]|medium|UP-013|JsonConvert.DeserializeObject without type parameter (unsafe polymorphic deserialization)|Specify target type: JsonConvert.DeserializeObject<T>(data) to prevent type confusion'

  # UP-014: csv.reader without quoting or escapechar configuration
  'csv\.reader\([[:space:]]*[a-zA-Z]|medium|UP-014|csv.reader() without explicit quoting or delimiter configuration|Configure csv.reader with quoting=csv.QUOTE_ALL and explicit delimiter for robust parsing'

  # UP-015: TOML parsing without error handling
  'toml\.load\([^)]*\)[[:space:]]*$|medium|UP-015|TOML file parsed without error handling|Wrap toml.load() in try/except to handle malformed TOML files gracefully'
)

# ============================================================================
# 2. ENCODING MISMATCHES (EM-001 through EM-015)
#    Detects UTF-8/Latin-1 confusion, missing charset headers, Buffer.from
#    without encoding, atob/btoa misuse, mixed encoding in pipeline.
# ============================================================================

declare -a SERDELINT_EM_PATTERNS=()

SERDELINT_EM_PATTERNS+=(
  # EM-001: Buffer.from() without encoding parameter
  'Buffer\.from\([^,)]+\)[[:space:]]*[;]|high|EM-001|Buffer.from() without explicit encoding parameter|Specify encoding explicitly: Buffer.from(data, "utf-8") to prevent encoding ambiguity'

  # EM-002: atob() used for binary data (only handles Latin-1 subset)
  'atob\([[:space:]]*[a-zA-Z_]|high|EM-002|atob() used for base64 decoding (does not handle UTF-8 properly)|Use Buffer.from(data, "base64") in Node.js or TextDecoder for proper UTF-8 base64 decoding'

  # EM-003: btoa() used with non-ASCII content
  'btoa\([[:space:]]*[a-zA-Z_]|high|EM-003|btoa() used for base64 encoding (fails on non-Latin-1 characters)|Use Buffer.from(str).toString("base64") or TextEncoder for proper UTF-8 base64 encoding'

  # EM-004: .encode() without specifying encoding
  '\.encode\(\)[[:space:]]*$|medium|EM-004|String .encode() without explicit encoding parameter|Specify encoding explicitly: .encode("utf-8") to prevent platform-dependent defaults'

  # EM-005: .decode() without specifying encoding
  '\.decode\(\)[[:space:]]*$|medium|EM-005|Bytes .decode() without explicit encoding parameter|Specify encoding explicitly: .decode("utf-8") to prevent platform-dependent defaults'

  # EM-006: open() without encoding parameter (Python file reading)
  'open\([[:space:]]*["\x27][^"]*["\x27][[:space:]]*\)|medium|EM-006|File open() without explicit encoding parameter|Specify encoding: open(path, encoding="utf-8") to prevent system-locale-dependent reads'

  # EM-007: latin-1 or iso-8859-1 encoding in modern codebase
  'encoding[[:space:]]*=[[:space:]]*["\x27]latin|medium|EM-007|Latin-1/ISO-8859-1 encoding used (limited character support)|Use UTF-8 encoding unless legacy system compatibility is specifically required'

  # EM-008: Response without Content-Type charset
  'Content-Type.*application/json["\x27][[:space:]]*\)|medium|EM-008|Content-Type header for JSON without charset specification|Set Content-Type: application/json; charset=utf-8 for explicit encoding declaration'

  # EM-009: readFile without encoding (returns Buffer in Node.js)
  'readFile\([[:space:]]*["\x27][^"]*["\x27][[:space:]]*,[[:space:]]*function|high|EM-009|fs.readFile() without encoding parameter (returns raw Buffer)|Specify encoding: fs.readFile(path, "utf-8", callback) to get string instead of Buffer'

  # EM-010: readFileSync without encoding
  'readFileSync\([[:space:]]*["\x27][^"]*["\x27][[:space:]]*\)|high|EM-010|fs.readFileSync() without encoding parameter (returns raw Buffer)|Specify encoding: fs.readFileSync(path, "utf-8") to get string instead of Buffer'

  # EM-011: TextDecoder without encoding label
  'new[[:space:]]TextDecoder\(\)|low|EM-011|TextDecoder instantiated without explicit encoding label|Specify encoding: new TextDecoder("utf-8") for clarity even though utf-8 is the default'

  # EM-012: String concatenation of bytes and text
  '\.encode\(.*\+.*\.decode\(|high|EM-012|Mixed bytes and string operations (encoding boundary confusion)|Keep bytes and strings separate; decode bytes to strings at boundaries, not mid-pipeline'

  # EM-013: charCodeAt used for multi-byte character processing
  'charCodeAt\([[:space:]]*[0-9]|medium|EM-013|charCodeAt() used for character processing (does not handle multi-byte chars)|Use codePointAt() instead of charCodeAt() for proper Unicode code point handling'

  # EM-014: iconv or encoding conversion without error handling
  'iconv\.[a-z]*\([^)]*\)[[:space:]]*;|medium|EM-014|iconv encoding conversion without error handling|Wrap iconv conversions in try/catch and handle unmappable character errors'

  # EM-015: BOM (byte order mark) not handled in file reading
  'replace\([[:space:]]*["\x27]\\\\uFEFF["\x27]|low|EM-015|BOM stripping detected (indicates inconsistent file encoding)|Ensure all files use UTF-8 without BOM; add BOM handling at the ingestion boundary'
)

# ============================================================================
# 3. DATA LOSS PATTERNS (DL-001 through DL-015)
#    Detects floating-point for currency, integer overflow on deserialization,
#    truncated BigInt, lossy type coercion, silently dropped fields.
# ============================================================================

declare -a SERDELINT_DL_PATTERNS=()

SERDELINT_DL_PATTERNS+=(
  # DL-001: parseFloat on price/amount/currency values
  'parseFloat\([^)]*[Pp]rice|high|DL-001|parseFloat() used for currency/price values (floating-point precision loss)|Use integer cents, Decimal.js, or BigNumber for currency to avoid floating-point errors'

  # DL-002: parseFloat on amount values
  'parseFloat\([^)]*[Aa]mount|high|DL-002|parseFloat() used for monetary amount values (precision loss risk)|Use integer arithmetic in smallest currency unit (cents) or a decimal library'

  # DL-003: Number() coercion on large numeric strings (BigInt truncation)
  'Number\([^)]*[Ii]d\)|high|DL-003|Number() coercion on ID field (truncates integers beyond 2^53)|Use BigInt or keep large numeric IDs as strings to prevent precision loss'

  # DL-004: parseInt without radix parameter
  'parseInt\([^,)]*\)[[:space:]]*[;,]|medium|DL-004|parseInt() without radix parameter|Always specify radix: parseInt(value, 10) to prevent octal/hex misinterpretation'

  # DL-005: Floating-point equality comparison after deserialization
  '==[[:space:]]*[0-9]+\.[0-9]+|medium|DL-005|Floating-point equality comparison (unreliable after deserialization)|Use epsilon comparison: Math.abs(a - b) < epsilon for floating-point equality checks'

  # DL-006: toFixed() used for financial calculations
  '\.toFixed\([[:space:]]*[0-9]+[[:space:]]*\).*[Pp]rice|high|DL-006|toFixed() used in financial context (rounds and returns string)|Use a decimal library for financial math; toFixed() has rounding and type issues'

  # DL-007: JSON.stringify loses undefined values
  'JSON\.stringify\([^)]*undefined|medium|DL-007|JSON.stringify() serializing object with undefined values (silently dropped)|Remove or convert undefined values to null before JSON serialization to prevent data loss'

  # DL-008: Date object serialized without timezone info
  'JSON\.stringify\([^)]*new[[:space:]]Date|medium|DL-008|Date object serialized via JSON.stringify (timezone may be lost)|Use .toISOString() explicitly and ensure timezone is preserved in serialized dates'

  # DL-009: Truncation via Math.floor or Math.round on deserialized data
  'Math\.floor\([^)]*[Pp]rice|medium|DL-009|Math.floor() applied to price/currency value (truncates precision)|Use decimal arithmetic library for currency; Math.floor causes data loss on monetary values'

  # DL-010: Spread operator potentially dropping prototype fields
  '\.\.\.[a-zA-Z_][[:alnum:]_]*[[:space:]]*\}.*JSON|low|DL-010|Spread operator on object before JSON serialization (may lose non-enumerable properties)|Verify that all required fields are enumerable before using spread for serialization'

  # DL-011: Silent field filtering with destructuring before serialization
  'const[[:space:]]*\{[^}]*\.\.\.[a-zA-Z_]|low|DL-011|Destructuring with rest spread may silently filter fields before serialization|Document which fields are intentionally excluded to prevent accidental data loss'

  # DL-012: Unsigned integer overflow in deserialization
  '>>>[[:space:]]*0|medium|DL-012|Unsigned right shift used for integer conversion (may overflow on large values)|Use explicit range checks for deserialized integers to prevent silent overflow'

  # DL-013: String to number coercion in deserialized data
  '\+[[:space:]]*[a-zA-Z_][[:alnum:]_]*\.[a-zA-Z_]*[Ii]d|medium|DL-013|Unary plus used for ID type coercion (truncates large integers)|Keep IDs as strings or use BigInt for numeric IDs exceeding Number.MAX_SAFE_INTEGER'

  # DL-014: Array map with Number for type conversion
  '\.map\([[:space:]]*Number[[:space:]]*\)|medium|DL-014|Array.map(Number) coercion (loses precision for large values, NaN for non-numeric)|Validate array elements before numeric coercion; handle NaN and precision limits explicitly'

  # DL-015: Implicit toString in JSON key construction
  '\[[[:space:]]*[a-zA-Z_][[:alnum:]_]*\.[a-zA-Z_]*[Ii]d[[:space:]]*\][[:space:]]*=|low|DL-015|Object key from numeric ID (implicit toString may lose precision)|Convert large numeric IDs to string explicitly before using as object keys'
)

# ============================================================================
# 4. SCHEMA VALIDATION (SV-001 through SV-015)
#    Detects no schema validation on input JSON, missing required field checks,
#    accepting arbitrary shapes, no version checking on API payloads.
# ============================================================================

declare -a SERDELINT_SV_PATTERNS=()

SERDELINT_SV_PATTERNS+=(
  # SV-001: JSON.parse result used directly without validation
  'JSON\.parse\([^)]*\)\.[a-zA-Z]|high|SV-001|Accessing properties on JSON.parse() result without schema validation|Validate parsed JSON against a schema (Zod, Joi, Ajv) before accessing properties'

  # SV-002: Request body accessed without schema validation
  'req\.body\.[a-zA-Z_]+[[:space:]]*[;,]|high|SV-002|Request body field accessed without schema validation|Validate req.body against a schema before accessing fields to prevent shape errors'

  # SV-003: API response data accessed without type checking
  'response\.data\.[a-zA-Z_]+|medium|SV-003|API response data accessed without type checking|Validate API response shape with a schema or type guard before accessing nested fields'

  # SV-004: Deserialized config used without required field checks
  'config\.[a-zA-Z_]+[[:space:]]*=[[:space:]]*[a-zA-Z]*\.parse|medium|SV-004|Parsed configuration used without validating required fields|Validate all required config fields after deserialization before use'

  # SV-005: No version field check in API payload
  'JSON\.parse.*version[[:space:]]*=|low|SV-005|API payload consumed without checking version field|Check payload version to ensure compatibility and handle schema migration'

  # SV-006: Zod/Joi schema defined but not used at entry point
  'z\.object\([^)]*\)[[:space:]]*;[[:space:]]*$|low|SV-006|Schema object defined but may not be applied at data entry point|Apply .parse() or .validate() on incoming data at the boundary, not just define the schema'

  # SV-007: Type assertion (as Type) without runtime validation
  'as[[:space:]][A-Z][a-zA-Z]+[[:space:]]*[;,)]|medium|SV-007|TypeScript type assertion without runtime validation (unsafe cast)|Use a runtime schema validator (Zod, io-ts) instead of type assertions on external data'

  # SV-008: Dynamic property access on deserialized object
  '\[[[:space:]]*[a-zA-Z_]+[[:space:]]*\][[:space:]]*[;.]|medium|SV-008|Dynamic property access on deserialized data without existence check|Validate that expected properties exist before dynamic access; use optional chaining or hasOwnProperty'

  # SV-009: Optional chaining without fallback on critical fields
  '\?\.[a-zA-Z_]+\?\.[a-zA-Z_]+\?\.|low|SV-009|Deep optional chaining suggests missing schema validation on deserialized data|Validate data shape upfront instead of relying on deep optional chaining for every access'

  # SV-010: any type annotation on deserialized data
  ':[[:space:]]*any[[:space:]]*[=;)]|medium|SV-010|TypeScript "any" type on deserialized data (bypasses type safety)|Use proper type annotations with runtime validation for deserialized data'

  # SV-011: JSON schema not checked before database insert
  '\.insert\([[:space:]]*JSON\.parse|high|SV-011|JSON.parse result inserted into database without schema validation|Validate parsed data against schema before database insertion to prevent bad data'

  # SV-012: Missing Content-Type check before parsing
  'JSON\.parse\([[:space:]]*req\.[a-z]|medium|SV-012|Parsing request data without Content-Type verification|Check Content-Type header matches expected format before parsing request body'

  # SV-013: Accepting unknown fields without stripping
  'Object\.assign\([[:space:]]*\{[[:space:]]*\}[[:space:]]*,[[:space:]]*req\.body|medium|SV-013|Object.assign spreading request body without field allowlisting|Use explicit field extraction or schema validation to prevent unexpected field injection'

  # SV-014: Environment variable parsed as JSON without validation
  'JSON\.parse\([[:space:]]*process\.env\.|medium|SV-014|Parsing environment variable as JSON without validation|Validate JSON from environment variables against expected schema before use'

  # SV-015: GraphQL input used without type validation
  'args\.[a-zA-Z_]+[[:space:]]*[;,]|low|SV-015|GraphQL args accessed without additional input validation|Add runtime validation on GraphQL resolver arguments beyond schema type checking'
)

# ============================================================================
# 5. FORMAT INTEROP (FI-001 through FI-015)
#    Detects JSON-to-XML round-trip issues, CSV without proper quoting,
#    YAML type coercion gotchas, date format ambiguity across formats.
# ============================================================================

declare -a SERDELINT_FI_PATTERNS=()

SERDELINT_FI_PATTERNS+=(
  # FI-001: JSON to XML conversion without attribute handling
  'json2xml\([^)]*\)|high|FI-001|JSON-to-XML conversion without attribute mapping strategy|Configure attribute prefixes and text node handling for lossless JSON-to-XML conversion'

  # FI-002: XML to JSON conversion without array normalization
  'xml2json\([^)]*\)|high|FI-002|XML-to-JSON conversion without array normalization (single vs array ambiguity)|Configure xml2json with explicitArray:true to ensure consistent array handling'

  # FI-003: CSV field without proper quoting for special characters
  'join\([[:space:]]*["\x27],["\x27]|medium|FI-003|CSV fields joined with comma without proper quoting (special characters will break)|Use a CSV library with proper RFC 4180 quoting instead of manual comma-join'

  # FI-004: YAML boolean coercion (yes/no/on/off become boolean)
  '["\x27]yes["\x27][[:space:]]*:[[:space:]]|medium|FI-004|YAML value "yes" may be coerced to boolean true|Quote string values in YAML that match boolean patterns: "yes", "no", "on", "off"'

  # FI-005: Date string without ISO 8601 format in data interchange
  'new[[:space:]]Date\([[:space:]]*["\x27][0-9][0-9]/|high|FI-005|Date parsed from locale-dependent format (MM/DD ambiguity)|Use ISO 8601 format (YYYY-MM-DD) for date interchange between systems'

  # FI-006: CSV parsing without handling embedded newlines
  '\.split\([[:space:]]*["\x27]\\n["\x27]\)|medium|FI-006|CSV split on newline without handling quoted fields with embedded newlines|Use a proper CSV parser (papaparse, csv-parse) that handles RFC 4180 multiline fields'

  # FI-007: YAML to JSON without handling anchors and aliases
  'yaml\..*toJSON\(|medium|FI-007|YAML-to-JSON conversion may not preserve anchor/alias references|Handle YAML anchors and aliases explicitly during conversion to prevent reference loss'

  # FI-008: JSON null vs missing field semantic difference lost
  'delete[[:space:]][a-zA-Z_]+\.[a-zA-Z_]+.*JSON\.stringify|medium|FI-008|Deleting properties before JSON.stringify (null vs absent semantic difference)|Use null instead of delete for optional fields to preserve explicit null semantics in JSON'

  # FI-009: Protobuf default values indistinguishable from unset
  'proto[a-zA-Z]*\.[a-zA-Z]+[[:space:]]*==[[:space:]]*0|medium|FI-009|Protobuf field compared to default value (0/empty may mean unset)|Use has_field() or wrapper types in Protobuf to distinguish default values from unset fields'

  # FI-010: MessagePack timestamp handling inconsistency
  'msgpack\.[a-z]*pack\([^)]*[Dd]ate|medium|FI-010|Date object passed to MessagePack without explicit timestamp extension|Use MessagePack timestamp extension type for dates to ensure cross-platform compatibility'

  # FI-011: Mixed date formats in the same codebase
  'moment\([^)]*["\x27][A-Z]{2,4}/|low|FI-011|Locale-dependent date format string used in data parsing|Standardize on ISO 8601 date format across all serialization boundaries'

  # FI-012: CSV without header row detection
  '\.parse\([^)]*\{[^}]*header[[:space:]]*:[[:space:]]*false|low|FI-012|CSV parsing with headers disabled (column mapping depends on position)|Enable header row parsing or document column positions to prevent mapping errors'

  # FI-013: JSON5 or JSONC used for data interchange
  'JSON5\.parse\(|medium|FI-013|JSON5 used for data interchange (non-standard, may not be supported by consumers)|Use standard JSON for data interchange; restrict JSON5 to configuration files only'

  # FI-014: XML namespace handling missing in conversion
  'xmlns[[:space:]]*=[[:space:]]*["\x27]|low|FI-014|XML namespace detected but may not be preserved during format conversion|Ensure XML namespaces are mapped correctly when converting to JSON or other formats'

  # FI-015: Binary data encoded as JSON string without format marker
  'JSON\.stringify\([^)]*[Bb]uffer|high|FI-015|Buffer/binary data serialized via JSON.stringify without base64 encoding|Convert binary data to base64 string before JSON serialization for safe transport'
)

# ============================================================================
# 6. SERIALIZATION OUTPUT (SO-001 through SO-015)
#    Detects circular reference risk, unbounded serialization depth, missing
#    content-type header, pretty-printing in production, serializing sensitive fields.
# ============================================================================

declare -a SERDELINT_SO_PATTERNS=()

SERDELINT_SO_PATTERNS+=(
  # SO-001: JSON.stringify without circular reference check
  'JSON\.stringify\([[:space:]]*[a-zA-Z_][[:alnum:]_]*[[:space:]]*\)[[:space:]]*;|high|SO-001|JSON.stringify() without replacer (circular reference risk)|Add a replacer function or use a safe serializer (flatted, safe-stable-stringify) to handle circular refs'

  # SO-002: JSON.stringify with pretty-printing in production response
  'JSON\.stringify\([^)]*,[[:space:]]*null[[:space:]]*,[[:space:]]*[24][[:space:]]*\)|medium|SO-002|JSON.stringify with indentation in response (wasteful in production)|Remove pretty-printing in production responses to reduce payload size and bandwidth'

  # SO-003: Serializing password or secret fields
  'JSON\.stringify\([^)]*[Pp]assword|critical|SO-003|Object containing password field being serialized|Exclude sensitive fields (password, secret, token) from serialization output'

  # SO-004: Serializing token or API key fields
  'JSON\.stringify\([^)]*[Tt]oken|critical|SO-004|Object containing token field being serialized|Strip token/apiKey fields before serialization to prevent credential exposure'

  # SO-005: Response without Content-Type header for JSON
  'res\.send\([[:space:]]*JSON\.stringify|high|SO-005|JSON sent via res.send() without Content-Type header|Use res.json() instead of res.send(JSON.stringify()) for automatic Content-Type headers'

  # SO-006: Unbounded toJSON or serialize method
  'toJSON\(\)[[:space:]]*\{[[:space:]]*return[[:space:]]*this|medium|SO-006|toJSON() returns this (circular reference and unbounded depth risk)|Return a plain object with selected fields from toJSON() instead of this'

  # SO-007: YAML.dump without default_flow_style or sort_keys
  'yaml\.dump\([[:space:]]*[a-zA-Z_]|low|SO-007|yaml.dump() without explicit formatting options|Configure yaml.dump(data, default_flow_style=False, sort_keys=True) for consistent output'

  # SO-008: Serializing stack traces in API responses
  'JSON\.stringify\([^)]*[Ss]tack|high|SO-008|Stack trace included in serialized response (information leakage)|Remove stack traces from production API responses; log them server-side only'

  # SO-009: Serializing user object with all fields
  'res\.json\([[:space:]]*user[[:space:]]*\)|high|SO-009|Full user object serialized in response (may expose sensitive data)|Use a DTO or select specific fields instead of serializing the full user object'

  # SO-010: No max depth or size limit on serialization
  'JSON\.stringify\([[:space:]]*req\.|medium|SO-010|Serializing request object without depth/size limits (potential DoS)|Limit serialization depth and output size to prevent memory exhaustion on large payloads'

  # SO-011: Serializing error objects (may expose internals)
  'JSON\.stringify\([^)]*[Ee]rror|medium|SO-011|Error object being serialized (may expose internal details)|Create a safe error DTO with code and message only; exclude stack and internal fields'

  # SO-012: XML serialization without proper escaping
  '<[a-zA-Z]+>[[:space:]]*["\x27][[:space:]]*\+[[:space:]]*[a-zA-Z_]|high|SO-012|Manual XML construction via string concatenation (injection risk)|Use an XML builder library with proper escaping instead of string concatenation'

  # SO-013: CSV output without escaping special characters
  '\.join\([[:space:]]*["\x27],["\x27][[:space:]]*\).*\.(csv|write)|medium|SO-013|CSV output via array.join without field escaping|Use a CSV writer library that handles quoting, escaping, and RFC 4180 compliance'

  # SO-014: Serializing database model directly
  'res\.json\([[:space:]]*await[[:space:]][a-zA-Z]+\.[a-z]+\(|medium|SO-014|Database query result serialized directly in response|Map database models to DTOs before serialization to control exposed fields'

  # SO-015: Serializing secret or apiKey fields in logs
  'console\.log\([^)]*JSON\.stringify\([^)]*[Ss]ecret|critical|SO-015|Object with secret field serialized to console log|Redact sensitive fields before logging; use a structured logger with field filtering'
)

# ============================================================================
# Utility Functions
# ============================================================================

# Get total pattern count across all categories
serdelint_pattern_count() {
  local count=0
  count=$((count + ${#SERDELINT_UP_PATTERNS[@]}))
  count=$((count + ${#SERDELINT_EM_PATTERNS[@]}))
  count=$((count + ${#SERDELINT_DL_PATTERNS[@]}))
  count=$((count + ${#SERDELINT_SV_PATTERNS[@]}))
  count=$((count + ${#SERDELINT_FI_PATTERNS[@]}))
  count=$((count + ${#SERDELINT_SO_PATTERNS[@]}))
  echo "$count"
}

# Get pattern count for a specific category
serdelint_category_count() {
  local category="$1"
  local patterns_name
  patterns_name=$(get_serdelint_patterns_for_category "$category")
  if [[ -z "$patterns_name" ]]; then
    echo 0
    return
  fi
  local -n _ref="$patterns_name"
  echo "${#_ref[@]}"
}

# Get patterns array name for a category
get_serdelint_patterns_for_category() {
  local category="$1"
  case "$category" in
    UP|up) echo "SERDELINT_UP_PATTERNS" ;;
    EM|em) echo "SERDELINT_EM_PATTERNS" ;;
    DL|dl) echo "SERDELINT_DL_PATTERNS" ;;
    SV|sv) echo "SERDELINT_SV_PATTERNS" ;;
    FI|fi) echo "SERDELINT_FI_PATTERNS" ;;
    SO|so) echo "SERDELINT_SO_PATTERNS" ;;
    *)     echo "" ;;
  esac
}

# Get the human-readable label for a category
get_serdelint_category_label() {
  local category="$1"
  case "$category" in
    UP|up) echo "Unsafe Parsing" ;;
    EM|em) echo "Encoding Mismatches" ;;
    DL|dl) echo "Data Loss Patterns" ;;
    SV|sv) echo "Schema Validation" ;;
    FI|fi) echo "Format Interop" ;;
    SO|so) echo "Serialization Output" ;;
    *)     echo "$category" ;;
  esac
}

# All category codes for iteration
get_all_serdelint_categories() {
  echo "UP EM DL SV FI SO"
}

# Get categories available for a given tier level
# free=0 -> UP, EM (30 patterns)
# pro=1  -> UP, EM, DL, SV (60 patterns)
# team=2 -> all 6 (90 patterns)
# enterprise=3 -> all 6 (90 patterns)
get_serdelint_categories_for_tier() {
  local tier_level="${1:-0}"
  if [[ "$tier_level" -ge 2 ]]; then
    echo "UP EM DL SV FI SO"
  elif [[ "$tier_level" -ge 1 ]]; then
    echo "UP EM DL SV"
  else
    echo "UP EM"
  fi
}

# Severity to numeric points for scoring
severity_to_points() {
  case "$1" in
    critical) echo 25 ;;
    high)     echo 15 ;;
    medium)   echo 8 ;;
    low)      echo 3 ;;
    *)        echo 0 ;;
  esac
}

# List patterns by category
serdelint_list_patterns() {
  local filter_category="${1:-all}"

  if [[ "$filter_category" == "all" ]]; then
    for cat in UP EM DL SV FI SO; do
      serdelint_list_patterns "$cat"
    done
    return
  fi

  local patterns_name
  patterns_name=$(get_serdelint_patterns_for_category "$filter_category")
  if [[ -z "$patterns_name" ]]; then
    echo "Unknown category: $filter_category"
    return 1
  fi

  local -n _patterns_ref="$patterns_name"
  local label
  label=$(get_serdelint_category_label "$filter_category")

  echo "  ${label} (${filter_category}):"
  for entry in "${_patterns_ref[@]}"; do
    IFS='|' read -r regex severity check_id description recommendation <<< "$entry"
    printf "    %-8s %-10s %s\n" "$check_id" "$severity" "$description"
  done
  echo ""
}

# Validate that a category code is valid
is_valid_serdelint_category() {
  local category="$1"
  case "$category" in
    UP|up|EM|em|DL|dl|SV|sv|FI|fi|SO|so) return 0 ;;
    *) return 1 ;;
  esac
}
