#!/usr/bin/env bash
# SecretScan -- Secret Detection Pattern Definitions
# Each pattern: REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
#
# Severity levels:
#   critical -- Hardcoded secrets that can compromise infrastructure immediately
#   high     -- Credentials or tokens that enable unauthorized access
#   medium   -- Potentially sensitive values, config secrets, entropy matches
#   low      -- Informational, possible false positives, weak patterns
#
# IMPORTANT: All regexes must use POSIX ERE syntax (grep -E compatible).
# - Use [[:space:]] instead of \s
# - Use [[:alnum:]] instead of \w
# - Avoid Perl-only features (\d, \w, etc.)
#
# Patterns starting with PLACEHOLDER_ are handled by file-level checks
# in analyzer.sh, not by direct grep matching.

set -euo pipefail

# ============================================================================
# 1. API KEYS & TOKENS (SK-001 through SK-025)
# ============================================================================

declare -a SECRETSCAN_APIKEY_PATTERNS=()

SECRETSCAN_APIKEY_PATTERNS+=(
  # --- AWS Access Key IDs ---
  'AKIA[0-9A-Z]{16}|critical|SK-001|AWS Access Key ID detected (AKIA prefix)|Rotate the AWS key immediately and use IAM roles or environment variables instead'

  # --- GitHub Personal Access Tokens ---
  'ghp_[0-9a-zA-Z]{36}|critical|SK-002|GitHub Personal Access Token detected (ghp_ prefix)|Revoke the token at github.com/settings/tokens and use environment variables'

  # --- GitHub OAuth Access Tokens ---
  'gho_[0-9a-zA-Z]{36}|critical|SK-003|GitHub OAuth Access Token detected (gho_ prefix)|Revoke the token and configure OAuth flow to use secure token storage'

  # --- GitHub App Installation Tokens ---
  'ghs_[0-9a-zA-Z]{36}|critical|SK-004|GitHub App Installation Token detected (ghs_ prefix)|Revoke and regenerate the token; store in a secrets manager'

  # --- GitHub Fine-Grained PATs ---
  'github_pat_[0-9a-zA-Z_]{82}|critical|SK-005|GitHub Fine-Grained Personal Access Token detected|Revoke at github.com/settings/tokens and use environment variables'

  # --- Stripe Live Secret Keys ---
  'sk_live_[0-9a-zA-Z]{24,}|critical|SK-006|Stripe Live Secret Key detected (sk_live_ prefix)|Rotate at dashboard.stripe.com/apikeys; never commit live keys'

  # --- Stripe Test Secret Keys ---
  'sk_test_[0-9a-zA-Z]{24,}|high|SK-007|Stripe Test Secret Key detected (sk_test_ prefix)|Move test keys to environment variables; avoid committing even test keys'

  # --- Stripe Restricted Keys ---
  'rk_live_[0-9a-zA-Z]{24,}|critical|SK-008|Stripe Live Restricted Key detected|Rotate at dashboard.stripe.com/apikeys; use environment variables'

  # --- Google API Keys ---
  'AIza[0-9A-Za-z_-]{35}|high|SK-009|Google API Key detected (AIza prefix)|Restrict the key in Google Cloud Console and move to environment variables'

  # --- Slack Bot Tokens ---
  'xoxb-[0-9]{10,}-[0-9a-zA-Z]{24,}|critical|SK-010|Slack Bot Token detected (xoxb- prefix)|Revoke at api.slack.com and store in a secrets manager'

  # --- Slack User Tokens ---
  'xoxp-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{24,}|critical|SK-011|Slack User Token detected (xoxp- prefix)|Revoke at api.slack.com and use OAuth flow with secure storage'

  # --- Slack Webhook URLs ---
  'hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}|high|SK-012|Slack Webhook URL detected|Regenerate the webhook and store in environment variables'

  # --- npm Access Tokens ---
  'npm_[0-9a-zA-Z]{36}|high|SK-013|npm Access Token detected (npm_ prefix)|Revoke at npmjs.com/settings/tokens and use environment variables'

  # --- PyPI API Tokens ---
  'pypi-[0-9a-zA-Z_-]{16,}|high|SK-014|PyPI API Token detected (pypi- prefix)|Revoke at pypi.org/manage/account/token and use environment variables'

  # --- Twilio Account SID ---
  'AC[0-9a-f]{32}|high|SK-015|Twilio Account SID detected (AC prefix)|Move to environment variables; SID alone is not secret but indicates Twilio usage'

  # --- Twilio Auth Token pattern ---
  'twilio.*[0-9a-f]{32}|high|SK-016|Possible Twilio Auth Token detected|Rotate at twilio.com/console and store in environment variables'

  # --- SendGrid API Keys ---
  'SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}|critical|SK-017|SendGrid API Key detected (SG. prefix)|Revoke at app.sendgrid.com/settings/api_keys and use environment variables'

  # --- Mailgun API Keys ---
  'key-[0-9a-zA-Z]{32}|high|SK-018|Possible Mailgun API Key detected (key- prefix)|Rotate the key and move to environment variables'

  # --- HuggingFace Tokens ---
  'hf_[0-9a-zA-Z]{34}|high|SK-019|HuggingFace Access Token detected (hf_ prefix)|Revoke at huggingface.co/settings/tokens and use environment variables'

  # --- OpenAI API Keys ---
  'sk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20}|critical|SK-020|OpenAI API Key detected (sk-...T3BlbkFJ pattern)|Rotate at platform.openai.com/api-keys and use environment variables'

  # --- Anthropic API Keys ---
  'sk-ant-[0-9a-zA-Z_-]{80,}|critical|SK-021|Anthropic API Key detected (sk-ant- prefix)|Rotate at console.anthropic.com and use environment variables'

  # --- Firebase API Keys ---
  'AIza[0-9A-Za-z_-]{35}|high|SK-022|Firebase/Google API Key detected|Restrict the key in Firebase Console and move to environment variables'

  # --- Algolia API Keys ---
  'ALGOLIA[_-]?API[_-]?KEY.*[0-9a-f]{32}|high|SK-023|Algolia API Key assignment detected|Move to environment variables; restrict key permissions in Algolia dashboard'

  # --- Mapbox Access Tokens ---
  'pk\.[0-9a-zA-Z]{60,}|high|SK-024|Mapbox Public Access Token detected (pk. prefix)|Rotate at mapbox.com/account/access-tokens and scope token permissions'

  # --- Datadog API Keys ---
  'dd[_-]?api[_-]?key.*[0-9a-f]{32}|high|SK-025|Datadog API Key assignment detected|Rotate at app.datadoghq.com and store in environment variables'
)

# ============================================================================
# 2. PASSWORDS & CREDENTIALS (PW-001 through PW-020)
# ============================================================================

declare -a SECRETSCAN_PASSWORD_PATTERNS=()

SECRETSCAN_PASSWORD_PATTERNS+=(
  # --- Password assignments (double quotes) ---
  'password[[:space:]]*=[[:space:]]*"[^"]{4,}"|critical|PW-001|Hardcoded password in double-quoted string assignment|Remove the hardcoded password; use environment variables or a secrets manager'

  # --- Password assignments (single quotes) ---
  "password[[:space:]]*=[[:space:]]*'[^']{4,}'|critical|PW-002|Hardcoded password in single-quoted string assignment|Remove the hardcoded password; use environment variables or a secrets manager"

  # --- passwd assignments ---
  'passwd[[:space:]]*=[[:space:]]*"[^"]{4,}"|critical|PW-003|Hardcoded passwd value detected|Remove the hardcoded password and use secure credential storage'

  # --- secret assignments (double quotes) ---
  'secret[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|PW-004|Hardcoded secret value in string assignment|Move the secret to environment variables or a secrets manager'

  # --- credential assignments ---
  'credential[s]?[[:space:]]*=[[:space:]]*"[^"]{4,}"|critical|PW-005|Hardcoded credential value detected|Remove and use a secrets manager or environment variables'

  # --- auth_token assignments ---
  'auth[_-]?token[[:space:]]*=[[:space:]]*"[^"]{8,}"|critical|PW-006|Hardcoded auth token in string assignment|Rotate the token and store in environment variables'

  # --- api_key assignments (generic) ---
  'api[_-]?key[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|PW-007|Hardcoded API key in string assignment|Move the API key to environment variables or a secrets manager'

  # --- api_secret assignments ---
  'api[_-]?secret[[:space:]]*=[[:space:]]*"[^"]{8,}"|critical|PW-008|Hardcoded API secret in string assignment|Rotate the secret and store in environment variables'

  # --- Basic auth headers ---
  'Authorization.*Basic[[:space:]]+[A-Za-z0-9+/=]{10,}|critical|PW-009|Hardcoded Basic Authentication header with encoded credentials|Remove hardcoded auth header; use runtime credential injection'

  # --- Bearer token headers ---
  'Authorization.*Bearer[[:space:]]+[A-Za-z0-9._-]{20,}|critical|PW-010|Hardcoded Bearer token in Authorization header|Remove hardcoded token; inject at runtime from secrets manager'

  # --- .env patterns committed to source ---
  '^[A-Z_]{2,}=["'"'"']?[A-Za-z0-9+/=_-]{16,}["'"'"']?[[:space:]]*$|high|PW-011|Possible .env value with long secret committed to source|Move to .env file excluded from version control via .gitignore'

  # --- JDBC connection strings with passwords ---
  'jdbc:[a-z]+://[^[:space:]]*password=[^&[:space:]]{4,}|critical|PW-012|JDBC connection string with embedded password|Use connection pooling with externalized credentials; never embed passwords in URLs'

  # --- MongoDB URIs with credentials ---
  'mongodb(\+srv)?://[^:[:space:]]+:[^@[:space:]]+@[^[:space:]]+|critical|PW-013|MongoDB connection URI with embedded credentials|Use environment variables for MongoDB credentials; never embed in code'

  # --- Redis URLs with passwords ---
  'redis://:[^@[:space:]]+@[^[:space:]]+|critical|PW-014|Redis URL with embedded password|Use environment variables for Redis credentials'

  # --- PostgreSQL connection strings ---
  'postgres(ql)?://[^:[:space:]]+:[^@[:space:]]+@[^[:space:]]+|critical|PW-015|PostgreSQL connection string with embedded credentials|Use environment variables for database credentials'

  # --- MySQL connection strings ---
  'mysql://[^:[:space:]]+:[^@[:space:]]+@[^[:space:]]+|critical|PW-016|MySQL connection string with embedded credentials|Use environment variables for database credentials'

  # --- Generic database URL with credentials ---
  'DATABASE_URL.*://[^:[:space:]]+:[^@[:space:]]+@|critical|PW-017|DATABASE_URL with embedded credentials|Move to .env file and use environment variables'

  # --- Password in URL query parameter ---
  '[?&]password=[^&[:space:]]{4,}|high|PW-018|Password in URL query parameter|Remove password from URL; use secure authentication flow'

  # --- SMTP credentials ---
  'smtp://[^:[:space:]]+:[^@[:space:]]+@[^[:space:]]+|critical|PW-019|SMTP URL with embedded credentials|Use environment variables for SMTP credentials'

  # --- LDAP bind passwords ---
  'ldap(s)?://[^:[:space:]]+:[^@[:space:]]+@[^[:space:]]+|critical|PW-020|LDAP URL with embedded bind password|Use environment variables for LDAP credentials'
)

# ============================================================================
# 3. PRIVATE KEYS & CERTIFICATES (PK-001 through PK-015)
# ============================================================================

declare -a SECRETSCAN_PRIVKEY_PATTERNS=()

SECRETSCAN_PRIVKEY_PATTERNS+=(
  # --- RSA Private Key ---
  'BEGIN RSA PRIVATE KEY|critical|PK-001|RSA private key detected in source code|Remove the private key immediately; use a secrets manager or key vault'

  # --- EC Private Key ---
  'BEGIN EC PRIVATE KEY|critical|PK-002|EC (Elliptic Curve) private key detected in source code|Remove the private key; store in a key vault or HSM'

  # --- DSA Private Key ---
  'BEGIN DSA PRIVATE KEY|critical|PK-003|DSA private key detected in source code|Remove the private key; use modern key types (EC/RSA) stored securely'

  # --- OpenSSH Private Key ---
  'BEGIN OPENSSH PRIVATE KEY|critical|PK-004|OpenSSH private key detected in source code|Remove the SSH key; use ssh-agent or key vault instead'

  # --- Generic Private Key ---
  'BEGIN PRIVATE KEY|critical|PK-005|Generic PKCS#8 private key detected in source code|Remove the private key; store in a secrets manager'

  # --- Encrypted Private Key ---
  'BEGIN ENCRYPTED PRIVATE KEY|high|PK-006|Encrypted private key detected in source code|Even encrypted keys should not be in source; use a key vault'

  # --- PGP Private Key ---
  'BEGIN PGP PRIVATE KEY BLOCK|critical|PK-007|PGP private key block detected in source code|Remove the PGP key; store in a key management system'

  # --- Certificate (in code files, not .pem) ---
  'BEGIN CERTIFICATE|medium|PK-008|X.509 certificate detected in source code|Move certificates to a dedicated cert store or config management'

  # --- SSH private key content (base64 body) ---
  'PLACEHOLDER_SSH_KEY_CONTENT|critical|PK-009|SSH private key content detected (base64 body pattern)|Remove the SSH key file from source control immediately'

  # --- PKCS12/PFX password patterns ---
  'pfx[_-]?password[[:space:]]*=[[:space:]]*"[^"]+"|high|PK-010|PFX/PKCS12 keystore password hardcoded|Move the keystore password to environment variables'

  # --- Java KeyStore password ---
  'keystore[_-]?password[[:space:]]*=[[:space:]]*"[^"]+"|high|PK-011|Java KeyStore password hardcoded|Move the keystore password to environment variables'

  # --- Truststore password ---
  'truststore[_-]?password[[:space:]]*=[[:space:]]*"[^"]+"|high|PK-012|Truststore password hardcoded|Move the truststore password to environment variables'

  # --- SSL key password ---
  'ssl[_-]?key[_-]?password[[:space:]]*=[[:space:]]*"[^"]+"|high|PK-013|SSL key password hardcoded|Move the SSL key password to environment variables'

  # --- PEM file content embedded in source ---
  'PLACEHOLDER_PEM_CONTENT_INLINE|critical|PK-014|PEM-encoded key content embedded in string literal|Extract to a file and load at runtime; never embed key material in code'

  # --- PKCS8 key format ---
  'BEGIN (RSA |EC )?PRIVATE KEY|critical|PK-015|Private key header detected (PKCS format)|Remove the private key from source code; use a key vault'
)

# ============================================================================
# 4. CLOUD & INFRASTRUCTURE (CL-001 through CL-020)
# ============================================================================

declare -a SECRETSCAN_CLOUD_PATTERNS=()

SECRETSCAN_CLOUD_PATTERNS+=(
  # --- AWS Secret Access Keys ---
  'aws[_-]?secret[_-]?access[_-]?key[[:space:]]*=[[:space:]]*"?[A-Za-z0-9/+=]{40}"?|critical|CL-001|AWS Secret Access Key assignment detected|Rotate the key in AWS IAM immediately; use IAM roles or env vars'

  # --- AWS Secret Key (generic assignment) ---
  'AWS_SECRET_ACCESS_KEY[[:space:]]*=[[:space:]]*[A-Za-z0-9/+=]{40}|critical|CL-002|AWS_SECRET_ACCESS_KEY environment variable with key value|Remove hardcoded key; use IAM roles, instance profiles, or AWS Secrets Manager'

  # --- Azure Storage Account Keys ---
  'AccountKey=[A-Za-z0-9+/=]{44,}|critical|CL-003|Azure Storage Account Key detected|Rotate in Azure Portal; use Managed Identity or Key Vault references'

  # --- Azure Connection Strings ---
  'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,}|critical|CL-004|Azure Storage connection string with embedded account key|Use Key Vault references or Managed Identity instead of connection strings'

  # --- GCP Service Account JSON key pattern ---
  '"type"[[:space:]]*:[[:space:]]*"service_account"|critical|CL-005|GCP Service Account JSON key file content detected|Remove the key file from source; use Workload Identity or env-based credentials'

  # --- GCP private_key_id ---
  '"private_key_id"[[:space:]]*:[[:space:]]*"[a-f0-9]{40}"|critical|CL-006|GCP Service Account private_key_id detected|Remove the service account key file from source control'

  # --- Heroku API Keys ---
  'HEROKU_API_KEY[[:space:]]*=[[:space:]]*[0-9a-f-]{36,}|high|CL-007|Heroku API Key assignment detected|Rotate at dashboard.heroku.com and use environment variables'

  # --- Heroku API key pattern ---
  'heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|high|CL-008|Possible Heroku API Key (UUID pattern) detected|Verify and rotate at dashboard.heroku.com'

  # --- DigitalOcean Personal Access Tokens ---
  'dop_v1_[0-9a-f]{64}|critical|CL-009|DigitalOcean Personal Access Token detected|Revoke at cloud.digitalocean.com/account/api/tokens and use env vars'

  # --- DigitalOcean OAuth Tokens ---
  'doo_v1_[0-9a-f]{64}|critical|CL-010|DigitalOcean OAuth Token detected|Revoke and regenerate the token; store in environment variables'

  # --- Cloudflare API Tokens ---
  'cloudflare.*[0-9a-zA-Z_-]{40}|high|CL-011|Possible Cloudflare API Token detected|Rotate at dash.cloudflare.com/profile/api-tokens and use env vars'

  # --- Cloudflare Global API Key ---
  'CF_API_KEY[[:space:]]*=[[:space:]]*[0-9a-f]{37}|critical|CL-012|Cloudflare Global API Key detected|Rotate and migrate to scoped API tokens stored in env vars'

  # --- Terraform state with secrets ---
  'PLACEHOLDER_TERRAFORM_STATE_SECRET|high|CL-013|Terraform state file with potential secrets detected|Encrypt Terraform state; use remote state with access controls'

  # --- Docker registry passwords ---
  'docker[_-]?password[[:space:]]*=[[:space:]]*"[^"]+"|high|CL-014|Docker registry password hardcoded|Use docker credential helpers or environment variables'

  # --- Docker auth config ---
  '"auth"[[:space:]]*:[[:space:]]*"[A-Za-z0-9+/=]{20,}"|high|CL-015|Docker auth token detected in config|Use docker credential stores instead of plaintext auth'

  # --- Kubernetes secrets in plain YAML ---
  'kind:[[:space:]]*Secret|high|CL-016|Kubernetes Secret manifest detected in source|Use sealed-secrets, external-secrets, or vault-injector instead of plain manifests'

  # --- Vault tokens ---
  'vault[_-]?token[[:space:]]*=[[:space:]]*"[^"]+"|critical|CL-017|HashiCorp Vault token hardcoded|Use Vault agent auto-auth or environment variables'

  # --- Vault token pattern (hvs.) ---
  'hvs\.[0-9a-zA-Z]{24,}|critical|CL-018|HashiCorp Vault service token detected (hvs. prefix)|Revoke the token and use Vault agent for authentication'

  # --- New Relic License Keys ---
  'NEW_RELIC_LICENSE_KEY[[:space:]]*=[[:space:]]*[0-9a-f]{40}|high|CL-019|New Relic License Key detected|Move to environment variables; rotate at newrelic.com'

  # --- PagerDuty Integration Keys ---
  'pagerduty.*[0-9a-f]{32}|high|CL-020|Possible PagerDuty integration key detected|Rotate the key and store in environment variables'
)

# ============================================================================
# 5. JWT & SESSION SECRETS (JW-001 through JW-010)
# ============================================================================

declare -a SECRETSCAN_JWT_PATTERNS=()

SECRETSCAN_JWT_PATTERNS+=(
  # --- JWT_SECRET assignments ---
  'JWT[_-]?SECRET[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-001|JWT signing secret hardcoded|Move to environment variables; use a strong random secret (256+ bits)'

  # --- JWT_SECRET (single quotes) ---
  "JWT[_-]?SECRET[[:space:]]*=[[:space:]]*'[^']{8,}'|high|JW-002|JWT signing secret hardcoded (single quotes)|Move to environment variables; use a strong random secret"

  # --- SESSION_SECRET assignments ---
  'SESSION[_-]?SECRET[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-003|Session secret hardcoded|Move to environment variables; rotate regularly'

  # --- COOKIE_SECRET assignments ---
  'COOKIE[_-]?SECRET[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-004|Cookie signing secret hardcoded|Move to environment variables; rotate regularly'

  # --- HMAC key assignments ---
  'HMAC[_-]?(KEY|SECRET)[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-005|HMAC key/secret hardcoded|Move to environment variables or a secrets manager'

  # --- Signing key assignments ---
  'SIGNING[_-]?KEY[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-006|Signing key hardcoded in string assignment|Move to environment variables; use strong random keys'

  # --- Encryption key assignments ---
  'ENCRYPTION[_-]?KEY[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-007|Encryption key hardcoded in string assignment|Move to environment variables or a key management service'

  # --- SECRET_KEY assignments (Django, Flask, etc.) ---
  'SECRET[_-]?KEY[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-008|Application secret key hardcoded|Move to environment variables; use a strong random value'

  # --- APP_SECRET assignments ---
  'APP[_-]?SECRET[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-009|Application secret hardcoded|Move to environment variables or a secrets manager'

  # --- TOKEN_SECRET assignments ---
  'TOKEN[_-]?SECRET[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|JW-010|Token secret hardcoded|Move to environment variables; rotate regularly'
)

# ============================================================================
# 6. GENERIC HIGH-ENTROPY STRINGS (EN-001 through EN-012)
# ============================================================================

declare -a SECRETSCAN_ENTROPY_PATTERNS=()

SECRETSCAN_ENTROPY_PATTERNS+=(
  # --- Long hex strings in assignments (32+ chars) ---
  '[_-]?(key|token|secret|password|credential|auth)[[:space:]]*=[[:space:]]*"?[0-9a-fA-F]{32,}"?|medium|EN-001|Long hex string (32+ chars) in secret-named variable assignment|Verify this is not a secret; if it is, move to environment variables'

  # --- Base64 strings in secret-named variables ---
  '[_-]?(key|token|secret|password)[[:space:]]*=[[:space:]]*"[A-Za-z0-9+/]{32,}={0,2}"|medium|EN-002|Base64-encoded value in secret-named variable|Verify this is not a secret; if it is, move to environment variables'

  # --- Long random strings in config assignments ---
  'config\.[a-zA-Z_]*secret[[:space:]]*=[[:space:]]*"[A-Za-z0-9]{24,}"|medium|EN-003|Long string in config secret assignment|Move config secrets to environment variables'

  # --- Hex strings assigned to API key vars ---
  'API[_-]?KEY[[:space:]]*[:=][[:space:]]*"?[0-9a-fA-F]{32,}"?|medium|EN-004|Long hex value assigned to API key variable|Verify and move to environment variables if sensitive'

  # --- Generic long token assignments ---
  '[_-]?token[[:space:]]*=[[:space:]]*"[A-Za-z0-9_-]{40,}"|medium|EN-005|Long token value in assignment (40+ chars)|Verify this is not a secret; move to environment variables if needed'

  # --- Entropy placeholder (handled by analyzer) ---
  'PLACEHOLDER_HIGH_ENTROPY_HEX|medium|EN-006|High-entropy hex string detected by entropy analysis|Verify whether this string is a secret; move to secure storage if so'

  # --- Entropy placeholder for base64 ---
  'PLACEHOLDER_HIGH_ENTROPY_BASE64|medium|EN-007|High-entropy base64 string detected by entropy analysis|Verify whether this string is a secret; move to secure storage if so'

  # --- Private/internal key variable with long value ---
  'PRIVATE[_-]?KEY[[:space:]]*=[[:space:]]*"[^"]{20,}"|high|EN-008|Long value assigned to PRIVATE_KEY variable|Move to environment variables or a key vault'

  # --- Access token with long value ---
  'ACCESS[_-]?TOKEN[[:space:]]*=[[:space:]]*"[^"]{20,}"|high|EN-009|Long value assigned to ACCESS_TOKEN variable|Move to environment variables or a secrets manager'

  # --- Client secret with long value ---
  'CLIENT[_-]?SECRET[[:space:]]*=[[:space:]]*"[^"]{8,}"|high|EN-010|Client secret value hardcoded|Move to environment variables or a secrets manager'

  # --- Refresh token with long value ---
  'REFRESH[_-]?TOKEN[[:space:]]*=[[:space:]]*"[^"]{20,}"|high|EN-011|Refresh token value hardcoded|Move to environment variables; rotate token'

  # --- Master key with long value ---
  'MASTER[_-]?KEY[[:space:]]*=[[:space:]]*"[^"]{8,}"|critical|EN-012|Master key value hardcoded|Remove immediately; use a key vault or HSM for master keys'
)

# ============================================================================
# Utility Functions
# ============================================================================

# Get total pattern count across all categories
secretscan_pattern_count() {
  local count=0
  count=$((count + ${#SECRETSCAN_APIKEY_PATTERNS[@]}))
  count=$((count + ${#SECRETSCAN_PASSWORD_PATTERNS[@]}))
  count=$((count + ${#SECRETSCAN_PRIVKEY_PATTERNS[@]}))
  count=$((count + ${#SECRETSCAN_CLOUD_PATTERNS[@]}))
  count=$((count + ${#SECRETSCAN_JWT_PATTERNS[@]}))
  count=$((count + ${#SECRETSCAN_ENTROPY_PATTERNS[@]}))
  echo "$count"
}

# List patterns by category
secretscan_list_patterns() {
  local filter_type="${1:-all}"
  local -n _patterns_ref

  case "$filter_type" in
    APIKEY)   _patterns_ref=SECRETSCAN_APIKEY_PATTERNS ;;
    PASSWORD) _patterns_ref=SECRETSCAN_PASSWORD_PATTERNS ;;
    PRIVKEY)  _patterns_ref=SECRETSCAN_PRIVKEY_PATTERNS ;;
    CLOUD)    _patterns_ref=SECRETSCAN_CLOUD_PATTERNS ;;
    JWT)      _patterns_ref=SECRETSCAN_JWT_PATTERNS ;;
    ENTROPY)  _patterns_ref=SECRETSCAN_ENTROPY_PATTERNS ;;
    all)
      secretscan_list_patterns "APIKEY"
      secretscan_list_patterns "PASSWORD"
      secretscan_list_patterns "PRIVKEY"
      secretscan_list_patterns "CLOUD"
      secretscan_list_patterns "JWT"
      secretscan_list_patterns "ENTROPY"
      return
      ;;
    *)
      echo "Unknown category: $filter_type"
      return 1
      ;;
  esac

  for entry in "${_patterns_ref[@]}"; do
    IFS='|' read -r regex severity check_id description recommendation <<< "$entry"
    # Skip placeholder patterns
    [[ "$regex" == PLACEHOLDER_* ]] && continue
    printf "%-12s %-8s %s\n" "$check_id" "$severity" "$description"
  done
}

# Get patterns array name for a category
get_secretscan_patterns_for_category() {
  local category="$1"
  case "$category" in
    apikey)   echo "SECRETSCAN_APIKEY_PATTERNS" ;;
    password) echo "SECRETSCAN_PASSWORD_PATTERNS" ;;
    privkey)  echo "SECRETSCAN_PRIVKEY_PATTERNS" ;;
    cloud)    echo "SECRETSCAN_CLOUD_PATTERNS" ;;
    jwt)      echo "SECRETSCAN_JWT_PATTERNS" ;;
    entropy)  echo "SECRETSCAN_ENTROPY_PATTERNS" ;;
    *)        echo "" ;;
  esac
}

# All category names for iteration
get_all_secretscan_categories() {
  echo "apikey password privkey cloud jwt entropy"
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
