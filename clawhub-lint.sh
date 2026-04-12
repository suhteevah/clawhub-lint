#!/usr/bin/env bash
# clawhub-lint — Unified static analysis suite
# 39 analyzers | 1,600+ patterns | POSIX grep-based | Zero dependencies
#
# Usage:
#   clawhub-lint scan <path> [--tools all|tool1,tool2,...] [--format text|json] [--verbose]
#   clawhub-lint list                    # List all available tools
#   clawhub-lint count                   # Count total patterns
#   clawhub-lint scan <path> --tools sqlguard,authaudit,secretscan
#   clawhub-lint scan <path> --all       # All 39 tools (default)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$SCRIPT_DIR/tools"
LIB_DIR="$SCRIPT_DIR/lib"
VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ============================================================================
# Helpers
# ============================================================================

usage() {
  echo -e "${BOLD}clawhub-lint${NC} v${VERSION} — 39 analyzers, 1,600+ patterns"
  echo ""
  echo "Usage:"
  echo "  clawhub-lint scan <path> [OPTIONS]"
  echo "  clawhub-lint list"
  echo "  clawhub-lint count"
  echo ""
  echo "Options:"
  echo "  --tools TOOLS   Comma-separated list of tools (default: all)"
  echo "  --format FMT    Output format: text, json, sarif (default: text)"
  echo "  --severity SEV  Minimum severity: low, medium, high, critical (default: low)"
  echo "  --verbose       Show per-file details"
  echo "  --help          Show this help"
}

list_tools() {
  echo -e "${BOLD}Available analyzers:${NC}"
  echo ""
  local count=0
  for tool_dir in "$TOOLS_DIR"/*/; do
    local name
    name=$(basename "$tool_dir")
    local pcount
    pcount=$(grep -cE '\|(critical|high|medium|low)\|' "$tool_dir/patterns.sh" 2>/dev/null | head -1 || echo 0)
    pcount=${pcount//[^0-9]/}
    printf "  ${CYAN}%-20s${NC} %3d patterns\n" "$name" "$pcount"
    count=$((count + 1))
  done
  echo ""
  echo -e "${BOLD}$count tools available${NC}"
}

count_patterns() {
  local total=0
  local tool_count=0
  for tool_dir in "$TOOLS_DIR"/*/; do
    local pcount
    pcount=$(grep -cE '\|(critical|high|medium|low)\|' "$tool_dir/patterns.sh" 2>/dev/null | head -1 || echo 0)
    pcount=${pcount//[^0-9]/}
    total=$((total + pcount))
    tool_count=$((tool_count + 1))
  done
  echo -e "${BOLD}$total${NC} patterns across ${BOLD}$tool_count${NC} analyzers"
}

# ============================================================================
# File Discovery (shared)
# ============================================================================

should_skip_file() {
  local filepath="$1"
  local basename_f
  basename_f=$(basename "$filepath")
  local basename_lower
  basename_lower=$(echo "$basename_f" | tr '[:upper:]' '[:lower:]')
  local ext="${basename_lower##*.}"

  case "$ext" in
    png|jpg|jpeg|gif|bmp|ico|svg|webp|mp3|mp4|avi|mov|mkv|wav|flac|ogg) return 0 ;;
    zip|tar|gz|bz2|xz|7z|rar|tgz) return 0 ;;
    exe|dll|so|dylib|o|a|class|pyc|pyo|wasm) return 0 ;;
    woff|woff2|ttf|eot|otf) return 0 ;;
    pdf|doc|docx|xls|xlsx|ppt|pptx) return 0 ;;
    lock|map) return 0 ;;
  esac

  case "$basename_lower" in
    *.min.js|*.min.css|*.min.mjs|*.bundle.js|*.chunk.js) return 0 ;;
    package-lock.json|yarn.lock|pnpm-lock.yaml|cargo.lock|poetry.lock) return 0 ;;
    .ds_store|thumbs.db|desktop.ini) return 0 ;;
  esac

  return 1
}

is_excluded_dir() {
  local filepath="$1"
  case "$filepath" in
    */.git/*|*/node_modules/*|*/vendor/*|*/dist/*|*/build/*|*/__pycache__/*) return 0 ;;
    */target/*|*/.next/*|*/.nuxt/*|*/coverage/*|*/.venv/*|*/venv/*) return 0 ;;
  esac
  return 1
}

discover_files() {
  local scan_path="$1"
  find "$scan_path" -type f 2>/dev/null | while read -r f; do
    is_excluded_dir "$f" && continue
    should_skip_file "$f" && continue
    echo "$f"
  done
}

# ============================================================================
# Language Affinity — which tools apply to which file types
# ============================================================================

# Tools that target web/scripting languages (JS/TS/Python/Ruby/PHP) and should
# NOT run against compiled languages (Rust, Go, C, C++, Java)
declare -A WEB_ONLY_TOOLS=(
  [inputshield]=1 [errorlens]=1 [asyncguard]=1 [httplint]=1
  [bundlephobia]=1 [featurelint]=1 [i18ncheck]=1 [gqllint]=1
  [memguard]=1 [styleguard]=1 [deadcode]=1 [testgap]=1
)

# Tools that are language-agnostic (grep patterns work on any source)
# Everything NOT in WEB_ONLY_TOOLS runs on all files.

# Compiled language extensions that web-only tools should skip
is_compiled_lang() {
  local filepath="$1"
  local ext="${filepath##*.}"
  case "$ext" in
    rs|go|c|h|cpp|hpp|cc|cxx|java|cs|swift|kt|scala|zig) return 0 ;;
  esac
  return 1
}

# ============================================================================
# Pattern Loading & Scanning
# ============================================================================

# All patterns loaded here: PATTERN_REGEX|SEVERITY|CHECK_ID|DESCRIPTION|RECOMMENDATION
declare -a ALL_PATTERNS=()

load_tool_patterns() {
  local tool_name="$1"
  local patterns_file="$TOOLS_DIR/$tool_name/patterns.sh"

  if [ ! -f "$patterns_file" ]; then
    echo -e "${RED}Tool not found: $tool_name${NC}" >&2
    return 1
  fi

  # Extract pattern lines (lines containing |severity|)
  while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" =~ ^[[:space:]]*\) ]] && continue
    [[ "$line" =~ ^[[:space:]]*declare ]] && continue
    [[ "$line" =~ ^[[:space:]]*set ]] && continue
    [[ "$line" =~ ^[[:space:]]*source ]] && continue
    [[ "$line" =~ ^\#!/ ]] && continue
    [[ "$line" =~ _PATTERNS\+= ]] && continue

    # Clean up: remove leading quote, trailing quote
    line="${line#*\'}"
    line="${line%\'*}"
    line="${line#*\"}"
    line="${line%\"*}"

    # Only keep lines that match the pattern format
    if echo "$line" | grep -qE '\|(critical|high|medium|low)\|'; then
      ALL_PATTERNS+=("$tool_name|$line")
    fi
  done < "$patterns_file"
}

scan_file() {
  local filepath="$1"
  local min_severity="$2"
  local findings=0
  local is_compiled=false
  is_compiled_lang "$filepath" && is_compiled=true

  for pattern_entry in "${ALL_PATTERNS[@]}"; do
    local tool_name="${pattern_entry%%|*}"

    # Skip web-only tools on compiled languages
    if $is_compiled && [[ -n "${WEB_ONLY_TOOLS[$tool_name]+x}" ]]; then
      continue
    fi
    local rest="${pattern_entry#*|}"
    local regex="${rest%%|*}"
    rest="${rest#*|}"
    local severity="${rest%%|*}"
    rest="${rest#*|}"
    local check_id="${rest%%|*}"
    rest="${rest#*|}"
    local description="${rest%%|*}"
    local recommendation="${rest#*|}"

    # Severity filter
    case "$min_severity" in
      critical) [[ "$severity" != "critical" ]] && continue ;;
      high) [[ "$severity" == "medium" || "$severity" == "low" ]] && continue ;;
      medium) [[ "$severity" == "low" ]] && continue ;;
    esac

    # Scan
    if grep -nE "$regex" "$filepath" 2>/dev/null | head -5 | while IFS=: read -r line_num matched_text; do
      echo "$filepath|$line_num|$severity|$tool_name/$check_id|$description|$recommendation"
      findings=$((findings + 1))
    done; then
      :
    fi
  done
}

# ============================================================================
# Scoring
# ============================================================================

calculate_score() {
  local critical=$1 high=$2 medium=$3 low=$4
  local score=100
  score=$((score - critical * 25 - high * 15 - medium * 8 - low * 3))
  [ $score -lt 0 ] && score=0
  echo $score
}

grade_from_score() {
  local score=$1
  if [ $score -ge 90 ]; then echo "A"
  elif [ $score -ge 80 ]; then echo "B"
  elif [ $score -ge 70 ]; then echo "C"
  elif [ $score -ge 60 ]; then echo "D"
  else echo "F"
  fi
}

# ============================================================================
# Main Scan
# ============================================================================

run_scan() {
  local scan_path="$1"
  local tools_str="$2"
  local format="$3"
  local min_severity="$4"
  local verbose="$5"

  # Load patterns
  if [ "$tools_str" = "all" ]; then
    for tool_dir in "$TOOLS_DIR"/*/; do
      local name
      name=$(basename "$tool_dir")
      load_tool_patterns "$name" 2>/dev/null || true
    done
  else
    IFS=',' read -ra TOOL_LIST <<< "$tools_str"
    for tool in "${TOOL_LIST[@]}"; do
      load_tool_patterns "$tool"
    done
  fi

  echo -e "${BOLD}clawhub-lint${NC} v${VERSION}"
  echo -e "Loaded ${BOLD}${#ALL_PATTERNS[@]}${NC} patterns"
  echo -e "Scanning: ${CYAN}$scan_path${NC}"
  echo ""

  # Discover files
  local files
  files=$(discover_files "$scan_path")
  local file_count
  file_count=$(echo "$files" | grep -c . || echo 0)
  echo -e "Found ${BOLD}$file_count${NC} files to scan"
  echo ""

  # Scan
  local critical=0 high=0 medium=0 low=0 total_findings=0

  while IFS= read -r filepath; do
    [ -z "$filepath" ] && continue
    while IFS='|' read -r file line sev check desc rec; do
      [ -z "$file" ] && continue
      total_findings=$((total_findings + 1))
      case "$sev" in
        critical) critical=$((critical + 1)); echo -e "${RED}CRITICAL${NC} $check $file:$line" ;;
        high)     high=$((high + 1));         echo -e "${YELLOW}HIGH${NC}     $check $file:$line" ;;
        medium)   medium=$((medium + 1));     [ "$verbose" = "true" ] && echo -e "${BLUE}MEDIUM${NC}   $check $file:$line" ;;
        low)      low=$((low + 1));           [ "$verbose" = "true" ] && echo -e "${DIM}LOW${NC}      $check $file:$line" ;;
      esac
    done < <(scan_file "$filepath" "$min_severity")
  done <<< "$files"

  # Score
  local score
  score=$(calculate_score $critical $high $medium $low)
  local grade
  grade=$(grade_from_score $score)

  echo ""
  echo -e "${BOLD}═══════════════════════════════════════${NC}"
  echo -e "${BOLD}Score: $score/100 (Grade: $grade)${NC}"
  echo -e "  Critical: $critical | High: $high | Medium: $medium | Low: $low"
  echo -e "  Total findings: $total_findings across $file_count files"
  echo -e "${BOLD}═══════════════════════════════════════${NC}"
}

# ============================================================================
# CLI
# ============================================================================

main() {
  local command="${1:-help}"
  shift || true

  case "$command" in
    scan)
      local scan_path="${1:-.}"
      shift || true
      local tools="all" format="text" severity="low" verbose="false"
      while [ $# -gt 0 ]; do
        case "$1" in
          --tools) tools="$2"; shift 2 ;;
          --all) tools="all"; shift ;;
          --format) format="$2"; shift 2 ;;
          --severity) severity="$2"; shift 2 ;;
          --verbose) verbose="true"; shift ;;
          *) shift ;;
        esac
      done
      run_scan "$scan_path" "$tools" "$format" "$severity" "$verbose"
      ;;
    list) list_tools ;;
    count) count_patterns ;;
    help|--help|-h) usage ;;
    *) echo "Unknown command: $command"; usage; exit 1 ;;
  esac
}

main "$@"
