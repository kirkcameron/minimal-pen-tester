#!/usr/bin/env bash
# Advanced Penetration Testing Script for minimal-server-mail
# Comprehensive security testing with detailed reporting

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TARGET_URL=""
OUTPUT_FILE=""
VERBOSE=false
AGGRESSIVE=false
DELAY=1

# Vulnerability counters
VULNERABILITIES=0
TESTS_PASSED=0
TOTAL_TESTS=0

# Help function
show_help() {
    echo "Advanced Penetration Testing Script for minimal-server-mail"
    echo ""
    echo "Usage: $0 [OPTIONS] <TARGET_URL>"
    echo ""
    echo "Options:"
    echo "  -v, --verbose       Verbose output"
    echo "  -a, --aggressive    Aggressive testing (more requests)"
    echo "  -o, --output FILE   Save results to file"
    echo "  -d, --delay SEC     Delay between requests (default: 1)"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 https://example.com/contact"
    echo "  $0 -v -a -o results.txt https://example.com/contact"
    echo ""
    echo "Advanced tests:"
    echo "  - SQL injection attempts"
    echo "  - XSS payload testing"
    echo "  - Email header injection"
    echo "  - File upload testing"
    echo "  - Authentication bypass"
    echo "  - Information disclosure"
}

# Log function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[$timestamp] INFO: $message${NC}"
            ;;
        "WARN")
            echo -e "${YELLOW}[$timestamp] WARN: $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}[$timestamp] ERROR: $message${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[$timestamp] SUCCESS: $message${NC}"
            ;;
        "VULN")
            echo -e "${RED}[$timestamp] VULNERABILITY: $message${NC}"
            VULNERABILITIES=$((VULNERABILITIES + 1))
            ;;
    esac
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "[$timestamp] $level: $message" >> "$OUTPUT_FILE"
    fi
}

# Test function
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    local vulnerability_type="$4"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    log "INFO" "Running test: $test_name"
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Command: $test_command"
    fi
    
    local result=$(eval "$test_command")
    
    if [[ "$result" == "$expected_result" ]]; then
        log "SUCCESS" "Test passed: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log "VULN" "Test failed: $test_name - $vulnerability_type"
        if [[ "$VERBOSE" == "true" ]]; then
            echo "Expected: $expected_result, Got: $result"
        fi
    fi
    
    sleep "$DELAY"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -a|--aggressive)
            AGGRESSIVE=true
            DELAY=0.1
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            if [[ -z "$TARGET_URL" ]]; then
                TARGET_URL="$1"
            fi
            shift
            ;;
    esac
done

# Check if target URL is provided
if [[ -z "$TARGET_URL" ]]; then
    echo -e "${RED}Error: Target URL is required${NC}"
    show_help
    exit 1
fi

# Ensure URL ends with /
if [[ ! "$TARGET_URL" =~ /$ ]]; then
    TARGET_URL="${TARGET_URL}/"
fi

# Initialize output file if specified
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "Advanced Penetration Test Report" > "$OUTPUT_FILE"
    echo "Target: $TARGET_URL" >> "$OUTPUT_FILE"
    echo "Date: $(date)" >> "$OUTPUT_FILE"
    echo "=================================" >> "$OUTPUT_FILE"
fi

echo -e "${PURPLE}🔍 Advanced Penetration Testing${NC}"
echo -e "${PURPLE}Target: $TARGET_URL${NC}"
echo -e "${PURPLE}Mode: $([ "$AGGRESSIVE" == "true" ] && echo "Aggressive" || echo "Standard")${NC}"
echo ""

# Test 1: Direct script access
echo -e "${CYAN}=== DIRECT ACCESS TESTS ===${NC}"
run_test "Direct mail.php access" \
    "curl -s -o /dev/null -w '%{http_code}' '$TARGET_URL'mail.php" \
    "404" \
    "Direct script access"

run_test "Config file access" \
    "curl -s -o /dev/null -w '%{http_code}' '$TARGET_URL'config.php" \
    "404" \
    "Config file exposure"

run_test ".htaccess access" \
    "curl -s -o /dev/null -w '%{http_code}' '$TARGET_URL'.htaccess" \
    "404" \
    ".htaccess exposure"

# Test 2: Header injection attacks
echo -e "${CYAN}=== HEADER INJECTION TESTS ===${NC}"
run_test "Email header injection" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=Test&email=test@evil.com%0d%0aBcc:spam@victim.com&message=Test' -w '%{http_code}'" \
    "400" \
    "Email header injection"

run_test "Name header injection" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=Test%0d%0aSubject:FAKE&email=test@test.com&message=Test' -w '%{http_code}'" \
    "400" \
    "Name header injection"

# Test 3: XSS attacks
echo -e "${CYAN}=== XSS ATTACK TESTS ===${NC}"
run_test "XSS in name field" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=<script>alert(1)</script>&email=test@test.com&message=Test' -w '%{http_code}'" \
    "400" \
    "XSS in name field"

run_test "XSS in message field" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=Test&email=test@test.com&message=<script>alert(1)</script>' -w '%{http_code}'" \
    "400" \
    "XSS in message field"

# Test 4: SQL injection attempts
echo -e "${CYAN}=== SQL INJECTION TESTS ===${NC}"
run_test "SQL injection in name" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=1'\'' OR '\''1'\''='\''1&email=test@test.com&message=Test' -w '%{http_code}'" \
    "400" \
    "SQL injection in name"

run_test "SQL injection in email" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=Test&email=test@test.com'\'' OR '\''1'\''='\''1&message=Test' -w '%{http_code}'" \
    "400" \
    "SQL injection in email"

# Test 5: Rate limiting
echo -e "${CYAN}=== RATE LIMITING TESTS ===${NC}"
if [[ "$AGGRESSIVE" == "true" ]]; then
    log "INFO" "Testing rate limiting with 10 rapid requests..."
    for i in {1..10}; do
        response=$(curl -s -X POST "$TARGET_URL"mail.php \
            -d "name=Spam$i&email=spam$i@test.com&message=Spam test $i" \
            -w "%{http_code}")
        if [[ "$response" == "429" ]]; then
            log "SUCCESS" "Rate limiting active after $i requests"
            break
        fi
        sleep 0.1
    done
else
    log "INFO" "Testing rate limiting with 5 requests..."
    for i in {1..5}; do
        response=$(curl -s -X POST "$TARGET_URL"mail.php \
            -d "name=Spam$i&email=spam$i@test.com&message=Spam test $i" \
            -w "%{http_code}")
        if [[ "$response" == "429" ]]; then
            log "SUCCESS" "Rate limiting active after $i requests"
            break
        fi
        sleep "$DELAY"
    done
fi

# Test 6: Input validation
echo -e "${CYAN}=== INPUT VALIDATION TESTS ===${NC}"
run_test "Empty fields" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=&email=&message=' -w '%{http_code}'" \
    "400" \
    "Empty field validation"

run_test "Invalid email format" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=Test&email=invalid-email&message=Test' -w '%{http_code}'" \
    "400" \
    "Email format validation"

run_test "Oversized input" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=$(printf 'A%.0s' {1..1000})&email=test@test.com&message=Test' -w '%{http_code}'" \
    "400" \
    "Input length validation"

# Test 7: Directory browsing
echo -e "${CYAN}=== DIRECTORY BROWSING TESTS ===${NC}"
run_test "Directory listing" \
    "curl -s '$TARGET_URL' | grep -q 'Index of' && echo '200' || echo '404'" \
    "404" \
    "Directory browsing enabled"

# Test 8: Information disclosure
echo -e "${CYAN}=== INFORMATION DISCLOSURE TESTS ===${NC}"
run_test "Error message disclosure" \
    "curl -s -X POST '$TARGET_URL'mail.php -d 'name=Test&email=test@test.com&message=Test' | grep -q 'error\|exception\|stack trace' && echo '200' || echo '404'" \
    "404" \
    "Error message disclosure"

# Generate report
echo ""
echo -e "${PURPLE}=== PENETRATION TEST SUMMARY ===${NC}"
echo -e "${BLUE}Total tests: $TOTAL_TESTS${NC}"
echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
echo -e "${RED}Vulnerabilities found: $VULNERABILITIES${NC}"

if [[ "$VULNERABILITIES" -eq 0 ]]; then
    echo -e "${GREEN}🎉 No vulnerabilities found! Your mail script appears to be secure.${NC}"
else
    echo -e "${RED}⚠️  $VULNERABILITIES vulnerabilities found! Please review and fix the issues above.${NC}"
fi

echo ""
echo -e "${YELLOW}Recommendations:${NC}"
echo "1. Move sensitive files outside web root"
echo "2. Implement proper input validation"
echo "3. Add rate limiting"
echo "4. Configure web server security rules"
echo "5. Regular security testing"

if [[ -n "$OUTPUT_FILE" ]]; then
    echo ""
    echo "Results saved to: $OUTPUT_FILE"
fi
