#!/usr/bin/env bash
# Input Validation Testing Script
# Focused testing for input validation and sanitization

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
            echo "Input Validation Testing Script"
            echo "Tests for input validation and sanitization vulnerabilities"
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

echo -e "${BLUE}🔍 Input Validation Testing: $TARGET_URL${NC}"
echo ""

# Test 1: XSS in name field
echo -e "${YELLOW}Test 1: XSS in Name Field${NC}"
echo "Testing XSS payload in name field..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=<script>alert('XSS')</script>&email=test@test.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: XSS in name field (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: XSS in name field blocked (HTTP $response)${NC}"
fi
echo ""

# Test 2: XSS in email field
echo -e "${YELLOW}Test 2: XSS in Email Field${NC}"
echo "Testing XSS payload in email field..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=<script>alert('XSS')</script>@test.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: XSS in email field (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: XSS in email field blocked (HTTP $response)${NC}"
fi
echo ""

# Test 3: XSS in message field
echo -e "${YELLOW}Test 3: XSS in Message Field${NC}"
echo "Testing XSS payload in message field..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@test.com&message=<script>alert('XSS')</script>" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: XSS in message field (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: XSS in message field blocked (HTTP $response)${NC}"
fi
echo ""

# Test 4: SQL injection in name field
echo -e "${YELLOW}Test 4: SQL Injection in Name Field${NC}"
echo "Testing SQL injection in name field..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=1' OR '1'='1&email=test@test.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: SQL injection in name field (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: SQL injection in name field blocked (HTTP $response)${NC}"
fi
echo ""

# Test 5: SQL injection in email field
echo -e "${YELLOW}Test 5: SQL Injection in Email Field${NC}"
echo "Testing SQL injection in email field..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@test.com' OR '1'='1&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: SQL injection in email field (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: SQL injection in email field blocked (HTTP $response)${NC}"
fi
echo ""

# Test 6: Input length validation
echo -e "${YELLOW}Test 6: Input Length Validation${NC}"
echo "Testing oversized input..."
long_name=$(printf 'A%.0s' {1..1000})
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=$long_name&email=test@test.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: No input length validation (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Input length validation active (HTTP $response)${NC}"
fi
echo ""

# Test 7: Empty field validation
echo -e "${YELLOW}Test 7: Empty Field Validation${NC}"
echo "Testing empty fields..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=&email=&message=" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Empty fields accepted (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Empty fields rejected (HTTP $response)${NC}"
fi
echo ""

# Test 8: Invalid email format
echo -e "${YELLOW}Test 8: Email Format Validation${NC}"
echo "Testing invalid email format..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=invalid-email&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Invalid email format accepted (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Invalid email format rejected (HTTP $response)${NC}"
fi
echo ""

# Test 9: Special characters
echo -e "${YELLOW}Test 9: Special Character Handling${NC}"
echo "Testing special characters..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=Test@#$%^&*()&email=test@test.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${GREEN}✅ SECURE: Special characters handled (HTTP $response)${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: Special characters rejected (HTTP $response)${NC}"
fi
echo ""

# Test 10: Unicode characters
echo -e "${YELLOW}Test 10: Unicode Character Handling${NC}"
echo "Testing Unicode characters..."
response=$(curl -s -X POST "$TARGET_URL"mail.php \
    -d "name=测试&email=test@test.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${GREEN}✅ SECURE: Unicode characters handled (HTTP $response)${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: Unicode characters rejected (HTTP $response)${NC}"
fi
echo ""

echo -e "${BLUE}🔍 Input validation testing completed!${NC}"
echo ""
echo "Summary:"
echo "- Check results above for input validation vulnerabilities"
echo "- Green ✅ means the test passed (secure)"
echo "- Red ❌ means a vulnerability was found"
echo "- Yellow ⚠️ means a warning (may be acceptable)"
echo ""
echo "If vulnerabilities are found:"
echo "1. Implement proper input sanitization"
echo "2. Validate all input formats"
echo "3. Set appropriate length limits"
echo "4. Use parameterized queries for database operations"
echo "5. Implement output encoding for XSS prevention"
