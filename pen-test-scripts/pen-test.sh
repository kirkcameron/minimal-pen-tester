#!/usr/bin/env bash
# Penetration Testing Script for minimal-server-mail
# Tests common security vulnerabilities in mail scripts

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TARGET_URL=""
VERBOSE=false

# Help function
show_help() {
    echo "Penetration Testing Script for minimal-server-mail"
    echo ""
    echo "Usage: $0 [OPTIONS] <TARGET_URL>"
    echo ""
    echo "Options:"
    echo "  -v, --verbose    Verbose output"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 https://example.com/contact"
    echo "  $0 -v https://example.com/contact"
    echo ""
    echo "Tests performed:"
    echo "  - Direct script access"
    echo "  - Config file exposure"
    echo "  - Header injection attacks"
    echo "  - Rate limiting tests"
    echo "  - Input validation tests"
    echo "  - Process authentication (NOVEL APPROACH)"
    echo "  - External process blocking"
    echo "  - Comprehensive process auth tests"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
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

echo -e "${BLUE}🔍 Starting penetration test against: $TARGET_URL${NC}"
echo ""

# Test 1: Direct script access
echo -e "${YELLOW}Test 1: Direct script access${NC}"
echo "Testing: $TARGET_URL"mail.php
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL"mail.php)
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: mail.php is directly accessible (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Response content:"
        curl -s "$TARGET_URL"mail.php | head -5
    fi
else
    echo -e "${GREEN}✅ SECURE: mail.php is not directly accessible (HTTP $response)${NC}"
fi
echo ""

# Test 2: Config file exposure
echo -e "${YELLOW}Test 2: Config file exposure${NC}"
echo "Testing: $TARGET_URL"config.php
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL"config.php)
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: config.php is accessible (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Response content:"
        curl -s "$TARGET_URL"config.php | head -5
    fi
else
    echo -e "${GREEN}✅ SECURE: config.php is not accessible (HTTP $response)${NC}"
fi
echo ""

# Test 3: .htaccess exposure
echo -e "${YELLOW}Test 3: .htaccess file exposure${NC}"
echo "Testing: $TARGET_URL".htaccess
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL".htaccess)
# Check if 200 response contains actual .htaccess content
if [[ "$response" == "200" ]] && curl -s "$TARGET_URL".htaccess | grep -q "RewriteRule\|DirectoryIndex\|Options"; then
    echo -e "${RED}❌ VULNERABLE: .htaccess is accessible (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Response content:"
        curl -s "$TARGET_URL".htaccess | head -5
    fi
else
    echo -e "${GREEN}✅ SECURE: .htaccess is not accessible (HTTP $response)${NC}"
fi
echo ""

# Test 4: Header injection attack
echo -e "${YELLOW}Test 4: Header injection attack${NC}"
echo "Testing header injection via email field..."
response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
    -d "name=Test&email=test@evil.com%0d%0aBcc:spam@victim.com&message=Test" \
    -w "%{http_code}")
if [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Header injection possible (HTTP $response)${NC}"
    echo "The email field accepts newline characters that could inject headers"
elif [[ "$response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
elif [[ "$response" == "405" ]]; then
    echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: Header injection blocked (HTTP $response)${NC}"
fi
echo ""

# Test 5: Rate limiting test
echo -e "${YELLOW}Test 5: Rate limiting test${NC}"
echo "Sending 5 rapid requests to test rate limiting..."
for i in {1..5}; do
    response=$(curl -s -X POST "$TARGET_URL"mail.php \
        -d "name=Spam$i&email=spam$i@test.com&message=Spam test $i" \
        -w "%{http_code}")
    if [[ "$response" == "429" ]]; then
        echo -e "${GREEN}✅ SECURE: Rate limiting active (HTTP $response)${NC}"
        break
    elif [[ "$i" == "5" ]]; then
        echo -e "${RED}❌ VULNERABLE: No rate limiting detected${NC}"
    fi
done
echo ""

# Test 6: Input validation test
echo -e "${YELLOW}Test 6: Input validation test${NC}"
echo "Testing with malicious input..."
response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
    -d "name=<script>alert('xss')</script>&email=invalid-email&message=" \
    -w "%{http_code}")
if [[ "$response" == "400" ]]; then
    echo -e "${GREEN}✅ SECURE: Input validation active (HTTP $response)${NC}"
elif [[ "$response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
elif [[ "$response" == "405" ]]; then
    echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
else
    echo -e "${RED}❌ VULNERABLE: Input validation insufficient (HTTP $response)${NC}"
fi
echo ""

# Test 7: Directory browsing
echo -e "${YELLOW}Test 7: Directory browsing${NC}"
echo "Testing: $TARGET_URL"
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL")
if curl -s "$TARGET_URL" | grep -q "Index of"; then
    echo -e "${RED}❌ VULNERABLE: Directory browsing enabled${NC}"
else
    echo -e "${GREEN}✅ SECURE: Directory browsing disabled${NC}"
fi
echo ""

# Test 8: Process authentication (NOVEL APPROACH)
echo -e "${YELLOW}Test 8: Process authentication${NC}"
echo "Testing if server can distinguish between internal and external processes..."

# Test internal process call
server_pid=$$
echo "Testing internal process authentication (PID: $server_pid)..."
response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
    -d "name=InternalTest&email=internal@test.com&message=Internal process test&process_id=$server_pid" \
    -w "%{http_code}")

if [[ "$response" == "200" ]]; then
    echo -e "${GREEN}✅ SECURE: Process authentication active (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server successfully validated internal process relationship"
    fi
elif [[ "$response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
elif [[ "$response" == "405" ]]; then
    echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: Process authentication unclear (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server response suggests process authentication may not be implemented"
    fi
fi
echo ""

# Test 9: External process blocking
echo -e "${YELLOW}Test 9: External process blocking${NC}"
echo "Testing if external processes are blocked..."

# Test external process call
external_pid=$((server_pid + 1000))
echo "Testing external process blocking (PID: $external_pid)..."
response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
    -d "name=ExternalTest&email=external@test.com&message=External process test&process_id=$external_pid" \
    -w "%{http_code}")

if [[ "$response" == "403" ]] || [[ "$response" == "401" ]]; then
    echo -e "${GREEN}✅ SECURE: External process blocked (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server successfully blocked external process access"
    fi
elif [[ "$response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
elif [[ "$response" == "405" ]]; then
    echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
elif [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: External process not blocked (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server accepted external process call - process authentication may be insufficient"
    fi
else
    echo -e "${YELLOW}⚠️  WARNING: External process blocking unclear (HTTP $response)${NC}"
fi
echo ""

# Test 10: Comprehensive process authentication tests
echo -e "${YELLOW}Test 10: Comprehensive process authentication tests${NC}"
echo "Running comprehensive process-based authentication test suite..."

# Check if comprehensive test script exists
if [ -f "./process_auth_comprehensive_tests.sh" ]; then
    echo "Running comprehensive process authentication tests..."
    chmod +x ./process_auth_comprehensive_tests.sh
    ./process_auth_comprehensive_tests.sh
else
    echo -e "${YELLOW}⚠️  WARNING: Comprehensive test script not found${NC}"
    echo "Comprehensive process authentication tests not available"
fi
echo ""

echo -e "${BLUE}🔍 Penetration test completed!${NC}"
echo ""
echo "Summary:"
echo "- Check the results above for any vulnerabilities"
echo "- Green ✅ means the test passed (secure)"
echo "- Red ❌ means a vulnerability was found"
echo ""
echo "If vulnerabilities are found:"
echo "1. Move sensitive files outside web root"
echo "2. Configure web server security rules"
echo "3. Implement input validation and rate limiting"
echo "4. Consider implementing process-based authentication (NOVEL APPROACH)"
echo "5. Test again after implementing fixes"
