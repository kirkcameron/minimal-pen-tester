#!/usr/bin/env bash
# Web Server Security Testing Script
# Focused testing for web server configuration vulnerabilities

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
            echo "Web Server Security Testing Script"
            echo "Tests for web server configuration vulnerabilities"
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

echo -e "${BLUE}🔍 Web Server Security Testing: $TARGET_URL${NC}"
echo ""

# Test 1: Directory browsing
echo -e "${YELLOW}Test 1: Directory Browsing${NC}"
echo "Testing directory listing..."
response=$(curl -s "$TARGET_URL" | grep -q "Index of" && echo "VULNERABLE" || echo "SECURE")
if [[ "$response" == "VULNERABLE" ]]; then
    echo -e "${RED}❌ VULNERABLE: Directory browsing enabled${NC}"
else
    echo -e "${GREEN}✅ SECURE: Directory browsing disabled${NC}"
fi
echo ""

# Test 2: Sensitive file access
echo -e "${YELLOW}Test 2: Sensitive File Access${NC}"
echo "Testing access to sensitive files..."

# Test .htaccess
htaccess_response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL".htaccess)
# Check if 200 response contains actual .htaccess content
if [[ "$htaccess_response" == "200" ]] && curl -s "$TARGET_URL".htaccess | grep -q "RewriteRule\|DirectoryIndex\|Options"; then
    echo -e "${RED}❌ VULNERABLE: .htaccess accessible (HTTP $htaccess_response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: .htaccess protected (HTTP $htaccess_response)${NC}"
fi

# Test config files
config_response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL"config.php)
if [[ "$config_response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: config.php accessible (HTTP $config_response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: config.php protected (HTTP $config_response)${NC}"
fi

# Test .env files
env_response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL".env)
if [[ "$env_response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: .env accessible (HTTP $env_response)${NC}"
else
    echo -e "${GREEN}✅ SECURE: .env protected (HTTP $env_response)${NC}"
fi
echo ""

# Test 3: Server information disclosure
echo -e "${YELLOW}Test 3: Server Information Disclosure${NC}"
echo "Testing server information disclosure..."

# Check for server headers
server_header=$(curl -s -I "$TARGET_URL" | grep -i "server:")
if [[ -n "$server_header" ]]; then
    echo -e "${YELLOW}⚠️  WARNING: Server information disclosed: $server_header${NC}"
else
    echo -e "${GREEN}✅ SECURE: No server information disclosed${NC}"
fi

# Check for X-Powered-By headers
powered_by=$(curl -s -I "$TARGET_URL" | grep -i "x-powered-by:")
if [[ -n "$powered_by" ]]; then
    echo -e "${YELLOW}⚠️  WARNING: Technology stack disclosed: $powered_by${NC}"
else
    echo -e "${GREEN}✅ SECURE: No technology stack disclosed${NC}"
fi
echo ""

# Test 4: Security headers
echo -e "${YELLOW}Test 4: Security Headers${NC}"
echo "Testing security headers..."

headers=$(curl -s -I "$TARGET_URL")

# Check for X-Frame-Options
if echo "$headers" | grep -qi "x-frame-options"; then
    echo -e "${GREEN}✅ SECURE: X-Frame-Options header present${NC}"
else
    echo -e "${RED}❌ VULNERABLE: X-Frame-Options header missing${NC}"
fi

# Check for X-Content-Type-Options
if echo "$headers" | grep -qi "x-content-type-options"; then
    echo -e "${GREEN}✅ SECURE: X-Content-Type-Options header present${NC}"
else
    echo -e "${RED}❌ VULNERABLE: X-Content-Type-Options header missing${NC}"
fi

# Check for X-XSS-Protection
if echo "$headers" | grep -qi "x-xss-protection"; then
    echo -e "${GREEN}✅ SECURE: X-XSS-Protection header present${NC}"
else
    echo -e "${RED}❌ VULNERABLE: X-XSS-Protection header missing${NC}"
fi

# Check for Strict-Transport-Security
if echo "$headers" | grep -qi "strict-transport-security"; then
    echo -e "${GREEN}✅ SECURE: Strict-Transport-Security header present${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: Strict-Transport-Security header missing${NC}"
fi
echo ""

# Test 5: HTTP methods
echo -e "${YELLOW}Test 5: HTTP Methods${NC}"
echo "Testing allowed HTTP methods..."

# Test OPTIONS method
options_response=$(curl -s -X OPTIONS "$TARGET_URL" -w "%{http_code}")
if [[ "$options_response" == "200" ]]; then
    echo -e "${YELLOW}⚠️  WARNING: OPTIONS method allowed${NC}"
else
    echo -e "${GREEN}✅ SECURE: OPTIONS method restricted${NC}"
fi

# Test TRACE method
trace_response=$(curl -s -X TRACE "$TARGET_URL" -w "%{http_code}")
if [[ "$trace_response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: TRACE method allowed${NC}"
else
    echo -e "${GREEN}✅ SECURE: TRACE method restricted${NC}"
fi

# Test PUT method
put_response=$(curl -s -X PUT "$TARGET_URL" -w "%{http_code}")
if [[ "$put_response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: PUT method allowed${NC}"
else
    echo -e "${GREEN}✅ SECURE: PUT method restricted${NC}"
fi

# Test DELETE method
delete_response=$(curl -s -X DELETE "$TARGET_URL" -w "%{http_code}")
if [[ "$delete_response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: DELETE method allowed${NC}"
else
    echo -e "${GREEN}✅ SECURE: DELETE method restricted${NC}"
fi
echo ""

# Test 6: Error handling
echo -e "${YELLOW}Test 6: Error Handling${NC}"
echo "Testing error handling..."

# Test 404 error
error_response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL"nonexistent-file.php)
if [[ "$error_response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: 404 errors handled properly${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: 404 error handling unusual (HTTP $error_response)${NC}"
fi

# Test 500 error (if possible)
error_response=$(curl -s -X POST "$TARGET_URL"mail.php -d "invalid=data" -w "%{http_code}")
if [[ "$error_response" == "500" ]]; then
    echo -e "${GREEN}✅ SECURE: 500 errors handled properly${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: 500 error handling unusual (HTTP $error_response)${NC}"
fi
echo ""

# Test 7: SSL/TLS configuration (if HTTPS)
if [[ "$TARGET_URL" =~ ^https ]]; then
    echo -e "${YELLOW}Test 7: SSL/TLS Configuration${NC}"
    echo "Testing SSL/TLS configuration..."
    
    # Check SSL certificate
    ssl_info=$(echo | openssl s_client -servername $(echo "$TARGET_URL" | sed 's|https://||' | sed 's|/.*||') -connect $(echo "$TARGET_URL" | sed 's|https://||' | sed 's|/.*||'):443 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)
    if [[ -n "$ssl_info" ]]; then
        echo -e "${GREEN}✅ SECURE: SSL certificate present${NC}"
    else
        echo -e "${RED}❌ VULNERABLE: SSL certificate issues${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  WARNING: Not testing SSL/TLS (HTTP connection)${NC}"
fi
echo ""

echo -e "${BLUE}🔍 Web server security testing completed!${NC}"
echo ""
echo "Summary:"
echo "- Check results above for web server configuration issues"
echo "- Green ✅ means the test passed (secure)"
echo "- Red ❌ means a vulnerability was found"
echo "- Yellow ⚠️ means a warning (may be acceptable)"
echo ""
echo "If vulnerabilities are found:"
echo "1. Configure web server security rules"
echo "2. Add security headers"
echo "3. Restrict HTTP methods"
echo "4. Implement proper error handling"
echo "5. Configure SSL/TLS properly"
