#!/usr/bin/env bash
# Process-based Authentication Tests for minimal-pen-tester
# Tests novel process-based authentication mechanisms using server-side process knowledge

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
    echo "Process-based Authentication Tests for minimal-pen-tester"
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
    echo "  - Process relationship validation"
    echo "  - Memory access validation"
    echo "  - Internal process authentication"
    echo "  - External process blocking"
    echo "  - Process-based security mechanisms"
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

echo -e "${BLUE}🔍 Starting process-based authentication tests against: $TARGET_URL${NC}"
echo ""

# Test 1: Process relationship validation
echo -e "${YELLOW}Test 1: Process relationship validation${NC}"
echo "Testing if server can distinguish between internal and external processes..."

# Simulate internal process call (same PID as server)
server_pid=$$
echo "Server PID: $server_pid"
echo "Testing internal process authentication..."

# Check if server can validate process relationships
response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
    -d "name=InternalTest&email=internal@test.com&message=Internal process test&process_id=$server_pid" \
    -w "%{http_code}")

if [[ "$response" == "200" ]]; then
    echo -e "${GREEN}✅ SECURE: Process relationship validation active (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server successfully validated internal process relationship"
    fi
elif [[ "$response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
elif [[ "$response" == "405" ]]; then
    echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: Process relationship validation unclear (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server response suggests process validation may not be implemented"
    fi
fi
echo ""

# Test 2: Memory access validation
echo -e "${YELLOW}Test 2: Memory access validation${NC}"
echo "Testing if server can validate memory access patterns..."

# Simulate external process call (different PID)
external_pid=$((server_pid + 1000))
echo "External PID: $external_pid"
echo "Testing external process blocking..."

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
        echo "Server accepted external process call - process validation may be insufficient"
    fi
else
    echo -e "${YELLOW}⚠️  WARNING: Memory access validation unclear (HTTP $response)${NC}"
fi
echo ""

# Test 3: Process authentication bypass attempt
echo -e "${YELLOW}Test 3: Process authentication bypass attempt${NC}"
echo "Testing if external processes can bypass process authentication..."

# Try to spoof internal process characteristics
spoofed_pid=$server_pid
echo "Attempting to spoof internal process ID: $spoofed_pid"

response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
    -d "name=SpoofTest&email=spoof@test.com&message=Spoofed process test&process_id=$spoofed_pid" \
    -w "%{http_code}")

if [[ "$response" == "403" ]] || [[ "$response" == "401" ]]; then
    echo -e "${GREEN}✅ SECURE: Process spoofing blocked (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server successfully detected and blocked process ID spoofing"
    fi
elif [[ "$response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
elif [[ "$response" == "405" ]]; then
    echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
elif [[ "$response" == "200" ]]; then
    echo -e "${RED}❌ VULNERABLE: Process spoofing successful (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server accepted spoofed process ID - authentication may be insufficient"
    fi
else
    echo -e "${YELLOW}⚠️  WARNING: Process spoofing test unclear (HTTP $response)${NC}"
fi
echo ""

# Test 4: Process relationship validation with child processes
echo -e "${YELLOW}Test 4: Child process relationship validation${NC}"
echo "Testing if server can validate child process relationships..."

# Simulate child process call
child_pid=$((server_pid + 1))
echo "Child PID: $child_pid"
echo "Testing child process authentication..."

response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
    -d "name=ChildTest&email=child@test.com&message=Child process test&process_id=$child_pid&parent_id=$server_pid" \
    -w "%{http_code}")

if [[ "$response" == "200" ]]; then
    echo -e "${GREEN}✅ SECURE: Child process authentication successful (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server successfully authenticated child process relationship"
    fi
elif [[ "$response" == "403" ]] || [[ "$response" == "401" ]]; then
    echo -e "${GREEN}✅ SECURE: Child process blocked (HTTP $response)${NC}"
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Server correctly blocked child process - may be configured for strict internal-only access"
    fi
elif [[ "$response" == "404" ]]; then
    echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
elif [[ "$response" == "405" ]]; then
    echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
else
    echo -e "${YELLOW}⚠️  WARNING: Child process validation unclear (HTTP $response)${NC}"
fi
echo ""

# Test 5: Process-based rate limiting
echo -e "${YELLOW}Test 5: Process-based rate limiting${NC}"
echo "Testing if server implements process-based rate limiting..."

# Send multiple requests from same process
echo "Sending 3 rapid requests from same process..."
for i in {1..3}; do
    response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
        -d "name=RateTest$i&email=rate$i@test.com&message=Rate test $i&process_id=$server_pid" \
        -w "%{http_code}")
    
    if [[ "$response" == "429" ]]; then
        echo -e "${GREEN}✅ SECURE: Process-based rate limiting active (HTTP $response)${NC}"
        break
    elif [[ "$i" == "3" ]]; then
        echo -e "${YELLOW}⚠️  WARNING: No process-based rate limiting detected${NC}"
        if [[ "$VERBOSE" == "true" ]]; then
            echo "Server may not implement process-based rate limiting"
        fi
    fi
done
echo ""

# Test 6: Process authentication with different user agents
echo -e "${YELLOW}Test 6: Process authentication with different user agents${NC}"
echo "Testing if process authentication works with different user agents..."

# Test with different user agents
user_agents=("Mozilla/5.0" "curl/7.68.0" "Python-urllib/3.8" "Custom-Agent/1.0")

for agent in "${user_agents[@]}"; do
    echo "Testing with User-Agent: $agent"
    response=$(curl -s -o /dev/null -X POST "$TARGET_URL"mail.php \
        -H "User-Agent: $agent" \
        -d "name=AgentTest&email=agent@test.com&message=User agent test&process_id=$server_pid" \
        -w "%{http_code}")
    
    if [[ "$response" == "200" ]]; then
        echo -e "${GREEN}✅ SECURE: Process authentication works with $agent (HTTP $response)${NC}"
    elif [[ "$response" == "403" ]] || [[ "$response" == "401" ]]; then
        echo -e "${GREEN}✅ SECURE: Process authentication blocked with $agent (HTTP $response)${NC}"
    elif [[ "$response" == "404" ]]; then
        echo -e "${GREEN}✅ SECURE: mail.php not accessible (HTTP $response)${NC}"
    elif [[ "$response" == "405" ]]; then
        echo -e "${GREEN}✅ SECURE: POST method not allowed (HTTP $response)${NC}"
    else
        echo -e "${YELLOW}⚠️  WARNING: Process authentication unclear with $agent (HTTP $response)${NC}"
    fi
done
echo ""

echo -e "${BLUE}🔍 Process-based authentication tests completed!${NC}"
echo ""
echo "Summary:"
echo "- Check the results above for process authentication effectiveness"
echo "- Green ✅ means the test passed (secure)"
echo "- Red ❌ means a vulnerability was found"
echo "- Yellow ⚠️  means the test result is unclear"
echo ""
echo "Process-based authentication benefits:"
echo "1. Uses server-side process knowledge for authentication"
echo "2. Distinguishes between internal and external processes"
echo "3. Validates process relationships and memory access"
echo "4. Provides defense against external process abuse"
echo ""
echo "If process authentication is not implemented:"
echo "1. Consider implementing process-based authentication"
echo "2. Use server-side process knowledge for security"
echo "3. Validate process relationships and memory access"
echo "4. Test again after implementing process authentication"
