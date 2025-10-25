#!/usr/bin/env bash
# Comprehensive Test Runner
# Runs all penetration tests and generates a comprehensive report
# Uses portable shebang for cross-platform compatibility

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

TARGET_URL="$1"
OUTPUT_FILE=""
VERBOSE=false
QUICK=false

# Help function
show_help() {
    echo "Comprehensive Test Runner for minimal-pen-tester"
    echo ""
    echo "Usage: $0 [OPTIONS] <TARGET_URL>"
    echo ""
    echo "Options:"
    echo "  -v, --verbose       Verbose output"
    echo "  -q, --quick         Quick tests only"
    echo "  -o, --output FILE   Save results to file"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 https://example.com/contact"
    echo "  $0 -v -o report.txt https://example.com/contact"
    echo "  $0 -q https://example.com/contact"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -q|--quick)
            QUICK=true
            shift
            ;;
        -o|--output)
            if [[ -z "$2" ]]; then
                echo "Error: -o requires a filename"
                exit 1
            fi
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            echo "Error: Unknown option $1"
            show_help
            exit 1
            ;;
        *)
            # This is the URL - should be the last argument
            TARGET_URL="$1"
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

# Validate URL format
if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
    echo -e "${RED}Error: URL must start with http:// or https://${NC}"
    echo "Provided: $TARGET_URL"
    exit 1
fi

# Ensure URL ends with /
if [[ ! "$TARGET_URL" =~ /$ ]]; then
    TARGET_URL="${TARGET_URL}/"
fi

# Debug output for troubleshooting
if [[ "$VERBOSE" == "true" ]]; then
    echo -e "${BLUE}Debug: Parsed arguments${NC}"
    echo "  TARGET_URL: $TARGET_URL"
    echo "  VERBOSE: $VERBOSE"
    echo "  QUICK: $QUICK"
    echo "  OUTPUT_FILE: $OUTPUT_FILE"
    echo ""
fi

# Initialize output file if specified
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "Comprehensive Penetration Test Report" > "$OUTPUT_FILE"
    echo "Target: $TARGET_URL" >> "$OUTPUT_FILE"
    echo "Date: $(date)" >> "$OUTPUT_FILE"
    echo "Mode: $([ "$QUICK" == "true" ] && echo "Quick" || echo "Comprehensive")" >> "$OUTPUT_FILE"
    echo "=================================" >> "$OUTPUT_FILE"
fi

echo -e "${PURPLE}[INFO] Comprehensive Penetration Testing${NC}"
echo -e "${PURPLE}Target: $TARGET_URL${NC}"
echo -e "${PURPLE}Mode: $([ "$QUICK" == "true" ] && echo "Quick" || echo "Comprehensive")${NC}"
echo ""

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
VULNERABILITIES=0

# Function to run test and count results
run_test() {
    local test_name="$1"
    local test_script="$2"
    local test_args="$3"
    
    echo -e "${BLUE}Running: $test_name${NC}"
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo "Command: ./$test_script $test_args"
    fi
    
    # Run the test
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "" >> "$OUTPUT_FILE"
        echo "=== $test_name ===" >> "$OUTPUT_FILE"
        ./$test_script $test_args >> "$OUTPUT_FILE" 2>&1
    else
        ./$test_script $test_args
    fi
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Simple heuristic: if test exits with 0, it passed
    if [[ $? -eq 0 ]]; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
    
    echo ""
}

# Always run quick security check
echo -e "${YELLOW}=== QUICK SECURITY CHECK ===${NC}"
run_test "Quick Security Check" "pen-test-scripts/quick-security-check.sh" "$TARGET_URL"

if [[ "$QUICK" == "true" ]]; then
    echo -e "${GREEN}[SUCCESS] Quick security check completed!${NC}"
    echo ""
    echo "For comprehensive testing, run without -q flag"
    exit 0
fi

# Comprehensive testing
echo -e "${YELLOW}=== COMPREHENSIVE TESTING ===${NC}"

# Core penetration tests
echo -e "${YELLOW}=== CORE PENETRATION TESTS ===${NC}"
run_test "Basic Penetration Test" "pen-test-scripts/pen-test.sh" "$TARGET_URL"

# Specialized tests
echo -e "${YELLOW}=== SPECIALIZED TESTS ===${NC}"
run_test "Mail Injection Tests" "pen-test-scripts/mail-injection-tests.sh" "$TARGET_URL"
run_test "Input Validation Tests" "pen-test-scripts/input-validation-tests.sh" "$TARGET_URL"
run_test "Web Server Security Tests" "pen-test-scripts/web-server-security.sh" "$TARGET_URL"

# Advanced testing
echo -e "${YELLOW}=== ADVANCED TESTING ===${NC}"
run_test "Advanced Penetration Test" "pen-test-scripts/advanced-pen-test.sh" "$TARGET_URL"

# Generate final report
echo -e "${PURPLE}=== FINAL REPORT ===${NC}"
echo -e "${BLUE}Total test suites: $TOTAL_TESTS${NC}"
echo -e "${GREEN}Test suites passed: $PASSED_TESTS${NC}"

if [[ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ]]; then
    echo -e "${GREEN}[SUCCESS] All test suites completed successfully!${NC}"
else
    echo -e "${YELLOW}[WARNING] Some test suites had issues${NC}"
fi

echo ""
echo -e "${YELLOW}Recommendations:${NC}"
echo "1. Review all test results above"
echo "2. Fix any vulnerabilities found"
echo "3. Re-run tests after implementing fixes"
echo "4. Consider regular security testing"
echo "5. Implement continuous security monitoring"

if [[ -n "$OUTPUT_FILE" ]]; then
    echo ""
    echo "Detailed results saved to: $OUTPUT_FILE"
fi

echo ""
echo -e "${PURPLE}[INFO] Comprehensive penetration testing completed!${NC}"
