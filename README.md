# Minimal Pen Tester

A lightweight penetration testing toolkit for web applications, specifically designed for testing mail scripts and contact forms.

> **Portable Scripts**: All shell scripts use `#!/usr/bin/env bash` for maximum compatibility across macOS, Linux, BSD, and Docker environments.

## ⚠️ Important: This is a Penetration Testing Tool

**This tool is designed for authorized penetration testing only. It sends malicious payloads and tests security boundaries. Use responsibly and only on systems you own or have explicit permission to test.**

## 🌐 What is httpbin.org?

**httpbin.org is a free HTTP testing service** perfect for learning security tools:

- ✅ **Safe testing environment** - No risk of damaging real systems
- ✅ **Always available** - Reliable 24/7 testing target
- ✅ **No legal concerns** - Designed specifically for testing purposes

**Think of it as a "practice target"** - like a shooting range for security testing.

## 🚀 Quick Start

```bash
# Clone and test against httpbin.org (safe testing service)
git clone https://github.com/kirkcameron/minimal-pen-tester.git
cd minimal-pen-tester
./run-all-tests.sh https://httpbin.org

# Test your own site
./quick-security-check.sh https://yoursite.com
./run-all-tests.sh -v -o results.txt https://yoursite.com
```

## 📋 Available Scripts

### Core Testing

- **`run-all-tests.sh`** - Main entry point - runs all tests with comprehensive reporting
- **`pen-test-scripts/quick-security-check.sh`** - Fast security assessment (3 critical tests)
- **`pen-test-scripts/pen-test.sh`** - Comprehensive testing with detailed results
- **`pen-test-scripts/advanced-pen-test.sh`** - Advanced testing with multiple attack vectors

### Specialized Testing

- **`pen-test-scripts/mail-injection-tests.sh`** - Email header injection testing
- **`pen-test-scripts/input-validation-tests.sh`** - XSS and SQL injection testing
- **`pen-test-scripts/web-server-security.sh`** - Web server configuration testing
- **`pen-test-scripts/process-auth-tests.sh`** - Process-based authentication testing

## 🛠️ Usage Examples

```bash
# Basic testing
./pen-test-scripts/quick-security-check.sh https://httpbin.org
./pen-test-scripts/pen-test.sh https://httpbin.org

# Comprehensive testing with report
./run-all-tests.sh -v -o security-report.txt https://httpbin.org

# Individual specialized tests
./pen-test-scripts/mail-injection-tests.sh https://httpbin.org
./pen-test-scripts/input-validation-tests.sh https://httpbin.org
./pen-test-scripts/web-server-security.sh https://httpbin.org
./pen-test-scripts/process-auth-tests.sh https://httpbin.org
```

## 📊 Test Coverage

**Vulnerability Categories:**

- Direct file access, header injection, XSS, SQL injection
- Rate limiting, input validation, directory browsing
- Process-based security testing (experimental approach)

**Attack Vectors:**

- Email header injection, XSS payloads, SQL injection
- Path traversal, rate limiting, process relationship testing

## 🧪 Process-Based Security Testing

**What It Tests:** Whether target applications can distinguish between internal and external processes.

**How It Works:**

1. **Simulates internal processes** (legitimate application requests)
2. **Simulates external processes** (attack tools, automated scripts)
3. **Tests process authentication bypasses**
4. **Identifies process-based security weaknesses**

**What It Identifies:**

- Process isolation mechanisms
- Process-based access controls
- System-level security boundaries
- Process relationship validation

**Note:** This is a **testing technique**, not a security feature. It tests whether targets implement process-based security controls.

## 🔒 Security Considerations

- ✅ **Only test your own applications**
- ✅ **Get permission before testing**
- ⚠️ **Unauthorized testing is illegal**
- ⚠️ **Follow responsible disclosure**
- ⚠️ **This tool sends malicious payloads - use responsibly**
- ⚠️ **Process-based testing is experimental - results may vary**

## 📚 Related Projects

- **[minimal-server-mail](https://github.com/kirkcameron/minimal-server-mail)**: Secure mail script implementation

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📄 Example Report

See [example_test_report.txt](example_report/example_test_report.txt) for a complete test report against httpbin.org.

---

**Remember: This is a penetration testing tool that sends malicious payloads. Always test responsibly and with proper authorization!** 🛡️

## ⚠️ Process Authentication Disclaimer

**Important:** The process-based security testing included in this toolkit is **experimental** and should not be relied upon for production security. It is designed to test whether target applications implement process-based security controls, not to provide security for your applications.

**What it actually does:**

- Tests if targets can distinguish between internal/external processes
- Identifies process-based security mechanisms
- Tests process authentication bypasses
- Validates system-level security boundaries

**What it does NOT do:**

- Provide secure authentication
- Guarantee security
- Replace proper security measures
- Work reliably in all environments
