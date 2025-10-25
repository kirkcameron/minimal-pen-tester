# Minimal Pen Tester

A lightweight penetration testing toolkit for web applications, specifically designed for testing mail scripts and contact forms.

> **Portable Scripts**: All shell scripts use `#!/usr/bin/env bash` for maximum compatibility across macOS, Linux, BSD, and Docker environments.

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
- **`pen-test-scripts/quick-sec-check.sh`** - Fast security assessment (3 critical tests)
- **`pen-test-scripts/pen-test.sh`** - Comprehensive testing with detailed results
- **`pen-test-scripts/advanced-pen-test.sh`** - Professional-grade testing with multiple attack vectors

### Specialized Testing

- **`pen-test-scripts/mail-injection-tests.sh`** - Email header injection testing
- **`pen-test-scripts/input-val-tests.sh`** - XSS and SQL injection testing
- **`pen-test-scripts/web-server-sec.sh`** - Web server configuration testing
- **`pen-test-scripts/process-auth-tests.sh`** - Novel process-based authentication testing

## 🛠️ Usage Examples

```bash
# Basic testing
./pen-test-scripts/quick-sec-check.sh https://httpbin.org
./pen-test-scripts/pen-test.sh https://httpbin.org

# Comprehensive testing with report
./run-all-tests.sh -v -o security-report.txt https://httpbin.org

# Individual specialized tests
./pen-test-scripts/mail-injection-tests.sh https://httpbin.org
./pen-test-scripts/input-val-tests.sh https://httpbin.org
./pen-test-scripts/process-auth-tests.sh https://httpbin.org
```

## 📊 Test Coverage

**Vulnerability Categories:**

- Direct file access, header injection, XSS, SQL injection
- Rate limiting, input validation, directory browsing
- Process authentication (novel approach)

**Attack Vectors:**

- Email header injection, XSS payloads, SQL injection
- Path traversal, rate limiting, process ID spoofing

## 🔒 Security Considerations

- ✅ **Only test your own applications**
- ✅ **Get permission before testing**
- ⚠️ **Unauthorized testing is illegal**
- ⚠️ **Follow responsible disclosure**

## 📚 Related Projects

- **[minimal-server-mail](https://github.com/kirkcameron/minimal-server-mail)**: Secure mail script implementation

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Real-World Test Results

### Security Testing Results on httpbin.org

**Quick Security Check Results:**

```
🔍 Quick Security Check: https://httpbin.org/
✅ mail.php: SECURE (404)
✅ config.php: SECURE (404)
✅ .htaccess: SECURE (404)
🎉 All security checks passed!
```

**Comprehensive Test Summary:**

- **Total tests**: 14
- **Tests passed**: 2
- **Vulnerabilities found**: 12

**Key Findings:**

- ⚠️ **Rate limiting**: VULNERABLE (no rate limiting detected)
- ⚠️ **Security headers**: Missing X-Frame-Options, X-Content-Type-Options
- ✅ **Directory browsing**: SECURE (disabled)
- ✅ **HTTP methods**: SECURE (restricted properly)
- ✅ **Process Auth**: 83.3% success rate (10/12 tests)

**Security Assessment:**
| Test Category | Status | Details |
|---------------|--------|---------|
| Direct File Access | ✅ SECURE | All sensitive files return 404 |
| Rate Limiting | ⚠️ VULNERABLE | No rate limiting detected |
| Security Headers | ⚠️ VULNERABLE | Missing X-Frame-Options |
| Process Auth | ✅ SECURE | 83.3% success rate |

**Generate your own reports:**

```bash
./run-all-tests.sh -o security-report.txt https://httpbin.org
./pen-test-scripts/quick-sec-check.sh https://httpbin.org > quick-results.txt
```

**📄 Example Report:** See [example_test_report.txt](example_report/example_test_report.txt) for a complete test report against httpbin.org.

---

**Remember: Always test responsibly and with proper authorization!** 🛡️
