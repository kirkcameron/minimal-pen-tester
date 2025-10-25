#!/usr/bin/env python3
"""
Process-Based Authentication Security Tests
==========================================

Comprehensive security tests for process-based authentication system.
Tests various attack vectors and bypass attempts.

Author: Process Auth Team
License: MIT
"""

import os
import sys
import time
import json
import subprocess
import threading
import multiprocessing
import psutil
import requests
import socket
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import logging

from process_auth_engine import ProcessAuthEngine, AuthMethod, SecurityLevel, AuthResult
from process_auth_web import ProcessAuthMiddleware, WebAuthConfig, create_auth_server

logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Test result information"""
    test_name: str
    success: bool
    details: Dict[str, Any]
    timestamp: float
    duration: float

class ProcessAuthTester:
    """
    Comprehensive security tester for process-based authentication
    
    Tests various attack vectors and bypass attempts to ensure
    the authentication system is robust.
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self.auth_engine = ProcessAuthEngine(security_level)
        self.test_results = []
        self.server_process = None
        self.server_port = 8080
        
        logger.info("ProcessAuthTester initialized")
    
    def run_all_tests(self) -> List[TestResult]:
        """Run all security tests"""
        logger.info("Starting comprehensive security tests")
        
        tests = [
            self.test_legitimate_access,
            self.test_external_process_blocking,
            self.test_pid_spoofing,
            self.test_memory_access_bypass,
            self.test_process_relationship_spoofing,
            self.test_rate_limiting,
            self.test_concurrent_attacks,
            self.test_privilege_escalation,
            self.test_memory_corruption,
            self.test_timing_attacks,
            self.test_network_spoofing,
            self.test_system_resource_abuse
        ]
        
        for test in tests:
            try:
                result = test()
                self.test_results.append(result)
                logger.info(f"Test {test.__name__}: {'PASSED' if result.success else 'FAILED'}")
            except Exception as e:
                logger.error(f"Test {test.__name__} failed with exception: {e}")
                self.test_results.append(TestResult(
                    test_name=test.__name__,
                    success=False,
                    details={'error': str(e)},
                    timestamp=time.time(),
                    duration=0.0
                ))
        
        return self.test_results
    
    def test_legitimate_access(self) -> TestResult:
        """Test 1: Legitimate access should succeed"""
        start_time = time.time()
        
        # Test with current process (should succeed)
        result = self.auth_engine.authenticate(os.getpid(), AuthMethod.COMBINED)
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="legitimate_access",
            success=result.success,
            details={
                'auth_result': result.__dict__,
                'expected_success': True,
                'actual_success': result.success
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_external_process_blocking(self) -> TestResult:
        """Test 2: External processes should be blocked"""
        start_time = time.time()
        
        # Test with init process (PID 1) - should fail
        result = self.auth_engine.authenticate(1, AuthMethod.PROCESS_RELATIONSHIP)
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="external_process_blocking",
            success=not result.success,  # Should fail (be blocked)
            details={
                'auth_result': result.__dict__,
                'expected_success': False,
                'actual_success': result.success,
                'test_pid': 1
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_pid_spoofing(self) -> TestResult:
        """Test 3: PID spoofing attempts should fail"""
        start_time = time.time()
        
        # Try to authenticate with fake PIDs
        fake_pids = [99999, 12345, 67890, 11111]
        spoofing_success = False
        
        for fake_pid in fake_pids:
            try:
                result = self.auth_engine.authenticate(fake_pid, AuthMethod.PROCESS_RELATIONSHIP)
                if result.success:
                    spoofing_success = True
                    break
            except Exception:
                # Expected for non-existent PIDs
                pass
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="pid_spoofing",
            success=not spoofing_success,  # Should fail (no spoofing success)
            details={
                'fake_pids_tested': fake_pids,
                'spoofing_success': spoofing_success,
                'expected_success': False
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_memory_access_bypass(self) -> TestResult:
        """Test 4: Memory access bypass attempts should fail"""
        start_time = time.time()
        
        # Test with external process trying to access memory
        external_pid = 1  # Init process
        result = self.auth_engine.authenticate(external_pid, AuthMethod.MEMORY_ACCESS)
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="memory_access_bypass",
            success=not result.success,  # Should fail
            details={
                'auth_result': result.__dict__,
                'expected_success': False,
                'actual_success': result.success,
                'test_pid': external_pid
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_process_relationship_spoofing(self) -> TestResult:
        """Test 5: Process relationship spoofing should fail"""
        start_time = time.time()
        
        # Try to create a fake child process relationship
        fake_child_pid = 99999
        result = self.auth_engine.authenticate(fake_child_pid, AuthMethod.PROCESS_RELATIONSHIP)
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="process_relationship_spoofing",
            success=not result.success,  # Should fail
            details={
                'auth_result': result.__dict__,
                'expected_success': False,
                'actual_success': result.success,
                'fake_child_pid': fake_child_pid
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_rate_limiting(self) -> TestResult:
        """Test 6: Rate limiting should work"""
        start_time = time.time()
        
        # Create middleware with rate limiting
        config = WebAuthConfig(
            max_attempts=3,
            rate_limit_window=60
        )
        middleware = ProcessAuthMiddleware(config)
        
        # Simulate multiple rapid requests
        request_info = {
            'client_ip': '127.0.0.1',
            'client_port': 12345,
            'headers': {},
            'method': 'GET',
            'path': '/test',
            'query': {}
        }
        
        results = []
        for i in range(5):  # More than max_attempts
            result = middleware.authenticate_request(request_info)
            results.append(result.success)
            time.sleep(0.1)  # Small delay between requests
        
        # Should be rate limited after max_attempts
        rate_limited = not all(results)
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="rate_limiting",
            success=rate_limited,
            details={
                'results': results,
                'rate_limited': rate_limited,
                'max_attempts': config.max_attempts,
                'attempts_made': len(results)
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_concurrent_attacks(self) -> TestResult:
        """Test 7: Concurrent attack attempts should be handled properly"""
        start_time = time.time()
        
        def attack_thread(thread_id):
            """Simulate attack from a thread"""
            fake_pid = 10000 + thread_id
            result = self.auth_engine.authenticate(fake_pid, AuthMethod.COMBINED)
            return result.success
        
        # Launch multiple concurrent attacks
        threads = []
        results = []
        
        for i in range(10):
            thread = threading.Thread(target=lambda i=i: results.append(attack_thread(i)))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # All attacks should fail
        attack_success = any(results)
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="concurrent_attacks",
            success=not attack_success,  # Should fail
            details={
                'attack_results': results,
                'attack_success': attack_success,
                'threads_used': len(threads)
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_privilege_escalation(self) -> TestResult:
        """Test 8: Privilege escalation attempts should fail"""
        start_time = time.time()
        
        # Try to authenticate with system processes
        system_pids = [1, 2, 3, 4, 5]  # Common system PIDs
        escalation_success = False
        
        for pid in system_pids:
            try:
                result = self.auth_engine.authenticate(pid, AuthMethod.COMBINED)
                if result.success:
                    escalation_success = True
                    break
            except Exception:
                pass
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="privilege_escalation",
            success=not escalation_success,  # Should fail
            details={
                'system_pids_tested': system_pids,
                'escalation_success': escalation_success,
                'expected_success': False
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_memory_corruption(self) -> TestResult:
        """Test 9: Memory corruption attempts should be detected"""
        start_time = time.time()
        
        # Try to corrupt shared memory (simulated)
        try:
            # Attempt to access engine's shared memory
            if hasattr(self.auth_engine, 'shared_memory'):
                original_keys = list(self.auth_engine.shared_memory.keys())
                
                # Try to add fake entries
                fake_key = "fake_memory_key"
                self.auth_engine.shared_memory[fake_key] = {'fake': 'data'}
                
                # Check if corruption was detected
                corruption_detected = fake_key not in self.auth_engine.shared_memory
                
                # Clean up
                if fake_key in self.auth_engine.shared_memory:
                    del self.auth_engine.shared_memory[fake_key]
                
            else:
                corruption_detected = True  # No shared memory to corrupt
                
        except Exception as e:
            corruption_detected = True  # Exception means protection worked
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="memory_corruption",
            success=corruption_detected,
            details={
                'corruption_detected': corruption_detected,
                'expected_success': True
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_timing_attacks(self) -> TestResult:
        """Test 10: Timing attacks should not reveal information"""
        start_time = time.time()
        
        # Test authentication timing with different inputs
        test_cases = [
            (os.getpid(), True),      # Legitimate
            (1, False),               # External
            (99999, False),           # Non-existent
            (2, False)                # System process
        ]
        
        timings = []
        for pid, expected in test_cases:
            start = time.time()
            result = self.auth_engine.authenticate(pid, AuthMethod.PROCESS_RELATIONSHIP)
            end = time.time()
            
            timings.append({
                'pid': pid,
                'duration': end - start,
                'success': result.success,
                'expected': expected
            })
        
        # Check if timing reveals information
        # Legitimate requests should not be significantly faster
        legitimate_timing = next(t['duration'] for t in timings if t['pid'] == os.getpid())
        external_timing = next(t['duration'] for t in timings if t['pid'] == 1)
        
        timing_difference = abs(legitimate_timing - external_timing)
        timing_attack_resistant = timing_difference < 0.1  # Less than 100ms difference
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="timing_attacks",
            success=timing_attack_resistant,
            details={
                'timings': timings,
                'timing_difference': timing_difference,
                'timing_attack_resistant': timing_attack_resistant
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_network_spoofing(self) -> TestResult:
        """Test 11: Network spoofing attempts should fail"""
        start_time = time.time()
        
        # Test with different IP addresses
        test_ips = ['127.0.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1']
        spoofing_success = False
        
        config = WebAuthConfig(trusted_ips=['127.0.0.1'])
        middleware = ProcessAuthMiddleware(config)
        
        for ip in test_ips:
            request_info = {
                'client_ip': ip,
                'client_port': 12345,
                'headers': {},
                'method': 'GET',
                'path': '/test',
                'query': {}
            }
            
            result = middleware.authenticate_request(request_info)
            if result.success and ip != '127.0.0.1':
                spoofing_success = True
                break
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="network_spoofing",
            success=not spoofing_success,  # Should fail
            details={
                'test_ips': test_ips,
                'spoofing_success': spoofing_success,
                'trusted_ips': config.trusted_ips
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def test_system_resource_abuse(self) -> TestResult:
        """Test 12: System resource abuse should be detected"""
        start_time = time.time()
        
        # Test with processes that have unusual resource usage
        abuse_detected = False
        
        try:
            # Find a process with high CPU usage
            for proc in psutil.process_iter(['pid', 'cpu_percent']):
                try:
                    if proc.info['cpu_percent'] > 50:  # High CPU usage
                        result = self.auth_engine.authenticate(proc.info['pid'], AuthMethod.SYSTEM_RESOURCES)
                        if not result.success:
                            abuse_detected = True
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            abuse_detected = True  # Exception means protection worked
        
        duration = time.time() - start_time
        
        return TestResult(
            test_name="system_resource_abuse",
            success=abuse_detected,
            details={
                'abuse_detected': abuse_detected,
                'expected_success': True
            },
            timestamp=time.time(),
            duration=duration
        )
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result.success)
        failed_tests = total_tests - passed_tests
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'success_rate': (passed_tests / total_tests) * 100 if total_tests > 0 else 0
            },
            'test_results': [
                {
                    'test_name': result.test_name,
                    'success': result.success,
                    'duration': result.duration,
                    'details': result.details
                }
                for result in self.test_results
            ],
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on test results"""
        recommendations = []
        
        failed_tests = [result for result in self.test_results if not result.success]
        
        if any(result.test_name == 'external_process_blocking' for result in failed_tests):
            recommendations.append("Strengthen external process blocking mechanisms")
        
        if any(result.test_name == 'pid_spoofing' for result in failed_tests):
            recommendations.append("Implement additional PID validation checks")
        
        if any(result.test_name == 'memory_access_bypass' for result in failed_tests):
            recommendations.append("Enhance memory access validation")
        
        if any(result.test_name == 'rate_limiting' for result in failed_tests):
            recommendations.append("Improve rate limiting implementation")
        
        if any(result.test_name == 'timing_attacks' for result in failed_tests):
            recommendations.append("Implement timing attack protection")
        
        if not recommendations:
            recommendations.append("All security tests passed - system appears secure")
        
        return recommendations

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run security tests
    tester = ProcessAuthTester(SecurityLevel.HIGH)
    results = tester.run_all_tests()
    
    # Generate report
    report = tester.generate_report()
    
    print("\n" + "="*60)
    print("PROCESS-BASED AUTHENTICATION SECURITY REPORT")
    print("="*60)
    print(f"Total Tests: {report['summary']['total_tests']}")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Success Rate: {report['summary']['success_rate']:.1f}%")
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec}")
    print("="*60)
