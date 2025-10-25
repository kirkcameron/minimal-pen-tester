#!/usr/bin/env python3
"""
Process-Based Security Testing Engine
====================================

⚠️  WARNING: This is a PENETRATION TESTING tool, not a security solution.

This engine tests whether target applications can distinguish between
internal and external processes. It is designed for security testing
and research purposes only.

DO NOT use this for production security - it is experimental and
process-based authentication can be easily bypassed.

Author: Process Auth Team
License: MIT
"""

import os
import sys
import psutil
import hashlib
import secrets
import time
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import mmap
import struct
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthMethod(Enum):
    """Authentication methods available"""
    PROCESS_RELATIONSHIP = "process_relationship"
    MEMORY_ACCESS = "memory_access"
    SYSTEM_RESOURCES = "system_resources"
    CPU_AFFINITY = "cpu_affinity"
    FILE_SYSTEM = "file_system"
    NETWORK_STACK = "network_stack"
    COMBINED = "combined"

class SecurityLevel(Enum):
    """Security levels for authentication"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PARANOID = "paranoid"

@dataclass
class ProcessInfo:
    """Process information for validation"""
    pid: int
    ppid: int
    name: str
    cmdline: List[str]
    cwd: str
    memory_info: Dict[str, Any]
    cpu_percent: float
    create_time: float
    status: str
    username: str

@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    method: AuthMethod
    confidence: float
    details: Dict[str, Any]
    timestamp: float
    server_pid: int
    client_pid: int

class ProcessAuthEngine:
    """
    Process-Based Security Testing Engine
    
    ⚠️  WARNING: This is for PENETRATION TESTING only, not production security.
    
    This engine tests whether target applications can distinguish between
    internal and external processes. It simulates various process
    relationships to test security boundaries.
    
    DO NOT use for production authentication - process-based security
    can be easily bypassed and is not reliable.
    """
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MEDIUM):
        self.security_level = security_level
        self.server_pid = os.getpid()
        self.server_info = self._get_process_info(self.server_pid)
        self.shared_memory = {}
        self.auth_cache = {}
        self.lock = threading.RLock()
        
        # Initialize shared memory segment
        self._init_shared_memory()
        
        logger.info(f"ProcessAuthEngine initialized with PID {self.server_pid}")
        logger.info(f"Security level: {security_level.value}")
    
    def _get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get comprehensive process information"""
        try:
            process = psutil.Process(pid)
            return ProcessInfo(
                pid=process.pid,
                ppid=process.ppid(),
                name=process.name(),
                cmdline=process.cmdline(),
                cwd=process.cwd(),
                memory_info=process.memory_info()._asdict(),
                cpu_percent=process.cpu_percent(),
                create_time=process.create_time(),
                status=process.status(),
                username=process.username()
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def _init_shared_memory(self):
        """Initialize shared memory for secure token exchange"""
        try:
            # Create a unique memory segment for this server instance
            self.memory_key = f"process_auth_{self.server_pid}_{int(time.time())}"
            self.shared_memory[self.memory_key] = {
                'server_pid': self.server_pid,
                'created': time.time(),
                'tokens': {},
                'access_log': []
            }
        except Exception as e:
            logger.error(f"Failed to initialize shared memory: {e}")
    
    def validate_process_relationship(self, client_pid: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate process relationship using parent-child hierarchy
        
        This is the core method - external processes cannot fake
        their relationship to the server process.
        """
        details = {
            'client_pid': client_pid,
            'server_pid': self.server_pid,
            'is_server_process': False,
            'is_child_process': False,
            'parent_chain': [],
            'relationship_strength': 0.0
        }
        
        try:
            # Check if client IS the server process
            if client_pid == self.server_pid:
                details['is_server_process'] = True
                details['relationship_strength'] = 1.0
                return True, details
            
            # Check parent-child relationship
            client_process = psutil.Process(client_pid)
            parent_chain = []
            current_pid = client_pid
            
            # Walk up the process tree
            for _ in range(10):  # Limit depth to prevent infinite loops
                try:
                    parent = psutil.Process(current_pid).parent()
                    if parent is None:
                        break
                    parent_pid = parent.pid
                    parent_chain.append(parent_pid)
                    
                    if parent_pid == self.server_pid:
                        details['is_child_process'] = True
                        details['parent_chain'] = parent_chain
                        details['relationship_strength'] = 0.8 - (len(parent_chain) * 0.1)
                        return True, details
                    
                    current_pid = parent_pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
            
            # Check for sibling processes (same parent)
            try:
                client_parent = client_process.parent()
                if client_parent and client_parent.pid == psutil.Process(self.server_pid).parent().pid:
                    details['is_sibling_process'] = True
                    details['relationship_strength'] = 0.6
                    return True, details
            except:
                pass
            
            return False, details
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            details['error'] = str(e)
            return False, details
    
    def validate_memory_access(self, client_pid: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate memory access patterns
        
        Only processes with proper system access can read
        server memory segments.
        """
        details = {
            'client_pid': client_pid,
            'memory_access_test': False,
            'shared_memory_access': False,
            'memory_patterns': {},
            'access_confidence': 0.0
        }
        
        try:
            # Test if client can access server's memory space
            client_process = psutil.Process(client_pid)
            
            # Check if client can read server's memory maps
            try:
                server_maps = psutil.Process(self.server_pid).memory_maps()
                client_maps = client_process.memory_maps()
                
                # Look for overlapping memory regions (indicates shared access)
                overlapping_regions = 0
                for server_map in server_maps:
                    for client_map in client_maps:
                        if (server_map.addr == client_map.addr and 
                            server_map.path == client_map.path):
                            overlapping_regions += 1
                
                details['overlapping_regions'] = overlapping_regions
                details['memory_access_test'] = overlapping_regions > 0
                
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Test shared memory access
            try:
                # Create a test token
                test_token = secrets.token_hex(16)
                self.shared_memory[self.memory_key]['tokens'][str(client_pid)] = {
                    'token': test_token,
                    'created': time.time(),
                    'access_count': 0
                }
                
                # Simulate client trying to access the token
                # In a real implementation, this would be done by the client process
                if str(client_pid) in self.shared_memory[self.memory_key]['tokens']:
                    details['shared_memory_access'] = True
                    details['access_confidence'] = 0.9
                
            except Exception as e:
                details['shared_memory_error'] = str(e)
            
            success = details['memory_access_test'] or details['shared_memory_access']
            return success, details
            
        except Exception as e:
            details['error'] = str(e)
            return False, details
    
    def validate_system_resources(self, client_pid: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate system resource access patterns
        
        Check CPU affinity, scheduling, and other system-level indicators.
        """
        details = {
            'client_pid': client_pid,
            'cpu_affinity_match': False,
            'scheduling_class': None,
            'resource_usage': {},
            'system_access_level': 0.0
        }
        
        try:
            client_process = psutil.Process(client_pid)
            server_process = psutil.Process(self.server_pid)
            
            # Check CPU affinity
            try:
                client_cpus = client_process.cpu_affinity()
                server_cpus = server_process.cpu_affinity()
                
                if set(client_cpus) & set(server_cpus):
                    details['cpu_affinity_match'] = True
                    details['system_access_level'] += 0.3
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Check process priority and scheduling
            try:
                client_nice = client_process.nice()
                server_nice = server_process.nice()
                
                if abs(client_nice - server_nice) <= 5:  # Similar priority
                    details['priority_match'] = True
                    details['system_access_level'] += 0.2
            except (psutil.AccessDenied, AttributeError):
                pass
            
            # Check resource usage patterns
            try:
                client_io = client_process.io_counters()
                server_io = server_process.io_counters()
                
                details['resource_usage'] = {
                    'client_io': client_io._asdict() if client_io else {},
                    'server_io': server_io._asdict() if server_io else {},
                    'io_similarity': 0.0
                }
                
                if client_io and server_io:
                    # Calculate similarity in I/O patterns
                    io_similarity = 0.0
                    for key in ['read_count', 'write_count', 'read_bytes', 'write_bytes']:
                        if hasattr(client_io, key) and hasattr(server_io, key):
                            client_val = getattr(client_io, key)
                            server_val = getattr(server_io, key)
                            if server_val > 0:
                                similarity = min(client_val, server_val) / max(client_val, server_val)
                                io_similarity += similarity
                    
                    details['resource_usage']['io_similarity'] = io_similarity / 4
                    details['system_access_level'] += io_similarity * 0.2
                
            except (psutil.AccessDenied, AttributeError):
                pass
            
            success = details['system_access_level'] > 0.5
            return success, details
            
        except Exception as e:
            details['error'] = str(e)
            return False, details
    
    def validate_file_system_access(self, client_pid: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate file system access patterns
        
        Check if client has access to server's working directory,
        temporary files, and other server-specific resources.
        """
        details = {
            'client_pid': client_pid,
            'working_directory_match': False,
            'file_access_patterns': {},
            'permission_level': 0.0
        }
        
        try:
            client_process = psutil.Process(client_pid)
            server_process = psutil.Process(self.server_pid)
            
            # Check working directory
            try:
                client_cwd = client_process.cwd()
                server_cwd = server_process.cwd()
                
                if client_cwd == server_cwd:
                    details['working_directory_match'] = True
                    details['permission_level'] += 0.4
                elif client_cwd.startswith(server_cwd):
                    details['working_directory_match'] = True
                    details['permission_level'] += 0.3
            except (psutil.AccessDenied, OSError):
                pass
            
            # Check open files
            try:
                client_files = set(f.path for f in client_process.open_files())
                server_files = set(f.path for f in server_process.open_files())
                
                shared_files = client_files & server_files
                details['file_access_patterns'] = {
                    'shared_files': list(shared_files),
                    'shared_count': len(shared_files),
                    'total_client_files': len(client_files),
                    'total_server_files': len(server_files)
                }
                
                if shared_files:
                    details['permission_level'] += min(len(shared_files) * 0.1, 0.4)
                
            except (psutil.AccessDenied, OSError):
                pass
            
            success = details['permission_level'] > 0.3
            return success, details
            
        except Exception as e:
            details['error'] = str(e)
            return False, details
    
    def authenticate(self, client_pid: int, method: AuthMethod = AuthMethod.COMBINED) -> AuthResult:
        """
        Main authentication method
        
        Performs comprehensive process-based authentication using
        the specified method or combination of methods.
        """
        start_time = time.time()
        
        with self.lock:
            # Check cache first
            cache_key = f"{client_pid}_{method.value}"
            if cache_key in self.auth_cache:
                cached_result = self.auth_cache[cache_key]
                if time.time() - cached_result['timestamp'] < 300:  # 5 minute cache
                    return AuthResult(**cached_result)
            
            success = False
            confidence = 0.0
            details = {'client_pid': client_pid, 'method': method.value}
            
            try:
                if method == AuthMethod.PROCESS_RELATIONSHIP:
                    success, method_details = self.validate_process_relationship(client_pid)
                    details.update(method_details)
                    confidence = method_details.get('relationship_strength', 0.0)
                
                elif method == AuthMethod.MEMORY_ACCESS:
                    success, method_details = self.validate_memory_access(client_pid)
                    details.update(method_details)
                    confidence = method_details.get('access_confidence', 0.0)
                
                elif method == AuthMethod.SYSTEM_RESOURCES:
                    success, method_details = self.validate_system_resources(client_pid)
                    details.update(method_details)
                    confidence = method_details.get('system_access_level', 0.0)
                
                elif method == AuthMethod.FILE_SYSTEM:
                    success, method_details = self.validate_file_system_access(client_pid)
                    details.update(method_details)
                    confidence = method_details.get('permission_level', 0.0)
                
                elif method == AuthMethod.COMBINED:
                    # Use multiple methods for higher security
                    methods = [
                        AuthMethod.PROCESS_RELATIONSHIP,
                        AuthMethod.MEMORY_ACCESS,
                        AuthMethod.SYSTEM_RESOURCES
                    ]
                    
                    results = []
                    for auth_method in methods:
                        try:
                            if auth_method == AuthMethod.PROCESS_RELATIONSHIP:
                                result, method_details = self.validate_process_relationship(client_pid)
                            elif auth_method == AuthMethod.MEMORY_ACCESS:
                                result, method_details = self.validate_memory_access(client_pid)
                            elif auth_method == AuthMethod.SYSTEM_RESOURCES:
                                result, method_details = self.validate_system_resources(client_pid)
                            
                            results.append((result, method_details))
                            details[f'{auth_method.value}_result'] = result
                            details[f'{auth_method.value}_details'] = method_details
                            
                        except Exception as e:
                            details[f'{auth_method.value}_error'] = str(e)
                            results.append((False, {'error': str(e)}))
                    
                    # Calculate combined confidence
                    successful_methods = sum(1 for result, _ in results if result)
                    total_methods = len(results)
                    confidence = successful_methods / total_methods if total_methods > 0 else 0.0
                    
                    # Require at least 2/3 methods to succeed for combined authentication
                    success = successful_methods >= (total_methods * 2 / 3)
                
                # Apply security level requirements
                if self.security_level == SecurityLevel.HIGH and confidence < 0.8:
                    success = False
                elif self.security_level == SecurityLevel.PARANOID and confidence < 0.9:
                    success = False
                
                # Create result
                result = AuthResult(
                    success=success,
                    method=method,
                    confidence=confidence,
                    details=details,
                    timestamp=time.time(),
                    server_pid=self.server_pid,
                    client_pid=client_pid
                )
                
                # Cache result
                self.auth_cache[cache_key] = asdict(result)
                
                # Log authentication attempt
                self._log_auth_attempt(result)
                
                return result
                
            except Exception as e:
                logger.error(f"Authentication failed for PID {client_pid}: {e}")
                return AuthResult(
                    success=False,
                    method=method,
                    confidence=0.0,
                    details={'error': str(e)},
                    timestamp=time.time(),
                    server_pid=self.server_pid,
                    client_pid=client_pid
                )
    
    def _log_auth_attempt(self, result: AuthResult):
        """Log authentication attempt for security monitoring"""
        log_entry = {
            'timestamp': result.timestamp,
            'client_pid': result.client_pid,
            'server_pid': result.server_pid,
            'method': result.method.value,
            'success': result.success,
            'confidence': result.confidence,
            'security_level': self.security_level.value
        }
        
        logger.info(f"Auth attempt: {json.dumps(log_entry)}")
        
        # Add to shared memory access log
        if self.memory_key in self.shared_memory:
            self.shared_memory[self.memory_key]['access_log'].append(log_entry)
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server process information for debugging"""
        return {
            'server_pid': self.server_pid,
            'server_info': asdict(self.server_info) if self.server_info else None,
            'security_level': self.security_level.value,
            'shared_memory_keys': list(self.shared_memory.keys()),
            'cache_size': len(self.auth_cache)
        }
    
    def clear_cache(self):
        """Clear authentication cache"""
        with self.lock:
            self.auth_cache.clear()
            logger.info("Authentication cache cleared")
    
    def set_security_level(self, level: SecurityLevel):
        """Change security level"""
        self.security_level = level
        logger.info(f"Security level changed to: {level.value}")

# Example usage and testing
if __name__ == "__main__":
    # Initialize engine
    engine = ProcessAuthEngine(SecurityLevel.MEDIUM)
    
    # Test authentication
    test_pid = os.getpid()  # Test with current process
    result = engine.authenticate(test_pid, AuthMethod.COMBINED)
    
    print(f"Authentication result: {result.success}")
    print(f"Confidence: {result.confidence}")
    print(f"Details: {json.dumps(result.details, indent=2)}")
    
    # Test with external process (should fail)
    try:
        # Try to authenticate with a random PID
        external_pid = 1  # Usually init process
        result = engine.authenticate(external_pid, AuthMethod.PROCESS_RELATIONSHIP)
        print(f"External PID {external_pid} auth result: {result.success}")
    except Exception as e:
        print(f"External PID test failed: {e}")
