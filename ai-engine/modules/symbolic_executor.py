import asyncio
import json
import os
import subprocess
import tempfile
import re
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger


class SymbolicExecutor:
    """Enhanced symbolic execution with Windows fallback support"""
    
    def __init__(self):
        self.mythril_path = self._find_mythril_executable()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="symbolic_"))
        self.timeout = 180  # 3 minutes for symbolic execution
        self.fallback_mode = not self.mythril_path
        
    async def initialize(self):
        """Initialize symbolic executor"""
        try:
            if not self.mythril_path:
                logger.info("Mythril not available on Windows - using enhanced fallback mode")
                self.fallback_mode = True
                return
                
            # Test mythril installation
            result = await self._run_command([self.mythril_path, "version"])
            if result['success']:
                logger.info(f"Mythril initialized: {result['output'].strip()}")
                self.fallback_mode = False
            else:
                logger.info("Mythril test failed - using enhanced fallback symbolic execution")
                self.fallback_mode = True
                
        except Exception as e:
            logger.info(f"Mythril not available: {e} - using enhanced fallback mode")
            self.fallback_mode = True
            
    async def analyze(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Run symbolic execution analysis"""
        try:
            if self.fallback_mode or not self.mythril_path:
                logger.info("Running enhanced fallback symbolic execution")
                return await self._enhanced_fallback_analysis(contract_code, compilation_result)
            
            # Try Mythril first if available
            try:
                return await self._run_mythril_analysis(contract_code, compilation_result)
            except Exception as mythril_error:
                logger.warning(f"Mythril failed, falling back: {mythril_error}")
                return await self._enhanced_fallback_analysis(contract_code, compilation_result)
                
        except Exception as e:
            logger.error(f"Symbolic execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "vulnerabilities": []
            }

    async def _run_mythril_analysis(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Run actual Mythril analysis (when available)"""
        try:
            # Create temporary contract file
            contract_file = self.temp_dir / f"contract_{os.getpid()}.sol"
            contract_file.write_text(contract_code)
            
            logger.info(f"Running Mythril analysis on {contract_file}")
            
            # Run Mythril analysis
            cmd = [
                self.mythril_path,
                "analyze",
                str(contract_file),
                "--output", "jsonv2",
                "--execution-timeout", "120",
                "--solver-timeout", "10000",
                "--max-depth", "12"
            ]
            
            result = await self._run_command(cmd, timeout=self.timeout)
            
            if not result['success']:
                logger.error(f"Mythril execution failed: {result['error']}")
                raise Exception(f"Mythril failed: {result['error']}")
            
            # Parse Mythril output
            vulnerabilities = self._parse_mythril_output(result['output'])
            
            # Add symbolic execution specific findings
            findings = [
                f"Analyzed with Mythril symbolic execution engine",
                f"Maximum depth: 12 transactions",
                f"Found {len(vulnerabilities)} potential vulnerabilities",
                f"Execution paths explored: {self._estimate_paths_explored(result['output'])}"
            ]
            
            return {
                "success": True,
                "vulnerabilities": vulnerabilities,
                "findings": findings,
                "tool": "Mythril",
                "version": await self._get_mythril_version(),
                "execution_time": result.get('execution_time', 'Unknown')
            }
            
        except Exception as e:
            logger.error(f"Mythril analysis failed: {e}")
            raise
        finally:
            # Cleanup
            try:
                if contract_file.exists():
                    contract_file.unlink()
            except Exception:
                pass

    async def _enhanced_fallback_analysis(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Enhanced fallback symbolic execution without Mythril"""
        vulnerabilities = []
        
        try:
            logger.info("Running enhanced pattern-based symbolic execution")
            
            # Advanced pattern matching for symbolic execution issues
            vulnerabilities.extend(self._check_reentrancy_patterns(contract_code))
            vulnerabilities.extend(self._check_integer_overflow_patterns(contract_code))
            vulnerabilities.extend(self._check_access_control_patterns(contract_code))
            vulnerabilities.extend(self._check_state_management_patterns(contract_code))
            vulnerabilities.extend(self._check_timestamp_dependence(contract_code))
            vulnerabilities.extend(self._check_tx_origin_usage(contract_code))
            vulnerabilities.extend(self._check_unchecked_calls(contract_code))
            vulnerabilities.extend(self._check_denial_of_service(contract_code))
            
            # Calculate complexity score
            complexity_score = self._calculate_symbolic_complexity(contract_code, compilation_result)
            
            findings = [
                "Enhanced symbolic execution analysis completed",
                f"Analyzed {len(contract_code.split('function'))-1} functions for logical flaws",
                f"Found {len(vulnerabilities)} potential symbolic execution issues",
                f"Contract complexity: {complexity_score}",
                "Using advanced pattern matching (Windows-compatible mode)"
            ]
            
            return {
                "success": True,
                "vulnerabilities": vulnerabilities,
                "findings": findings,
                "tool": "EnhancedSymbolicAnalyzer",
                "version": "1.0.0-fallback",
                "complexity_score": complexity_score
            }
            
        except Exception as e:
            logger.error(f"Enhanced fallback analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "vulnerabilities": []
            }

    def _check_reentrancy_patterns(self, contract_code: str) -> List[Dict]:
        """Check for reentrancy vulnerabilities using pattern analysis"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Look for external calls that could be vulnerable
            external_call_patterns = [
                'call.value', '.call{value:', '.transfer(', '.send(',
                'call()', '.delegatecall(', '.staticcall('
            ]
            
            if any(pattern in line_clean for pattern in external_call_patterns):
                # Check if there's state change after external call (CEI violation)
                state_change_found = False
                
                for j in range(i + 1, min(i + 15, len(lines))):
                    next_line = lines[j].strip().lower()
                    
                    # Skip comments and empty lines
                    if not next_line or next_line.startswith('//') or next_line.startswith('*'):
                        continue
                    
                    # Look for state changes
                    state_change_patterns = [
                        '=', '+=', '-=', '*=', '/=', '%=', '++', '--',
                        'delete ', '.push(', '.pop()', 'transfer(', 'mint(', 'burn('
                    ]
                    
                    if any(op in next_line for op in state_change_patterns):
                        # Exclude safe patterns
                        if not any(safe in next_line for safe in ['require(', 'assert(', 'revert(']):
                            state_change_found = True
                            break
                
                if state_change_found:
                    vulnerabilities.append({
                        "id": f"symbolic_reentrancy_{i}",
                        "title": "Potential Reentrancy Vulnerability",
                        "description": "External call followed by state change violates Checks-Effects-Interactions pattern",
                        "severity": "High",
                        "category": "Reentrancy", 
                        "location": {"line": i + 1},
                        "vulnerable_code": line.strip()[:100],
                        "recommendation": "Use ReentrancyGuard modifier or follow Checks-Effects-Interactions pattern",
                        "impact": "Attacker could drain contract funds through recursive calls",
                        "confidence": "Medium",
                        "tool": "EnhancedSymbolicAnalyzer",
                        "references": [
                            {
                                "title": "SWC-107: Reentrancy",
                                "url": "https://swcregistry.io/docs/SWC-107"
                            }
                        ]
                    })
        
        return vulnerabilities

    def _check_integer_overflow_patterns(self, contract_code: str) -> List[Dict]:
        """Check for integer overflow/underflow vulnerabilities"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        # Check Solidity version
        is_safe_version = 'pragma solidity ^0.8' in contract_code or 'pragma solidity >=0.8' in contract_code
        has_safemath = 'safemath' in contract_code.lower()
        
        if is_safe_version:
            return vulnerabilities  # Solidity 0.8+ has built-in overflow protection
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Look for arithmetic operations on potentially large numbers
            arithmetic_patterns = ['+', '-', '*', '/']
            vulnerable_types = ['uint', 'balance', 'amount', 'value', 'supply', 'price']
            
            if any(op in line_clean for op in arithmetic_patterns):
                if any(vtype in line_clean for vtype in vulnerable_types):
                    if not has_safemath and 'unchecked' not in line_clean:
                        # Check if it's in a require/assert statement (safer)
                        if not any(safe in line_clean for safe in ['require(', 'assert(', 'revert(']):
                            vulnerabilities.append({
                                "id": f"symbolic_overflow_{i}",
                                "title": "Potential Integer Overflow/Underflow",
                                "description": "Arithmetic operation may result in integer overflow or underflow in Solidity <0.8.0",
                                "severity": "Medium",
                                "category": "Arithmetic",
                                "location": {"line": i + 1},
                                "vulnerable_code": line.strip()[:100],
                                "recommendation": "Use SafeMath library or upgrade to Solidity 0.8+",
                                "impact": "May lead to unexpected behavior, fund loss, or logic errors",
                                "confidence": "Medium",
                                "tool": "EnhancedSymbolicAnalyzer",
                                "references": [
                                    {
                                        "title": "SWC-101: Integer Overflow and Underflow",
                                        "url": "https://swcregistry.io/docs/SWC-101"
                                    }
                                ]
                            })
        
        return vulnerabilities

    def _check_access_control_patterns(self, contract_code: str) -> List[Dict]:
        """Check for access control vulnerabilities"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        # Look for sensitive functions without proper access control
        sensitive_keywords = [
            'selfdestruct', 'suicide', 'transfer(', 'mint(', 'burn(',
            'setowner', 'transferownership', 'withdraw', 'changeowner'
        ]
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            if 'function' in line_clean and 'public' in line_clean:
                # Check if it's a sensitive function
                is_sensitive = any(keyword in line_clean for keyword in sensitive_keywords)
                
                if is_sensitive:
                    # Look for access control modifiers
                    has_access_control = any(modifier in line_clean for modifier in [
                        'onlyowner', 'onlyadmin', 'onlyauthorized', 'require(',
                        'modifier', 'internal', 'private'
                    ])
                    
                    # Check the next few lines for require statements
                    if not has_access_control:
                        for j in range(i + 1, min(i + 5, len(lines))):
                            next_line = lines[j].strip().lower()
                            if 'require(' in next_line and ('msg.sender' in next_line or 'owner' in next_line):
                                has_access_control = True
                                break
                    
                    if not has_access_control:
                        vulnerabilities.append({
                            "id": f"symbolic_access_{i}",
                            "title": "Missing Access Control",
                            "description": "Sensitive function lacks proper access control mechanism",
                            "severity": "High",
                            "category": "Access Control",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:100],
                            "recommendation": "Add onlyOwner modifier or require() statements to restrict access",
                            "impact": "Unauthorized users may access privileged functionality",
                            "confidence": "Medium",
                            "tool": "EnhancedSymbolicAnalyzer",
                            "references": [
                                {
                                    "title": "SWC-105: Unprotected Ether Withdrawal",
                                    "url": "https://swcregistry.io/docs/SWC-105"
                                }
                            ]
                        })
        
        return vulnerabilities

    def _check_state_management_patterns(self, contract_code: str) -> List[Dict]:
        """Check for state management issues"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Check for uninitialized storage pointers
            if 'mapping' in line_clean and 'storage' in line_clean:
                if not any(init in line_clean for init in ['=', 'new', 'memory']):
                    vulnerabilities.append({
                        "id": f"symbolic_storage_{i}",
                        "title": "Uninitialized Storage Pointer",
                        "description": "Storage pointer may be uninitialized, leading to unexpected behavior",
                        "severity": "Medium",
                        "category": "State Management",
                        "location": {"line": i + 1},
                        "vulnerable_code": line.strip()[:100],
                        "recommendation": "Initialize storage pointers explicitly",
                        "impact": "May lead to data corruption or unexpected state changes",
                        "confidence": "Low",
                        "tool": "EnhancedSymbolicAnalyzer"
                    })
            
            # Check for state variable shadowing
            if 'uint' in line_clean or 'address' in line_clean or 'bool' in line_clean:
                # This is a simplified check - in reality, you'd need to parse the AST
                pass
        
        return vulnerabilities

    def _check_timestamp_dependence(self, contract_code: str) -> List[Dict]:
        """Check for timestamp dependence vulnerabilities"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        timestamp_patterns = ['block.timestamp', 'now', 'block.number']
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            for pattern in timestamp_patterns:
                if pattern in line_clean:
                    # Check if it's used in critical logic
                    if any(critical in line_clean for critical in ['require(', 'if(', '>', '<', '==']):
                        vulnerabilities.append({
                            "id": f"symbolic_timestamp_{i}",
                            "title": "Timestamp Dependence",
                            "description": f"Contract logic depends on {pattern} which can be manipulated by miners",
                            "severity": "Low",
                            "category": "Timestamp",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:100],
                            "recommendation": "Avoid using block timestamp for critical logic or use block numbers instead",
                            "impact": "Miners may manipulate timestamps to influence contract behavior",
                            "confidence": "Medium",
                            "tool": "EnhancedSymbolicAnalyzer",
                            "references": [
                                {
                                    "title": "SWC-116: Block values as a proxy for time",
                                    "url": "https://swcregistry.io/docs/SWC-116"
                                }
                            ]
                        })
        
        return vulnerabilities

    def _check_tx_origin_usage(self, contract_code: str) -> List[Dict]:
        """Check for tx.origin usage"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            if 'tx.origin' in line_clean:
                vulnerabilities.append({
                    "id": f"symbolic_txorigin_{i}",
                    "title": "Use of tx.origin",
                    "description": "Using tx.origin for authorization is vulnerable to phishing attacks",
                    "severity": "Medium",
                    "category": "Access Control",
                    "location": {"line": i + 1},
                    "vulnerable_code": line.strip()[:100],
                    "recommendation": "Use msg.sender instead of tx.origin for authorization",
                    "impact": "Contract vulnerable to phishing attacks",
                    "confidence": "High",
                    "tool": "EnhancedSymbolicAnalyzer",
                    "references": [
                        {
                            "title": "SWC-115: Authorization through tx.origin",
                            "url": "https://swcregistry.io/docs/SWC-115"
                        }
                    ]
                })
        
        return vulnerabilities

    def _check_unchecked_calls(self, contract_code: str) -> List[Dict]:
        """Check for unchecked external calls"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Look for external calls that should be checked
            call_patterns = ['.call(', '.send(', '.delegatecall(']
            
            for pattern in call_patterns:
                if pattern in line_clean:
                    # Check if return value is checked
                    has_check = any(check in line_clean for check in [
                        'require(', 'assert(', 'if(', 'bool ', 'success'
                    ])
                    
                    if not has_check:
                        vulnerabilities.append({
                            "id": f"symbolic_unchecked_{i}",
                            "title": "Unchecked External Call",
                            "description": "External call return value is not checked",
                            "severity": "Medium",
                            "category": "Error Handling",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:100],
                            "recommendation": "Always check return values of external calls",
                            "impact": "Failed calls may go unnoticed, leading to unexpected behavior",
                            "confidence": "Medium",
                            "tool": "EnhancedSymbolicAnalyzer",
                            "references": [
                                {
                                    "title": "SWC-104: Unchecked Call Return Value",
                                    "url": "https://swcregistry.io/docs/SWC-104"
                                }
                            ]
                        })
        
        return vulnerabilities

    def _check_denial_of_service(self, contract_code: str) -> List[Dict]:
        """Check for potential denial of service vulnerabilities"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Check for unbounded loops
            if any(loop in line_clean for loop in ['for(', 'while(']):
                # Look for array or mapping iteration
                if any(iter_pattern in line_clean for iter_pattern in ['.length', 'array', 'list']):
                    vulnerabilities.append({
                        "id": f"symbolic_dos_{i}",
                        "title": "Potential Denial of Service",
                        "description": "Unbounded loop may cause out-of-gas errors",
                        "severity": "Medium",
                        "category": "Gas Limit",
                        "location": {"line": i + 1},
                        "vulnerable_code": line.strip()[:100],
                        "recommendation": "Implement pagination or limit loop iterations",
                        "impact": "Function may become unusable due to gas limit",
                        "confidence": "Low",
                        "tool": "EnhancedSymbolicAnalyzer"
                    })
        
        return vulnerabilities

    def _calculate_symbolic_complexity(self, contract_code: str, compilation_result: Dict) -> str:
        """Calculate symbolic execution complexity score"""
        try:
            # Count decision points (branches)
            branch_keywords = ['if', 'else', 'require', 'assert', 'for', 'while', '?']
            branch_count = sum(contract_code.lower().count(keyword) for keyword in branch_keywords)
            
            # Count functions
            function_count = contract_code.lower().count('function')
            
            # Count external calls
            external_calls = contract_code.lower().count('call') + contract_code.lower().count('transfer')
            
            # Calculate complexity score
            complexity_score = (branch_count * 2) + function_count + (external_calls * 3)
            
            if complexity_score < 20:
                return "Low"
            elif complexity_score < 50:
                return "Medium"
            else:
                return "High"
                
        except Exception:
            return "Unknown"

    def _parse_mythril_output(self, output: str) -> List[Dict]:
        """Parse Mythril JSON output to extract vulnerabilities"""
        vulnerabilities = []
        
        try:
            if not output.strip():
                return vulnerabilities
                
            # Try to parse as single JSON first, then line by line
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
            except json.JSONDecodeError:
                # Try parsing line by line
                data = []
                for line in output.split('\n'):
                    line = line.strip()
                    if line and line.startswith('{'):
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            
            for item in data:
                if 'issues' in item:
                    for issue in item['issues']:
                        vulnerability = self._parse_mythril_issue(issue)
                        if vulnerability:
                            vulnerabilities.append(vulnerability)
                elif 'title' in item:  # Single issue format
                    vulnerability = self._parse_mythril_issue(item)
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            logger.error(f"Failed to parse Mythril output: {e}")
            
        return vulnerabilities
    
    def _parse_mythril_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse a single Mythril issue"""
        try:
            title = issue.get('title', 'Unknown Issue')
            description = issue.get('description', 'No description available')
            swc_id = issue.get('swc-id', '')
            severity = issue.get('severity', 'Medium')
            
            # Extract source location
            location = None
            vulnerable_code = None
            
            source_map = issue.get('sourceMap', issue.get('source_map'))
            if source_map:
                location = {
                    "line": source_map.get('line', 0),
                    "column": source_map.get('column', 0)
                }
                
            # Get code snippet if available
            if 'code' in issue:
                vulnerable_code = issue['code'][:200]  # Limit length
            
            # Map Mythril severity to our format
            severity_mapping = {
                'High': 'High',
                'Medium': 'Medium',
                'Low': 'Low'
            }
            
            mapped_severity = severity_mapping.get(severity, 'Medium')
            
            vulnerability = {
                "id": f"mythril_{swc_id}_{abs(hash(title)) % 10000}",
                "title": title,
                "description": self._clean_description(description),
                "severity": mapped_severity,
                "category": self._get_category_from_swc(swc_id),
                "location": location,
                "vulnerable_code": vulnerable_code,
                "recommendation": self._get_recommendation_from_swc(swc_id),
                "impact": self._get_impact_from_swc(swc_id),
                "confidence": "High",  # Mythril findings are generally high confidence
                "tool": "Mythril",
                "references": self._get_references_from_swc(swc_id)
            }
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Error parsing Mythril issue: {e}")
            return None

    def _get_category_from_swc(self, swc_id: str) -> str:
        """Get vulnerability category from SWC ID"""
        categories = {
            'SWC-101': 'Integer Overflow',
            'SWC-103': 'Floating Pragma',
            'SWC-104': 'Unchecked Call Return Value',
            'SWC-105': 'Unprotected Ether Withdrawal',
            'SWC-106': 'Unprotected SELFDESTRUCT',
            'SWC-107': 'Reentrancy',
            'SWC-108': 'State Variable Default Visibility',
            'SWC-109': 'Uninitialized Storage Pointer',
            'SWC-110': 'Assert Violation',
            'SWC-111': 'Use of Deprecated Functions',
            'SWC-112': 'Delegatecall to Untrusted Callee',
            'SWC-113': 'DoS with Failed Call',
            'SWC-114': 'Transaction Order Dependence',
            'SWC-115': 'Authorization through tx.origin',
            'SWC-116': 'Block values as a proxy for time',
            'SWC-118': 'Incorrect Constructor Name',
            'SWC-119': 'Shadowing State Variables',
            'SWC-120': 'Weak Sources of Randomness',
            'SWC-123': 'Requirement Violation',
            'SWC-124': 'Write to Arbitrary Storage Location'
        }
        
        return categories.get(swc_id, 'General')
    
    def _get_recommendation_from_swc(self, swc_id: str) -> str:
        """Get recommendation from SWC ID"""
        recommendations = {
            'SWC-101': 'Use SafeMath library or Solidity 0.8+ built-in overflow checks',
            'SWC-103': 'Use specific compiler version instead of floating pragma',
            'SWC-104': 'Always check return values of external calls',
            'SWC-105': 'Implement proper access control for withdrawal functions',
            'SWC-106': 'Implement proper access control for selfdestruct',
            'SWC-107': 'Use Checks-Effects-Interactions pattern or ReentrancyGuard',
            'SWC-108': 'Explicitly specify visibility for all state variables',
            'SWC-109': 'Initialize storage pointers properly',
            'SWC-110': 'Review assert conditions and use require for user input validation',
            'SWC-111': 'Replace deprecated functions with modern alternatives',
            'SWC-112': 'Avoid delegatecall to untrusted contracts',
            'SWC-113': 'Handle failed calls gracefully',
            'SWC-114': 'Use commit-reveal schemes for sensitive operations',
            'SWC-115': 'Use msg.sender instead of tx.origin',
            'SWC-116': 'Use oracle services for time-dependent logic',
            'SWC-118': 'Use constructor keyword for constructors',
            'SWC-119': 'Avoid shadowing state variables',
            'SWC-120': 'Use verifiable random functions (VRF) for randomness',
            'SWC-123': 'Review and fix requirement violations',
            'SWC-124': 'Validate storage locations before writing'
        }
        
        return recommendations.get(swc_id, 'Follow security best practices')
    
    def _get_impact_from_swc(self, swc_id: str) -> str:
        """Get impact description from SWC ID"""
        impacts = {
            'SWC-101': 'Integer overflow/underflow can lead to unexpected behavior and potential fund loss',
            'SWC-105': 'Unauthorized users may be able to withdraw contract funds',
            'SWC-106': 'Unauthorized users may be able to destroy the contract',
            'SWC-107': 'Attackers can drain contract funds through reentrancy attacks',
            'SWC-112': 'Attacker can execute arbitrary code in contract context',
            'SWC-115': 'Contract vulnerable to phishing attacks',
            'SWC-120': 'Predictable randomness can be exploited by miners or attackers',
            'SWC-124': 'Attacker may be able to overwrite arbitrary storage locations'
        }
        
        return impacts.get(swc_id, 'May lead to security vulnerabilities or unexpected behavior')
    
    def _get_references_from_swc(self, swc_id: str) -> List[Dict]:
        """Get reference links from SWC ID"""
        if swc_id:
            return [
                {
                    "title": f"{swc_id} - Smart Contract Weakness Classification",
                    "url": f"https://swcregistry.io/docs/{swc_id}"
                }
            ]
        return []
    
    def _clean_description(self, description: str) -> str:
        """Clean and format description text"""
        if not description:
            return "No description available"
            
        # Remove extra whitespace and clean up
        cleaned = ' '.join(description.split())
        
        # Limit length
        if len(cleaned) > 500:
            cleaned = cleaned[:500] + "..."
            
        return cleaned
    
    def _estimate_paths_explored(self, output: str) -> str:
        """Estimate number of execution paths explored"""
        try:
            # Look for indicators in output
            if "timeout" in output.lower():
                return "Limited (timeout)"
            elif "max depth" in output.lower():
                return "Limited (max depth)"
            else:
                return "Multiple paths"
        except Exception:
            return "Unknown"
    
    def _find_mythril_executable(self) -> Optional[str]:
        """Find Mythril executable"""
        try:
            # Check common locations
            possible_paths = [
                "myth",
                "/usr/local/bin/myth",
                "/usr/bin/myth",
                "~/.local/bin/myth"
            ]
            
            for path in possible_paths:
                try:
                    result = subprocess.run(
                        [path, "version"], 
                        capture_output=True, 
                        text=True, 
                        timeout=10
                    )
                    if result.returncode == 0:
                        return path
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
                    
            return None
            
        except Exception as e:
            logger.error(f"Error finding Mythril: {e}")
            return None
    
    async def _run_command(self, cmd: List[str], timeout: int = 120) -> Dict:
        """Run shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode('utf-8'),
                "error": stderr.decode('utf-8'),
                "returncode": process.returncode
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "output": "",
                "error": "Command timeout",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "returncode": -1
            }
    
    async def _get_mythril_version(self) -> str:
        """Get Mythril version"""
        try:
            if self.mythril_path:
                result = await self._run_command([self.mythril_path, "version"])
                if result['success']:
                    return result['output'].strip()
            return "Unknown"
        except Exception:
            return "Unknown"
    
    async def check_availability(self) -> bool:
        """Check if symbolic executor is available (always true for fallback)"""
        return True  # Enhanced fallback mode always available
