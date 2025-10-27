import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from loguru import logger


class StaticAnalyzer:
    """Real static analysis using Slither"""
    
    def __init__(self):
        self.slither_path = self._find_slither_executable()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="slither_"))
        
    async def initialize(self):
        """Initialize static analyzer"""
        try:
            if not self.slither_path:
                logger.error("Slither not found. Install with: pip install slither-analyzer")
                return
                
            # Test slither installation
            result = await self._run_command([self.slither_path, "--version"])
            if result['success']:
                logger.info(f"Slither initialized: {result['output'].strip()}")
            else:
                logger.error(f"Slither initialization failed: {result['error']}")
                
        except Exception as e:
            logger.error(f"Static analyzer initialization failed: {e}")
            
    async def analyze(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Run Slither static analysis"""
        try:
            if not self.slither_path:
                logger.info("Slither not available, using enhanced pattern analysis")
                return await self._enhanced_pattern_analysis(contract_code, compilation_result)

            # Create temporary contract file
            contract_file = self.temp_dir / f"contract_{os.getpid()}.sol"
            contract_file.write_text(contract_code)
            
            logger.info(f"Running Slither analysis on {contract_file}")
            
            # Run Slither with JSON output
            cmd = [
                self.slither_path,
                str(contract_file),
                "--json", "-",
                "--disable-color",
                "--filter-paths", "node_modules"
            ]
            
            result = await self._run_command(cmd, timeout=120)  # 2 minute timeout
            
            if not result['success']:
                logger.error(f"Slither execution failed: {result['error']}")
                logger.info("Falling back to pattern analysis")
                return await self._enhanced_pattern_analysis(contract_code, compilation_result)
            
            # Parse Slither JSON output
            vulnerabilities = self._parse_slither_output(result['output'])
            
            # Add additional static checks
            additional_vulns = self._run_additional_checks(contract_code)
            vulnerabilities.extend(additional_vulns)
            
            findings = [
                f"Analyzed with Slither static analyzer v{await self._get_slither_version()}",
                f"Found {len(vulnerabilities)} potential issues",
                f"Contract complexity: {compilation_result.get('metrics', {}).get('complexity_level', 'Unknown')}",
                f"Lines of code analyzed: {compilation_result.get('metrics', {}).get('code_lines', 0)}"
            ]
            
            return {
                "success": True,
                "vulnerabilities": vulnerabilities,
                "findings": findings,
                "tool": "Slither",
                "version": await self._get_slither_version()
            }
            
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            logger.info("Falling back to pattern analysis")
            return await self._enhanced_pattern_analysis(contract_code, compilation_result)
        finally:
            # Cleanup
            try:
                if 'contract_file' in locals() and contract_file.exists():
                    contract_file.unlink()
            except Exception:
                pass
    
    async def _enhanced_pattern_analysis(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Enhanced pattern-based analysis when Slither is not available"""
        vulnerabilities = []
        
        try:
            logger.info("Running enhanced pattern-based static analysis")
            
            # Run comprehensive pattern checks
            vulnerabilities.extend(self._check_reentrancy_patterns(contract_code))
            vulnerabilities.extend(self._check_access_control_patterns(contract_code))
            vulnerabilities.extend(self._check_integer_overflow_patterns(contract_code))
            vulnerabilities.extend(self._check_external_calls(contract_code))
            vulnerabilities.extend(self._check_state_visibility(contract_code))
            vulnerabilities.extend(self._check_deprecated_functions(contract_code))
            vulnerabilities.extend(self._check_gas_optimization(contract_code))
            vulnerabilities.extend(self._run_additional_checks(contract_code))
            
            findings = [
                "Enhanced pattern-based static analysis completed",
                f"Found {len(vulnerabilities)} potential issues",
                f"Analyzed {len(contract_code.split('function'))-1} functions",
                "Note: Install Slither for more comprehensive analysis"
            ]
            
            return {
                "success": True,
                "vulnerabilities": vulnerabilities,
                "findings": findings,
                "tool": "EnhancedPatternAnalyzer",
                "version": "1.0.0"
            }
            
        except Exception as e:
            logger.error(f"Enhanced pattern analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "vulnerabilities": []
            }

    def _check_reentrancy_patterns(self, contract_code: str) -> List[Dict]:
        """Check for reentrancy vulnerability patterns"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Look for external calls
            external_calls = ['call.value', '.call{value:', '.transfer(', '.send(']
            if any(call in line_clean for call in external_calls):
                # Check for state changes after the call
                for j in range(i + 1, min(i + 10, len(lines))):
                    next_line = lines[j].strip().lower()
                    if any(op in next_line for op in ['=', '+=', '-=', '++', '--']):
                        vulnerabilities.append({
                            "id": f"pattern_reentrancy_{i}",
                            "title": "Potential Reentrancy Vulnerability",
                            "description": "External call followed by state change may be vulnerable to reentrancy",
                            "severity": "High",
                            "category": "Reentrancy",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:150],
                            "recommendation": "Use ReentrancyGuard or Checks-Effects-Interactions pattern",
                            "impact": "Attackers could drain contract funds through recursive calls",
                            "confidence": "Medium",
                            "tool": "PatternAnalyzer",
                            "references": [
                                {
                                    "title": "SWC-107: Reentrancy",
                                    "url": "https://swcregistry.io/docs/SWC-107"
                                }
                            ]
                        })
                        break
        
        return vulnerabilities

    def _check_access_control_patterns(self, contract_code: str) -> List[Dict]:
        """Check for access control issues"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        sensitive_functions = ['selfdestruct', 'suicide', 'transferownership', 'setowner']
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Check for public functions with sensitive operations
            if 'function' in line_clean and 'public' in line_clean:
                if any(sensitive in line_clean for sensitive in sensitive_functions):
                    # Check for access control
                    has_modifier = any(mod in line_clean for mod in ['onlyowner', 'onlyadmin', 'require('])
                    
                    if not has_modifier:
                        # Check next few lines for require statements
                        for j in range(i + 1, min(i + 5, len(lines))):
                            next_line = lines[j].strip().lower()
                            if 'require(' in next_line and 'msg.sender' in next_line:
                                has_modifier = True
                                break
                    
                    if not has_modifier:
                        vulnerabilities.append({
                            "id": f"pattern_access_{i}",
                            "title": "Missing Access Control",
                            "description": "Sensitive function lacks proper access control mechanisms",
                            "severity": "High",
                            "category": "Access Control",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:150],
                            "recommendation": "Add onlyOwner modifier or require() statements",
                            "impact": "Unauthorized users may access privileged functionality",
                            "confidence": "Medium",
                            "tool": "PatternAnalyzer",
                            "references": [
                                {
                                    "title": "SWC-105: Unprotected Ether Withdrawal",
                                    "url": "https://swcregistry.io/docs/SWC-105"
                                }
                            ]
                        })
        
        return vulnerabilities

    def _check_integer_overflow_patterns(self, contract_code: str) -> List[Dict]:
        """Check for integer overflow issues"""
        vulnerabilities = []
        
        # Check Solidity version
        is_safe_version = any(version in contract_code for version in [
            'pragma solidity ^0.8', 'pragma solidity >=0.8', 'pragma solidity 0.8'
        ])
        
        if is_safe_version:
            return vulnerabilities  # Solidity 0.8+ has built-in overflow protection
        
        has_safemath = 'safemath' in contract_code.lower()
        if has_safemath:
            return vulnerabilities  # SafeMath library used
        
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Look for arithmetic operations
            if any(op in line_clean for op in ['+', '-', '*', '/']):
                if any(var_type in line_clean for var_type in ['uint', 'balance', 'amount']):
                    if 'unchecked' not in line_clean:
                        vulnerabilities.append({
                            "id": f"pattern_overflow_{i}",
                            "title": "Potential Integer Overflow/Underflow",
                            "description": "Arithmetic operation without overflow protection in Solidity <0.8.0",
                            "severity": "Medium",
                            "category": "Arithmetic",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:150],
                            "recommendation": "Use SafeMath library or upgrade to Solidity 0.8+",
                            "impact": "May lead to unexpected calculation results and fund loss",
                            "confidence": "Low",
                            "tool": "PatternAnalyzer",
                            "references": [
                                {
                                    "title": "SWC-101: Integer Overflow and Underflow",
                                    "url": "https://swcregistry.io/docs/SWC-101"
                                }
                            ]
                        })
        
        return vulnerabilities

    def _check_external_calls(self, contract_code: str) -> List[Dict]:
        """Check for external call issues"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Check for unchecked external calls
            external_calls = ['.call(', '.send(', '.delegatecall(']
            
            for call in external_calls:
                if call in line_clean:
                    # Check if return value is handled
                    has_check = any(check in line_clean for check in [
                        'require(', 'assert(', 'if(', 'bool ', 'success'
                    ])
                    
                    if not has_check:
                        vulnerabilities.append({
                            "id": f"pattern_unchecked_{i}",
                            "title": "Unchecked External Call",
                            "description": "External call return value is not checked",
                            "severity": "Medium", 
                            "category": "Error Handling",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:150],
                            "recommendation": "Always check return values of external calls",
                            "impact": "Failed calls may go unnoticed",
                            "confidence": "Medium",
                            "tool": "PatternAnalyzer",
                            "references": [
                                {
                                    "title": "SWC-104: Unchecked Call Return Value",
                                    "url": "https://swcregistry.io/docs/SWC-104"
                                }
                            ]
                        })
        
        return vulnerabilities

    def _check_state_visibility(self, contract_code: str) -> List[Dict]:
        """Check for state variable visibility issues"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip()
            
            # Check for state variables without explicit visibility
            if any(var_type in line_clean.lower() for var_type in ['uint', 'int', 'address', 'bool', 'string', 'bytes']):
                if ';' in line_clean and 'function' not in line_clean.lower():
                    if not any(visibility in line_clean.lower() for visibility in ['public', 'private', 'internal']):
                        vulnerabilities.append({
                            "id": f"pattern_visibility_{i}",
                            "title": "State Variable Default Visibility",
                            "description": "State variable uses default visibility (internal)",
                            "severity": "Low",
                            "category": "Code Quality",
                            "location": {"line": i + 1},
                            "vulnerable_code": line.strip()[:150],
                            "recommendation": "Explicitly specify visibility for all state variables",
                            "impact": "Unclear contract interface and potential confusion",
                            "confidence": "Low",
                            "tool": "PatternAnalyzer"
                        })
        
        return vulnerabilities

    def _check_deprecated_functions(self, contract_code: str) -> List[Dict]:
        """Check for deprecated function usage"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        deprecated_patterns = {
            'suicide(': {
                'title': 'Use of Deprecated suicide() Function',
                'recommendation': 'Use selfdestruct() instead of suicide()',
                'severity': 'Low'
            },
            'throw;': {
                'title': 'Use of Deprecated throw Statement', 
                'recommendation': 'Use revert() instead of throw',
                'severity': 'Low'
            },
            'tx.origin': {
                'title': 'Use of tx.origin',
                'recommendation': 'Use msg.sender instead of tx.origin',
                'severity': 'Medium'
            }
        }
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            for pattern, info in deprecated_patterns.items():
                if pattern in line_clean:
                    vulnerabilities.append({
                        "id": f"pattern_deprecated_{i}",
                        "title": info['title'],
                        "description": f"Usage of deprecated pattern: {pattern}",
                        "severity": info['severity'],
                        "category": "Deprecated",
                        "location": {"line": i + 1},
                        "vulnerable_code": line.strip()[:150],
                        "recommendation": info['recommendation'],
                        "impact": "May cause unexpected behavior or compilation issues",
                        "confidence": "High",
                        "tool": "PatternAnalyzer"
                    })
        
        return vulnerabilities

    def _check_gas_optimization(self, contract_code: str) -> List[Dict]:
        """Check for gas optimization opportunities"""
        vulnerabilities = []
        lines = contract_code.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Check for public functions that could be external
            if 'function' in line_clean and 'public' in line_clean:
                if 'view' in line_clean or 'pure' in line_clean:
                    # This could potentially be external
                    vulnerabilities.append({
                        "id": f"pattern_gas_{i}",
                        "title": "Gas Optimization Opportunity",
                        "description": "Public function could potentially be declared as external",
                        "severity": "Info",
                        "category": "Gas Optimization",
                        "location": {"line": i + 1},
                        "vulnerable_code": line.strip()[:150],
                        "recommendation": "Consider using external instead of public for functions not called internally",
                        "impact": "Higher gas costs",
                        "confidence": "Low",
                        "tool": "PatternAnalyzer"
                    })
        
        return vulnerabilities

    def _parse_slither_output(self, output: str) -> List[Dict]:
        """Parse Slither JSON output to extract vulnerabilities"""
        vulnerabilities = []
        
        try:
            if not output.strip():
                return vulnerabilities
                
            data = json.loads(output)
            
            for result in data.get('results', {}).get('detectors', []):
                # Extract vulnerability information
                impact = result.get('impact', 'Medium')
                confidence = result.get('confidence', 'Medium')
                description = result.get('description', 'No description available')
                check = result.get('check', 'unknown')
                
                # Get source location
                elements = result.get('elements', [])
                location = None
                vulnerable_code = None
                
                if elements:
                    first_element = elements[0]
                    source_mapping = first_element.get('source_mapping', {})
                    if source_mapping:
                        location = {
                            "line": source_mapping.get('lines', [0])[0] if source_mapping.get('lines') else 0,
                            "column": source_mapping.get('starting_column', 0),
                        }
                    
                    # Try to extract vulnerable code
                    if 'source_mapping' in first_element and 'content' in source_mapping:
                        vulnerable_code = source_mapping['content'][:200]  # Limit length
                
                # Map Slither severity to our format
                severity_mapping = {
                    'High': 'High',
                    'Medium': 'Medium', 
                    'Low': 'Low',
                    'Informational': 'Info'
                }
                
                severity = severity_mapping.get(impact, 'Medium')
                
                vulnerability = {
                    "id": f"slither_{check}_{len(vulnerabilities)}",
                    "title": self._get_vulnerability_title(check),
                    "description": self._clean_description(description),
                    "severity": severity,
                    "category": self._get_category(check),
                    "location": location,
                    "vulnerable_code": vulnerable_code,
                    "recommendation": self._get_recommendation(check),
                    "impact": self._get_impact_description(check, impact),
                    "confidence": confidence,
                    "tool": "Slither",
                    "references": self._get_references(check)
                }
                
                vulnerabilities.append(vulnerability)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Slither JSON output: {e}")
        except Exception as e:
            logger.error(f"Error parsing Slither output: {e}")
            
        return vulnerabilities
    
    def _run_additional_checks(self, contract_code: str) -> List[Dict]:
        """Run additional static checks beyond Slither"""
        additional_vulns = []
        
        try:
            code_lower = contract_code.lower()
            
            # Check for common anti-patterns
            checks = [
                {
                    "pattern": "block.timestamp",
                    "title": "Timestamp Dependence",
                    "severity": "Low", 
                    "category": "Timestamp",
                    "description": "Contract relies on block.timestamp which can be manipulated by miners."
                },
                {
                    "pattern": "block.number",
                    "title": "Block Number Dependence",
                    "severity": "Low",
                    "category": "Block Info",
                    "description": "Contract relies on block.number which may not be reliable for timing."
                },
                {
                    "pattern": "blockhash(",
                    "title": "Blockhash Usage",
                    "severity": "Low",
                    "category": "Randomness",
                    "description": "Using blockhash for randomness can be manipulated."
                }
            ]
            
            for check in checks:
                if check["pattern"] in code_lower:
                    # Find line number
                    lines = contract_code.split('\n')
                    line_num = 0
                    for i, line in enumerate(lines):
                        if check["pattern"] in line.lower():
                            line_num = i + 1
                            break
                    
                    vuln = {
                        "id": f"additional_{check['pattern'].replace('.', '_').replace('(', '')}_{len(additional_vulns)}",
                        "title": check["title"],
                        "description": check["description"],
                        "severity": check["severity"],
                        "category": check["category"],
                        "location": {"line": line_num} if line_num > 0 else None,
                        "recommendation": f"Avoid relying on {check['pattern']} for critical logic",
                        "impact": "May lead to security vulnerabilities or unexpected behavior",
                        "confidence": "Medium",
                        "tool": "StaticAnalyzer",
                        "references": []
                    }
                    additional_vulns.append(vuln)
                    
        except Exception as e:
            logger.error(f"Additional checks failed: {e}")
            
        return additional_vulns
    
    def _get_vulnerability_title(self, check: str) -> str:
        """Get human-readable title for Slither check"""
        titles = {
            "reentrancy-eth": "Reentrancy Vulnerability",
            "reentrancy-no-eth": "Reentrancy (No Ether)",
            "reentrancy-benign": "Benign Reentrancy",
            "reentrancy-events": "Reentrancy (Events)",
            "uninitialized-state": "Uninitialized State Variables",
            "uninitialized-storage": "Uninitialized Storage Variables",
            "arbitrary-send": "Arbitrary Send",
            "controlled-delegatecall": "Controlled Delegatecall",
            "tx-origin": "Dangerous use of tx.origin",
            "suicidal": "Functions allowing anyone to destruct the contract",
            "assembly": "Assembly usage",
            "low-level-calls": "Low level calls",
            "naming-convention": "Conformance to Solidity naming conventions",
            "pragma": "If different pragma directives are used",
            "solc-version": "Incorrect versions of Solidity",
            "unused-state": "Unused state variables",
            "external-function": "Public function that could be declared external",
            "constable-states": "State variables that could be declared constant",
            "immutable-states": "State variables that could be declared immutable",
            "calls-loop": "Calls inside a loop",
            "timestamp": "Dangerous usage of block.timestamp",
            "weak-prng": "Weak PRNG"
        }
        
        return titles.get(check, f"Slither Check: {check}")
    
    def _get_category(self, check: str) -> str:
        """Get vulnerability category"""
        categories = {
            "reentrancy-eth": "Reentrancy",
            "reentrancy-no-eth": "Reentrancy", 
            "reentrancy-benign": "Reentrancy",
            "reentrancy-events": "Reentrancy",
            "uninitialized-state": "Uninitialized Variables",
            "uninitialized-storage": "Uninitialized Variables",
            "arbitrary-send": "Access Control",
            "controlled-delegatecall": "Access Control",
            "tx-origin": "Access Control",
            "suicidal": "Access Control",
            "assembly": "Low Level",
            "low-level-calls": "Low Level",
            "naming-convention": "Code Quality",
            "pragma": "Code Quality",
            "solc-version": "Code Quality",
            "unused-state": "Gas Optimization",
            "external-function": "Gas Optimization",
            "constable-states": "Gas Optimization",
            "immutable-states": "Gas Optimization",
            "calls-loop": "Gas Limit",
            "timestamp": "Timestamp",
            "weak-prng": "Randomness"
        }
        
        return categories.get(check, "General")
    
    def _get_recommendation(self, check: str) -> str:
        """Get recommendation for fixing the issue"""
        recommendations = {
            "reentrancy-eth": "Use the Checks-Effects-Interactions pattern or ReentrancyGuard modifier",
            "reentrancy-no-eth": "Use the Checks-Effects-Interactions pattern",
            "uninitialized-state": "Initialize all state variables explicitly",
            "uninitialized-storage": "Initialize storage variables before use",
            "arbitrary-send": "Implement proper access control mechanisms",
            "controlled-delegatecall": "Avoid delegatecall to user-controlled addresses",
            "tx-origin": "Use msg.sender instead of tx.origin for authorization",
            "suicidal": "Implement proper access control for destructive functions",
            "assembly": "Avoid inline assembly when possible, or document extensively",
            "low-level-calls": "Use high-level Solidity functions instead of low-level calls",
            "naming-convention": "Follow Solidity naming conventions",
            "pragma": "Use consistent pragma directives across contracts",
            "solc-version": "Use the latest stable Solidity version",
            "unused-state": "Remove unused state variables to save gas",
            "external-function": "Declare public functions as external if they're not called internally",
            "constable-states": "Declare constant state variables as constant",
            "immutable-states": "Declare immutable state variables as immutable",
            "calls-loop": "Avoid external calls in loops or implement circuit breaker",
            "timestamp": "Use block numbers or oracle services instead of timestamps",
            "weak-prng": "Use verifiable random functions (VRF) for secure randomness"
        }
        
        return recommendations.get(check, "Review and fix according to best practices")
    
    def _get_impact_description(self, check: str, impact: str) -> str:
        """Get detailed impact description"""
        impacts = {
            "reentrancy-eth": "Attackers can drain contract funds through recursive calls",
            "arbitrary-send": "Funds can be sent to unintended recipients", 
            "controlled-delegatecall": "Attacker can execute arbitrary code in contract context",
            "tx-origin": "Vulnerable to phishing attacks",
            "suicidal": "Contract can be destroyed by unauthorized users",
            "calls-loop": "Contract may hit gas limit and become unusable",
            "weak-prng": "Predictable randomness can be exploited"
        }
        
        return impacts.get(check, f"Potential {impact.lower()} impact on contract security")
    
    def _get_references(self, check: str) -> List[Dict]:
        """Get reference links for the vulnerability"""
        references = {
            "reentrancy-eth": [
                {
                    "title": "SWC-107: Reentrancy",
                    "url": "https://swcregistry.io/docs/SWC-107"
                }
            ],
            "tx-origin": [
                {
                    "title": "SWC-115: Authorization through tx.origin",
                    "url": "https://swcregistry.io/docs/SWC-115"
                }
            ],
            "arbitrary-send": [
                {
                    "title": "SWC-105: Unprotected Ether Withdrawal", 
                    "url": "https://swcregistry.io/docs/SWC-105"
                }
            ],
            "controlled-delegatecall": [
                {
                    "title": "SWC-112: Delegatecall to Untrusted Callee",
                    "url": "https://swcregistry.io/docs/SWC-112"
                }
            ]
        }
        
        return references.get(check, [])
    
    def _clean_description(self, description: str) -> str:
        """Clean and format description text"""
        if not description:
            return "No description available"
            
        # Remove markdown formatting and clean up
        cleaned = description.replace('\n', ' ').strip()
        
        # Limit length
        if len(cleaned) > 500:
            cleaned = cleaned[:500] + "..."
            
        return cleaned
    
    def _find_slither_executable(self) -> Optional[str]:
        """Find Slither executable (improved version)"""
        try:
            # First, try the simple 'slither' command (most likely to work)
            try:
                result = subprocess.run(
                    ["slither", "--version"], 
                    capture_output=True, 
                    text=True, 
                    timeout=10
                )
                if result.returncode == 0:
                    logger.info(f"Found Slither executable: slither")
                    return "slither"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Check other common locations
            possible_paths = [
                "/usr/local/bin/slither",
                "/usr/bin/slither", 
                "~/.local/bin/slither"
            ]
            
            for path in possible_paths:
                try:
                    result = subprocess.run(
                        [path, "--version"], 
                        capture_output=True, 
                        text=True, 
                        timeout=10
                    )
                    if result.returncode == 0:
                        logger.info(f"Found Slither executable: {path}")
                        return path
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
                    
            logger.warning("Slither executable not found in common locations")
            return None
            
        except Exception as e:
            logger.error(f"Error finding Slither: {e}")
            return None
    
    async def _run_command(self, cmd: List[str], timeout: int = 60) -> Dict:
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
    
    async def _get_slither_version(self) -> str:
        """Get Slither version"""
        try:
            if self.slither_path:
                result = await self._run_command([self.slither_path, "--version"])
                if result['success']:
                    return result['output'].strip()
            return "Unknown"
        except Exception:
            return "Unknown"
    
    async def check_availability(self) -> bool:
        """Check if Slither is available"""
        return self.slither_path is not None
