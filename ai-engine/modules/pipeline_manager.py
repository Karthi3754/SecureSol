import asyncio
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Dict, List, Optional

from loguru import logger

from modules.static_analyzer import StaticAnalyzer
from modules.symbolic_executor import SymbolicExecutor
from modules.fuzz_tester import FuzzTester
from modules.intent_detector import IntentDetector
from utils.solc_handler import SolidityCompiler


class AnalysisPipeline:
    """Real analysis pipeline orchestrator"""
    
    def __init__(self):
        self.static_analyzer = StaticAnalyzer()
        self.symbolic_executor = SymbolicExecutor()
        self.fuzz_tester = FuzzTester()
        self.intent_detector = IntentDetector()
        self.compiler = SolidityCompiler()
        
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.analysis_timeout = 300  # 5 minutes
        
    async def initialize(self):
        """Initialize all analysis components"""
        try:
            logger.info("Initializing analysis pipeline...")
            
            # Initialize compiler first
            await self.compiler.initialize()
            
            # Initialize analyzers in parallel
            await asyncio.gather(
                self.static_analyzer.initialize(),
                self.symbolic_executor.initialize(),
                self.fuzz_tester.initialize(),
                self.intent_detector.initialize(),
                return_exceptions=True
            )
            
            logger.info("Analysis pipeline initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize analysis pipeline: {e}")
            raise
    
    async def analyze(self, request) -> Dict:
        """Run complete analysis pipeline"""
        analysis_id = str(uuid.uuid4())
        start_time = time.time()
        
        try:
            logger.info(f"Starting analysis {analysis_id} for {request.contract_name}")
            
            # Step 1: Compile contract
            logger.info("Step 1: Compiling contract...")
            compilation_result = await self.compiler.compile_contract(
                request.contract_code, 
                request.contract_name
            )
            
            if not compilation_result.get('success', False):
                return {
                    "success": False,
                    "error": f"Compilation failed: {compilation_result.get('error', 'Unknown error')}",
                    "analysis_id": analysis_id
                }
            
            # Step 2: Run analysis modules in parallel
            logger.info("Step 2: Running security analysis modules...")
            
            analysis_tasks = []
            
            # Static Analysis (always run)
            analysis_tasks.append(self._run_static_analysis(
                request.contract_code, compilation_result
            ))
            
            # Advanced analysis for premium scans
            if request.scan_type == "premium":
                analysis_tasks.append(self._run_symbolic_execution(
                    request.contract_code, compilation_result
                ))
                analysis_tasks.append(self._run_fuzz_testing(
                    request.contract_code, compilation_result
                ))
                analysis_tasks.append(self._run_intent_detection(
                    request.contract_code, compilation_result
                ))
            
            # Execute analysis modules with timeout
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*analysis_tasks, return_exceptions=True),
                    timeout=self.analysis_timeout
                )
            except asyncio.TimeoutError:
                logger.error(f"Analysis timeout for {analysis_id}")
                raise Exception("Analysis timeout - contract too complex")
            
            # Process results
            static_result = results[0] if len(results) > 0 else {}
            symbolic_result = results[1] if len(results) > 1 else {}
            fuzz_result = results[2] if len(results) > 2 else {}
            intent_result = results[3] if len(results) > 3 else {}
            
            # Step 3: Merge and format results
            logger.info("Step 3: Merging analysis results...")
            final_result = await self._merge_results(
                analysis_id=analysis_id,
                contract_name=request.contract_name,
                compilation_result=compilation_result,
                static_result=static_result,
                symbolic_result=symbolic_result,
                fuzz_result=fuzz_result,
                intent_result=intent_result,
                scan_type=request.scan_type
            )
            
            analysis_time = time.time() - start_time
            final_result["analysis_time"] = f"{analysis_time:.2f}s"
            
            logger.info(f"Analysis {analysis_id} completed in {analysis_time:.2f}s")
            return final_result
            
        except Exception as e:
            logger.error(f"Analysis {analysis_id} failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis_id": analysis_id
            }
    
    async def _run_static_analysis(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Run static analysis"""
        try:
            return await self.static_analyzer.analyze(contract_code, compilation_result)
        except Exception as e:
            logger.error(f"Static analysis failed: {e}")
            return {"success": False, "error": str(e), "vulnerabilities": []}
    
    async def _run_symbolic_execution(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Run symbolic execution"""
        try:
            return await self.symbolic_executor.analyze(contract_code, compilation_result)
        except Exception as e:
            logger.error(f"Symbolic execution failed: {e}")
            return {"success": False, "error": str(e), "vulnerabilities": []}
    
    async def _run_fuzz_testing(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Run fuzz testing"""
        try:
            return await self.fuzz_tester.analyze(contract_code, compilation_result)
        except Exception as e:
            logger.error(f"Fuzz testing failed: {e}")
            return {"success": False, "error": str(e), "vulnerabilities": []}
    
    async def _run_intent_detection(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Run AI intent detection"""
        try:
            return await self.intent_detector.analyze(contract_code, compilation_result)
        except Exception as e:
            logger.error(f"Intent detection failed: {e}")
            return {"success": False, "error": str(e), "findings": []}
    
    async def _merge_results(self, **kwargs) -> Dict:
        """Merge analysis results into final report"""
        try:
            analysis_id = kwargs.get('analysis_id')
            contract_name = kwargs.get('contract_name')
            compilation_result = kwargs.get('compilation_result', {})
            static_result = kwargs.get('static_result', {})
            symbolic_result = kwargs.get('symbolic_result', {})
            fuzz_result = kwargs.get('fuzz_result', {})
            intent_result = kwargs.get('intent_result', {})
            scan_type = kwargs.get('scan_type', 'basic')
            
            # Collect all vulnerabilities
            all_vulnerabilities = []
            
            # Add static analysis vulnerabilities
            if static_result.get('vulnerabilities'):
                all_vulnerabilities.extend(static_result['vulnerabilities'])
            
            # Add symbolic execution vulnerabilities
            if symbolic_result.get('vulnerabilities'):
                all_vulnerabilities.extend(symbolic_result['vulnerabilities'])
            
            # Add fuzz testing vulnerabilities
            if fuzz_result.get('vulnerabilities'):
                all_vulnerabilities.extend(fuzz_result['vulnerabilities'])
            
            # Deduplicate vulnerabilities
            unique_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
            
            # Calculate security score
            security_score = self._calculate_security_score(
                unique_vulnerabilities, 
                compilation_result.get('metrics', {})
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                unique_vulnerabilities, 
                intent_result.get('findings', [])
            )
            
            # Build final result
            result = {
                "success": True,
                "analysis_id": analysis_id,
                "contract_name": contract_name,
                "vulnerabilities": unique_vulnerabilities,
                "security_score": security_score,
                "gas_optimization": self._assess_gas_optimization(compilation_result),
                "complexity_score": compilation_result.get('metrics', {}).get('complexity_level', 'Unknown'),
                "functions_analyzed": compilation_result.get('metrics', {}).get('function_count', 0),
                "lines_of_code": compilation_result.get('metrics', {}).get('code_lines', 0),
                "solidity_version": compilation_result.get('solidity_version', 'Unknown'),
                "static_analysis": {
                    "completed": static_result.get('success', False),
                    "findings": static_result.get('findings', []),
                    "vulnerabilities_found": len(static_result.get('vulnerabilities', []))
                },
                "symbolic_execution": {
                    "completed": symbolic_result.get('success', False),
                    "findings": symbolic_result.get('findings', []),
                    "vulnerabilities_found": len(symbolic_result.get('vulnerabilities', []))
                },
                "fuzz_testing": {
                    "completed": fuzz_result.get('success', False),
                    "findings": fuzz_result.get('findings', []),
                    "test_cases_run": fuzz_result.get('test_cases_run', 0),
                    "vulnerabilities_found": len(fuzz_result.get('vulnerabilities', []))
                },
                "ai_analysis": {
                    "completed": intent_result.get('success', False),
                    "findings": intent_result.get('findings', []),
                    "confidence_score": intent_result.get('confidence', 0.0)
                },
                "recommendations": recommendations
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to merge analysis results: {e}")
            raise
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities based on title and location"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # Create unique key based on title and location
            key = (
                vuln.get('title', ''),
                vuln.get('location', {}).get('line', 0),
                vuln.get('severity', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _calculate_security_score(self, vulnerabilities: List[Dict], metrics: Dict) -> int:
        """Calculate overall security score"""
        try:
            base_score = 100
            
            # Deduct points based on vulnerability severity
            severity_weights = {
                'Critical': 25,
                'High': 15,
                'Medium': 8,
                'Low': 3,
                'Info': 1
            }
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Low')
                base_score -= severity_weights.get(severity, 3)
            
            # Additional deductions based on complexity
            complexity = metrics.get('complexity_level', 'Low')
            if complexity == 'High':
                base_score -= 5
            elif complexity == 'Medium':
                base_score -= 2
            
            # Bonus for good practices
            if metrics.get('comment_lines', 0) > metrics.get('code_lines', 0) * 0.1:
                base_score += 5  # Good documentation
            
            return max(0, min(100, base_score))
            
        except Exception as e:
            logger.error(f"Error calculating security score: {e}")
            return 50  # Default score
    
    def _assess_gas_optimization(self, compilation_result: Dict) -> str:
        """Assess gas optimization level"""
        try:
            metrics = compilation_result.get('metrics', {})
            bytecode_size = len(compilation_result.get('bytecode', '')) // 2  # Convert hex to bytes
            
            # Simple heuristics for gas optimization
            if bytecode_size < 10000:  # Less than 10KB
                return "Excellent"
            elif bytecode_size < 20000:  # Less than 20KB
                return "Good" 
            elif bytecode_size < 40000:  # Less than 40KB
                return "Fair"
            else:
                return "Needs Improvement"
            
        except Exception:
            return "Unknown"
    
    def _generate_recommendations(self, vulnerabilities: List[Dict], intent_findings: List[Dict]) -> List[Dict]:
        """Generate security recommendations"""
        recommendations = []
        
        try:
            # Generic recommendations based on vulnerabilities
            vuln_categories = set(vuln.get('category', '') for vuln in vulnerabilities)
            
            if 'Reentrancy' in vuln_categories:
                recommendations.append({
                    "title": "Implement Reentrancy Protection",
                    "description": "Use OpenZeppelin's ReentrancyGuard or follow the Checks-Effects-Interactions pattern.",
                    "priority": "High"
                })
            
            if 'Access Control' in vuln_categories:
                recommendations.append({
                    "title": "Strengthen Access Control",
                    "description": "Implement proper role-based access control using OpenZeppelin AccessControl.",
                    "priority": "High"
                })
            
            if 'Integer Overflow' in vuln_categories:
                recommendations.append({
                    "title": "Use Safe Math Operations",
                    "description": "Use Solidity 0.8+ built-in overflow checks or SafeMath library.",
                    "priority": "Medium"
                })
            
            # Recommendations based on intent analysis
            if intent_findings:
                recommendations.append({
                    "title": "Review Implementation vs Intent",
                    "description": "AI analysis detected potential mismatches between intended functionality and implementation.",
                    "priority": "Medium"
                })
            
            # Always include general recommendations
            recommendations.extend([
                {
                    "title": "Comprehensive Testing",
                    "description": "Implement unit tests, integration tests, and property-based testing.",
                    "priority": "High"
                },
                {
                    "title": "External Security Audit", 
                    "description": "Consider professional security audit before mainnet deployment.",
                    "priority": "Medium"
                },
                {
                    "title": "Documentation",
                    "description": "Add comprehensive NatSpec documentation for all public functions.",
                    "priority": "Low"
                }
            ])
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
        
        return recommendations
    
    async def check_tools_availability(self) -> Dict[str, bool]:
        """Check availability of analysis tools"""
        try:
            tools_status = {
                "solc": await self.compiler.initialize() is None,  # No exception means success
                "slither": await self.static_analyzer.check_availability(),
                "mythril": await self.symbolic_executor.check_availability(),
                "echidna": await self.fuzz_tester.check_availability(),
                "ai_models": await self.intent_detector.check_availability()
            }
            
            return tools_status
            
        except Exception as e:
            logger.error(f"Error checking tools availability: {e}")
            return {
                "solc": False,
                "slither": False,
                "mythril": False,
                "echidna": False,
                "ai_models": False
            }
    
    async def cleanup(self):
        """Clean up resources"""
        try:
            # Shutdown thread pool
            self.executor.shutdown(wait=True)
            
            # Cleanup individual components
            if hasattr(self.compiler, 'cleanup'):
                await self.compiler.cleanup()
                
            logger.info("Pipeline cleanup completed")
            
        except Exception as e:
            logger.error(f"Pipeline cleanup failed: {e}")
