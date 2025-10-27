import asyncio
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from loguru import logger
from solcx import compile_source, get_installed_solc_versions, install_solc, set_solc_version


class SolidityCompiler:
    """Real Solidity compiler using py-solc-x"""
    
    def __init__(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="solc_"))
        self.installed_versions = set()
        self.default_version = "0.8.19"
        
    async def initialize(self):
        """Initialize the compiler"""
        try:
            # Get already installed versions
            try:
                self.installed_versions = set(get_installed_solc_versions())
                logger.info(f"Found installed Solidity versions: {self.installed_versions}")
            except Exception as e:
                logger.warning(f"Could not get installed versions: {e}")
                self.installed_versions = set()
            
            # Install default version if not available
            if not self.installed_versions:
                logger.info(f"Installing default Solidity version: {self.default_version}")
                install_solc(self.default_version)
                self.installed_versions.add(self.default_version)
            
            # Set default version
            latest_version = max(self.installed_versions)
            set_solc_version(latest_version)
            logger.info(f"Using Solidity version: {latest_version}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Solidity compiler: {e}")
            raise
    
    async def compile_contract(self, contract_code: str, contract_name: str) -> Dict:
        """Compile Solidity contract and return compilation results"""
        try:
            # Extract pragma version
            pragma_version = self._extract_pragma_version(contract_code)
            
            # Install required version if not available
            if pragma_version and pragma_version not in self.installed_versions:
                logger.info(f"Installing Solidity version: {pragma_version}")
                try:
                    install_solc(pragma_version)
                    self.installed_versions.add(pragma_version)
                    set_solc_version(pragma_version)
                except Exception as e:
                    logger.warning(f"Could not install version {pragma_version}, using default: {e}")
            
            # Compile the contract
            logger.info(f"Compiling contract: {contract_name}")
            
            compiled_sol = compile_source(
                contract_code,
                output_values=[
                    'abi', 'bin', 'bin-runtime', 'opcodes', 
                    'ast', 'storage-layout', 'devdoc', 'userdoc'
                ]
            )
            
            # Extract main contract (usually the last one)
            contracts = list(compiled_sol.keys())
            main_contract_key = contracts[-1] if contracts else None
            
            if not main_contract_key:
                raise Exception("No contracts found in compilation output")
            
            main_contract = compiled_sol[main_contract_key]
            
            # Parse compilation results
            result = {
                "success": True,
                "contract_name": contract_name,
                "solidity_version": pragma_version or "unknown",
                "bytecode": main_contract['bin'],
                "runtime_bytecode": main_contract['bin-runtime'],
                "abi": main_contract['abi'],
                "opcodes": main_contract.get('opcodes', ''),
                "ast": main_contract.get('ast', {}),
                "storage_layout": main_contract.get('storage-layout', {}),
                "devdoc": main_contract.get('devdoc', {}),
                "userdoc": main_contract.get('userdoc', {}),
                "contracts_found": len(contracts),
                "all_contracts": [key.split(':')[-1] for key in contracts]
            }
            
            # Extract function signatures
            result["function_signatures"] = self._extract_function_signatures(result["abi"])
            
            # Calculate code metrics
            result["metrics"] = self._calculate_metrics(contract_code, result["abi"])
            
            logger.info(f"Successfully compiled {contract_name}")
            return result
            
        except Exception as e:
            logger.error(f"Compilation failed for {contract_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "contract_name": contract_name,
                "solidity_version": pragma_version or "unknown"
            }
    
    def _extract_pragma_version(self, contract_code: str) -> Optional[str]:
        """Extract Solidity version from pragma statement"""
        try:
            # Look for pragma solidity statements
            pragma_pattern = r'pragma\s+solidity\s+([^;]+);'
            match = re.search(pragma_pattern, contract_code, re.IGNORECASE)
            
            if match:
                version_spec = match.group(1).strip()
                
                # Handle different version specifications
                if version_spec.startswith('^'):
                    # For ^0.8.0, use 0.8.19 (a stable version)
                    base_version = version_spec[1:]
                    if base_version.startswith('0.8'):
                        return '0.8.19'
                    elif base_version.startswith('0.7'):
                        return '0.7.6'
                    elif base_version.startswith('0.6'):
                        return '0.6.12'
                    elif base_version.startswith('0.5'):
                        return '0.5.17'
                    elif base_version.startswith('0.4'):
                        return '0.4.26'
                
                elif version_spec.startswith('>='):
                    # For >=0.8.0, use latest compatible
                    return '0.8.19'
                
                elif re.match(r'^\d+\.\d+\.\d+$', version_spec):
                    # Exact version specified
                    return version_spec
            
            return None
            
        except Exception as e:
            logger.warning(f"Could not extract pragma version: {e}")
            return None
    
    def _extract_function_signatures(self, abi: List[Dict]) -> List[Dict]:
        """Extract function signatures from ABI"""
        functions = []
        
        try:
            for item in abi:
                if item.get('type') == 'function':
                    # Build function signature
                    name = item['name']
                    inputs = item.get('inputs', [])
                    outputs = item.get('outputs', [])
                    
                    input_types = [param['type'] for param in inputs]
                    output_types = [param['type'] for param in outputs]
                    
                    signature = f"{name}({','.join(input_types)})"
                    
                    functions.append({
                        "name": name,
                        "signature": signature,
                        "inputs": inputs,
                        "outputs": outputs,
                        "stateMutability": item.get('stateMutability', 'nonpayable'),
                        "visibility": item.get('visibility', 'public')
                    })
                    
        except Exception as e:
            logger.error(f"Error extracting function signatures: {e}")
        
        return functions
    
    def _calculate_metrics(self, contract_code: str, abi: List[Dict]) -> Dict:
        """Calculate contract metrics"""
        try:
            lines = contract_code.split('\n')
            
            # Basic metrics
            total_lines = len(lines)
            code_lines = len([line for line in lines if line.strip() and not line.strip().startswith('//')])
            comment_lines = len([line for line in lines if line.strip().startswith('//')])
            
            # Function metrics
            function_count = len([item for item in abi if item.get('type') == 'function'])
            public_functions = len([
                item for item in abi 
                if item.get('type') == 'function' and 
                item.get('visibility') in ['public', 'external']
            ])
            
            # State mutability analysis
            view_functions = len([
                item for item in abi 
                if item.get('type') == 'function' and 
                item.get('stateMutability') in ['view', 'pure']
            ])
            
            payable_functions = len([
                item for item in abi 
                if item.get('type') == 'function' and 
                item.get('stateMutability') == 'payable'
            ])
            
            # Complexity estimation
            complexity_indicators = [
                'if', 'else', 'for', 'while', 'require', 'assert', 
                'modifier', 'mapping', 'struct', 'enum'
            ]
            
            complexity_score = 0
            code_lower = contract_code.lower()
            for indicator in complexity_indicators:
                complexity_score += code_lower.count(indicator)
            
            # Determine complexity level
            if complexity_score < 10:
                complexity_level = "Low"
            elif complexity_score < 25:
                complexity_level = "Medium"
            else:
                complexity_level = "High"
            
            return {
                "total_lines": total_lines,
                "code_lines": code_lines,
                "comment_lines": comment_lines,
                "function_count": function_count,
                "public_functions": public_functions,
                "view_functions": view_functions,
                "payable_functions": payable_functions,
                "complexity_score": complexity_score,
                "complexity_level": complexity_level
            }
            
        except Exception as e:
            logger.error(f"Error calculating metrics: {e}")
            return {}
    
    async def cleanup(self):
        """Clean up temporary files"""
        try:
            import shutil
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info("Cleaned up temporary compilation files")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
