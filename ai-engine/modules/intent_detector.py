import asyncio
import json
import pickle
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import nltk
import numpy as np
import pandas as pd
from loguru import logger
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split


class IntentDetector:
    """AI-powered intent detection using machine learning"""
    
    def __init__(self):
        self.models_dir = Path("models")
        self.models_dir.mkdir(exist_ok=True)
        
        self.intent_model = None
        self.vulnerability_classifier = None
        self.tfidf_vectorizer = None
        self.is_initialized = False
        
        # Contract patterns for intent analysis
        self.common_patterns = {
            'token': ['transfer', 'balanceof', 'approve', 'allowance', 'totalsupply'],
            'access_control': ['onlyowner', 'modifier', 'require', 'owner'],
            'financial': ['deposit', 'withdraw', 'payment', 'fund', 'balance'],
            'governance': ['vote', 'proposal', 'delegate', 'governance'],
            'auction': ['bid', 'auction', 'highest', 'winner'],
            'marketplace': ['buy', 'sell', 'price', 'listing'],
            'staking': ['stake', 'reward', 'unstake', 'yield'],
            'insurance': ['claim', 'premium', 'coverage', 'policy']
        }
        
    async def initialize(self):
        """Initialize AI models"""
        try:
            logger.info("Initializing AI intent detection models...")
            
            # Download required NLTK data
            await self._download_nltk_data()
            
            # Load or create models
            await self._load_or_create_models()
            
            self.is_initialized = True
            logger.info("Intent detector initialized successfully")
            
        except Exception as e:
            logger.error(f"Intent detector initialization failed: {e}")
            # Continue with basic functionality
            self.is_initialized = False
    
    async def analyze(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Analyze contract intent vs implementation"""
        try:
            if not self.is_initialized:
                return await self._basic_intent_analysis(contract_code, compilation_result)
            
            logger.info("Running AI intent detection analysis...")
            
            # Extract features from contract
            features = await self._extract_contract_features(contract_code, compilation_result)
            
            # Predict contract intent
            predicted_intent = await self._predict_intent(features)
            
            # Analyze intent vs implementation mismatches
            mismatches = await self._detect_intent_mismatches(
                contract_code, predicted_intent, features
            )
            
            # Calculate confidence score
            confidence = await self._calculate_confidence(features, predicted_intent)
            
            findings = [
                f"Detected contract type: {predicted_intent['primary_type']}",
                f"Confidence score: {confidence:.2f}",
                f"Found {len(mismatches)} potential intent mismatches",
                f"Analyzed {len(features.get('functions', []))} functions"
            ]
            
            return {
                "success": True,
                "findings": findings,
                "predicted_intent": predicted_intent,
                "intent_mismatches": mismatches,
                "confidence": confidence,
                "features": features,
                "tool": "IntentDetector"
            }
            
        except Exception as e:
            logger.error(f"Intent detection failed: {e}")
            return await self._basic_intent_analysis(contract_code, compilation_result)
    
    async def _basic_intent_analysis(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Basic intent analysis without ML models"""
        try:
            # Simple pattern-based analysis
            detected_patterns = {}
            code_lower = contract_code.lower()
            
            for category, patterns in self.common_patterns.items():
                matches = sum(1 for pattern in patterns if pattern in code_lower)
                if matches > 0:
                    detected_patterns[category] = matches
            
            # Determine primary intent
            primary_type = max(detected_patterns.keys(), key=detected_patterns.get) \
                          if detected_patterns else "general"
            
            # Basic mismatch detection
            mismatches = []
            
            # Check for common anti-patterns
            if 'token' in detected_patterns:
                if 'transfer' in code_lower and 'balanceof' not in code_lower:
                    mismatches.append({
                        "type": "missing_balance_check",
                        "description": "Token contract missing balance check before transfer",
                        "severity": "Medium",
                        "recommendation": "Add balance verification before transfers"
                    })
            
            if 'financial' in detected_patterns:
                if 'withdraw' in code_lower and 'onlyowner' not in code_lower:
                    mismatches.append({
                        "type": "missing_access_control",
                        "description": "Financial function lacks proper access control",
                        "severity": "High",
                        "recommendation": "Add access control to financial functions"
                    })
            
            findings = [
                f"Basic pattern analysis completed",
                f"Detected primary type: {primary_type}",
                f"Found {len(mismatches)} potential issues",
                "Note: Install ML dependencies for advanced intent detection"
            ]
            
            return {
                "success": True,
                "findings": findings,
                "predicted_intent": {
                    "primary_type": primary_type,
                    "detected_patterns": detected_patterns
                },
                "intent_mismatches": mismatches,
                "confidence": 0.6,  # Lower confidence for basic analysis
                "tool": "BasicIntentDetector"
            }
            
        except Exception as e:
            logger.error(f"Basic intent analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "findings": []
            }
    
    async def _download_nltk_data(self):
        """Download required NLTK data"""
        try:
            import ssl
            try:
                _create_unverified_https_context = ssl._create_unverified_context
            except AttributeError:
                pass
            else:
                ssl._create_default_https_context = _create_unverified_https_context
            
            nltk_data = ['punkt', 'stopwords', 'wordnet', 'averaged_perceptron_tagger']
            
            for data in nltk_data:
                try:
                    nltk.data.find(f'tokenizers/{data}')
                except LookupError:
                    logger.info(f"Downloading NLTK data: {data}")
                    nltk.download(data, quiet=True)
                    
        except Exception as e:
            logger.warning(f"NLTK data download failed: {e}")
    
    async def _load_or_create_models(self):
        """Load existing models or create new ones"""
        try:
            intent_model_path = self.models_dir / "intent_detection_model.pkl"
            vuln_classifier_path = self.models_dir / "vulnerability_classifier.pkl"
            
            if intent_model_path.exists() and vuln_classifier_path.exists():
                # Load existing models
                self.intent_model = joblib.load(intent_model_path)
                self.vulnerability_classifier = joblib.load(vuln_classifier_path)
                logger.info("Loaded existing ML models")
            else:
                # Create and train new models
                await self._create_and_train_models()
                logger.info("Created and trained new ML models")
                
        except Exception as e:
            logger.error(f"Model loading/creation failed: {e}")
            raise
    
    async def _create_and_train_models(self):
        """Create and train ML models from scratch"""
        try:
            # Generate training data
            training_data = self._generate_training_data()
            
            # Prepare features and labels
            X, y_intent, y_vuln = self._prepare_training_data(training_data)
            
            # Create TF-IDF vectorizer
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2)
            )
            X_vectorized = self.tfidf_vectorizer.fit_transform(X)
            
            # Train intent detection model
            self.intent_model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            self.intent_model.fit(X_vectorized, y_intent)
            
            # Train vulnerability classifier
            self.vulnerability_classifier = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=8
            )
            self.vulnerability_classifier.fit(X_vectorized, y_vuln)
            
            # Save models
            joblib.dump(self.intent_model, self.models_dir / "intent_detection_model.pkl")
            joblib.dump(self.vulnerability_classifier, self.models_dir / "vulnerability_classifier.pkl")
            joblib.dump(self.tfidf_vectorizer, self.models_dir / "tfidf_vectorizer.pkl")
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            raise
    
    def _generate_training_data(self) -> List[Dict]:
        """Generate synthetic training data for model training"""
        training_data = []
        
        # Token contracts
        token_samples = [
            {
                "code": "function transfer(address to, uint256 amount) public returns (bool) { balances[msg.sender] -= amount; balances[to] += amount; }",
                "intent": "token",
                "vulnerable": False
            },
            {
                "code": "function transfer(address to, uint256 amount) public { balances[to] += amount; }",
                "intent": "token", 
                "vulnerable": True  # Missing balance check
            }
        ]
        
        # Financial contracts
        financial_samples = [
            {
                "code": "function withdraw(uint256 amount) public onlyOwner { payable(msg.sender).transfer(amount); }",
                "intent": "financial",
                "vulnerable": False
            },
            {
                "code": "function withdraw() public { payable(msg.sender).transfer(address(this).balance); }",
                "intent": "financial",
                "vulnerable": True  # No access control
            }
        ]
        
        # Add more sample data for different contract types
        training_data.extend(token_samples)
        training_data.extend(financial_samples)
        
        # Add generated samples for other categories
        for category in self.common_patterns:
            patterns = self.common_patterns[category]
            sample_code = f"function example() public {{ {' '.join(patterns[:2])} }}"
            training_data.append({
                "code": sample_code,
                "intent": category,
                "vulnerable": False
            })
        
        return training_data
    
    def _prepare_training_data(self, training_data: List[Dict]) -> Tuple[List[str], List[str], List[bool]]:
        """Prepare training data for ML models"""
        X = []  # Features (code)
        y_intent = []  # Intent labels
        y_vuln = []  # Vulnerability labels
        
        for sample in training_data:
            X.append(sample["code"])
            y_intent.append(sample["intent"])
            y_vuln.append(sample["vulnerable"])
        
        return X, y_intent, y_vuln
    
    async def _extract_contract_features(self, contract_code: str, compilation_result: Dict) -> Dict:
        """Extract features from contract for ML analysis"""
        try:
            features = {
                "raw_code": contract_code,
                "code_length": len(contract_code),
                "functions": [],
                "keywords": {},
                "complexity_metrics": {},
                "abi_features": {}
            }
            
            # Extract function information
            abi = compilation_result.get("abi", [])
            for item in abi:
                if item.get("type") == "function":
                    features["functions"].append({
                        "name": item["name"],
                        "inputs": len(item.get("inputs", [])),
                        "outputs": len(item.get("outputs", [])),
                        "stateMutability": item.get("stateMutability", "nonpayable")
                    })
            
            # Count keywords and patterns
            code_lower = contract_code.lower()
            for category, patterns in self.common_patterns.items():
                count = sum(1 for pattern in patterns if pattern in code_lower)
                features["keywords"][category] = count
            
            # Extract complexity metrics
            metrics = compilation_result.get("metrics", {})
            features["complexity_metrics"] = {
                "functions_count": metrics.get("function_count", 0),
                "lines_of_code": metrics.get("code_lines", 0),
                "complexity_level": metrics.get("complexity_level", "Unknown")
            }
            
            # ABI-based features
            features["abi_features"] = {
                "total_functions": len([item for item in abi if item.get("type") == "function"]),
                "payable_functions": len([item for item in abi if item.get("stateMutability") == "payable"]),
                "view_functions": len([item for item in abi if item.get("stateMutability") in ["view", "pure"]])
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return {"error": str(e)}
    
    async def _predict_intent(self, features: Dict) -> Dict:
        """Predict contract intent using ML model"""
        try:
            if not self.intent_model or not self.tfidf_vectorizer:
                return {"primary_type": "unknown", "confidence": 0.0}
            
            # Vectorize the contract code
            code_vector = self.tfidf_vectorizer.transform([features["raw_code"]])
            
            # Predict intent
            prediction = self.intent_model.predict(code_vector)[0]
            probabilities = self.intent_model.predict_proba(code_vector)[0]
            
            # Get top predictions with probabilities
            classes = self.intent_model.classes_
            top_predictions = []
            
            for i, prob in enumerate(probabilities):
                if prob > 0.1:  # Only include predictions with >10% confidence
                    top_predictions.append({
                        "type": classes[i],
                        "probability": float(prob)
                    })
            
            # Sort by probability
            top_predictions.sort(key=lambda x: x["probability"], reverse=True)
            
            return {
                "primary_type": prediction,
                "confidence": float(max(probabilities)),
                "all_predictions": top_predictions
            }
            
        except Exception as e:
            logger.error(f"Intent prediction failed: {e}")
            return {"primary_type": "unknown", "confidence": 0.0}
    
    async def _detect_intent_mismatches(self, contract_code: str, predicted_intent: Dict, features: Dict) -> List[Dict]:
        """Detect mismatches between intent and implementation"""
        mismatches = []
        
        try:
            primary_type = predicted_intent.get("primary_type", "unknown")
            code_lower = contract_code.lower()
            
            # Token contract specific checks
            if primary_type == "token":
                if "transfer" in code_lower and "balances[msg.sender]" not in code_lower:
                    mismatches.append({
                        "type": "token_balance_check",
                        "description": "Token transfer function missing sender balance check",
                        "severity": "High",
                        "recommendation": "Add balance verification: require(balances[msg.sender] >= amount)"
                    })
                
                if "approve" not in code_lower and "allowance" not in code_lower:
                    mismatches.append({
                        "type": "token_approval_missing",
                        "description": "Token contract missing approval mechanism",
                        "severity": "Medium",
                        "recommendation": "Implement approve() and allowance() functions for ERC-20 compatibility"
                    })
            
            # Financial contract specific checks
            elif primary_type == "financial":
                withdraw_functions = re.findall(r'function\s+withdraw.*?\{', code_lower, re.DOTALL)
                for func in withdraw_functions:
                    if "onlyowner" not in func and "require" not in func:
                        mismatches.append({
                            "type": "financial_access_control",
                            "description": "Financial withdrawal function lacks access control",
                            "severity": "Critical",
                            "recommendation": "Add proper access control modifier to withdrawal functions"
                        })
            
            # Access control contract checks
            elif primary_type == "access_control":
                if "modifier" not in code_lower:
                    mismatches.append({
                        "type": "access_control_implementation",
                        "description": "Access control contract without custom modifiers",
                        "severity": "Low",
                        "recommendation": "Consider implementing custom access control modifiers"
                    })
            
            # Generic checks for all contract types
            if "selfdestruct" in code_lower or "suicide" in code_lower:
                if "onlyowner" not in code_lower:
                    mismatches.append({
                        "type": "destructive_function_access",
                        "description": "Contract destruction function lacks proper access control",
                        "severity": "Critical",
                        "recommendation": "Restrict contract destruction to authorized users only"
                    })
            
            return mismatches
            
        except Exception as e:
            logger.error(f"Intent mismatch detection failed: {e}")
            return []
    
    async def _calculate_confidence(self, features: Dict, predicted_intent: Dict) -> float:
        """Calculate overall confidence score for the analysis"""
        try:
            base_confidence = predicted_intent.get("confidence", 0.0)
            
            # Adjust confidence based on various factors
            adjustments = 0.0
            
            # More functions = higher confidence
            func_count = features.get("complexity_metrics", {}).get("functions_count", 0)
            if func_count > 5:
                adjustments += 0.1
            elif func_count > 10:
                adjustments += 0.2
            
            # More code = higher confidence
            code_length = features.get("code_length", 0)
            if code_length > 1000:
                adjustments += 0.05
            elif code_length > 5000:
                adjustments += 0.1
            
            # Pattern matches increase confidence
            keyword_matches = sum(features.get("keywords", {}).values())
            if keyword_matches > 3:
                adjustments += 0.1
            
            final_confidence = min(1.0, base_confidence + adjustments)
            return final_confidence
            
        except Exception as e:
            logger.error(f"Confidence calculation failed: {e}")
            return 0.5
    
    async def check_availability(self) -> bool:
        """Check if AI models are available"""
        return self.is_initialized or True  # Basic analysis always available
