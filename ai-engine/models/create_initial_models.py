"""
Script to create initial ML models for intent detection.
This will be automatically executed if models don't exist.
"""

import joblib
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer


def create_dummy_models():
    """Create basic dummy models for initial deployment"""
    models_dir = Path("models")
    models_dir.mkdir(exist_ok=True)
    
    # Sample training data
    sample_contracts = [
        ("function transfer(address to, uint256 amount) public", "token"),
        ("function withdraw() public onlyOwner", "financial"),
        ("function vote(uint256 proposalId) public", "governance"),
        ("function deposit() public payable", "financial"),
        ("function mint(address to, uint256 amount) public", "token")
    ]
    
    # Create TF-IDF vectorizer
    vectorizer = TfidfVectorizer(max_features=100)
    X = [contract[0] for contract in sample_contracts]
    y = [contract[1] for contract in sample_contracts]
    
    X_vectorized = vectorizer.fit_transform(X)
    
    # Create and train intent detection model
    intent_model = RandomForestClassifier(n_estimators=10, random_state=42)
    intent_model.fit(X_vectorized, y)
    
    # Create and train vulnerability classifier
    vuln_labels = [False, True, False, True, False]  # Sample vulnerability labels
    vuln_classifier = RandomForestClassifier(n_estimators=10, random_state=42)
    vuln_classifier.fit(X_vectorized, vuln_labels)
    
    # Save models
    joblib.dump(intent_model, models_dir / "intent_detection_model.pkl")
    joblib.dump(vuln_classifier, models_dir / "vulnerability_classifier.pkl")
    joblib.dump(vectorizer, models_dir / "tfidf_vectorizer.pkl")
    
    print("✅ Created initial ML models")


if __name__ == "__main__":
    create_dummy_models()
