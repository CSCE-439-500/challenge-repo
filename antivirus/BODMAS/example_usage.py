#!/usr/bin/env python3
"""
Example usage of the PE Malware Predictor

This script demonstrates how to use the trained BODMAS models
to predict malware in PE files.
"""

from pe_malware_predictor import PEMalwarePredictor
import os
import glob

def main():
    """Example usage of the PE malware predictor."""
    
    # Initialize the predictor
    predictor = PEMalwarePredictor()
    
    # Load models (adjust paths as needed)
    model_files = {
        'Random Forest': 'bodmas_malware_models_Random Forest_20250916_151423.joblib',
        'XGBoost': 'bodmas_malware_models_XGBoost_20250916_151423.joblib',
        'Neural Network': 'bodmas_malware_models_Neural Network_20250916_151423.joblib'
    }
    
    scaler_file = 'bodmas_malware_models_scaler_20250916_151423.joblib'
    metadata_file = 'bodmas_malware_models_metadata_20250916_151423.json'
    
    # Check if model files exist
    missing_files = []
    for name, filepath in model_files.items():
        if not os.path.exists(filepath):
            missing_files.append(f"{name}: {filepath}")
    
    if not os.path.exists(scaler_file):
        missing_files.append(f"Scaler: {scaler_file}")
    
    if missing_files:
        print("Warning: Some model files are missing:")
        for missing in missing_files:
            print(f"  - {missing}")
        print("\nPlease ensure all model files are in the current directory.")
        return
    
    # Load models
    print("Loading trained models...")
    predictor.load_models(model_files, scaler_file, metadata_file)
    
    if not predictor.models:
        print("Error: No models could be loaded.")
        return
    
    print(f"Successfully loaded {len(predictor.models)} models: {list(predictor.models.keys())}")
    
    # Example 1: Predict on a single PE file
    print("\n" + "="*50)
    print("Example 1: Single PE file prediction")
    print("="*50)
    
    # Replace with actual PE file path
    pe_file = "example.exe"  # Change this to your PE file path
    
    if os.path.exists(pe_file):
        try:
            # Individual model predictions
            results = predictor.predict_pe_file(pe_file)
            
            print(f"Analyzing: {pe_file}")
            print("\nIndividual Model Results:")
            for model_name, result in results.items():
                prediction = "Malware" if result['prediction'] == 1 else "Benign"
                print(f"  {model_name}: {prediction} (prob: {result['probability']:.3f}, conf: {result['confidence']})")
            
            # Ensemble prediction
            ensemble_result = predictor.ensemble_predict_pe_file(pe_file)
            print(f"\nEnsemble Prediction:")
            print(f"  Result: {'Malware' if ensemble_result['ensemble_prediction'] == 1 else 'Benign'}")
            print(f"  Probability: {ensemble_result['ensemble_probability']:.3f}")
            print(f"  Confidence: {ensemble_result['ensemble_confidence']}")
            
        except Exception as e:
            print(f"Error analyzing {pe_file}: {e}")
    else:
        print(f"PE file not found: {pe_file}")
        print("Please provide a valid PE file path.")
    
    # Example 2: Batch prediction on multiple files
    print("\n" + "="*50)
    print("Example 2: Batch prediction")
    print("="*50)
    
    # Look for PE files in current directory
    pe_files = glob.glob("*.exe") + glob.glob("*.dll") + glob.glob("*.sys")
    
    if pe_files:
        print(f"Found {len(pe_files)} PE files for batch analysis:")
        for pe_file in pe_files[:3]:  # Limit to first 3 files
            print(f"  - {pe_file}")
        
        # Batch prediction
        batch_results = predictor.predict_pe_files(pe_files[:3])
        
        print("\nBatch Results:")
        for file_path, results in batch_results.items():
            if 'error' in results:
                print(f"  {file_path}: Error - {results['error']}")
            else:
                # Use ensemble result for simplicity
                ensemble_result = predictor.ensemble_predict_pe_file(file_path)
                prediction = "Malware" if ensemble_result['ensemble_prediction'] == 1 else "Benign"
                print(f"  {file_path}: {prediction} (prob: {ensemble_result['ensemble_probability']:.3f})")
    else:
        print("No PE files found in current directory.")
    
    # Example 3: Using specific model
    print("\n" + "="*50)
    print("Example 3: Using specific model")
    print("="*50)
    
    if os.path.exists(pe_file):
        try:
            # Use only Random Forest model
            rf_result = predictor.predict_pe_file(pe_file, model_name='Random Forest')
            
            print(f"Using Random Forest model on: {pe_file}")
            for model_name, result in rf_result.items():
                prediction = "Malware" if result['prediction'] == 1 else "Benign"
                print(f"  Result: {prediction} (prob: {result['probability']:.3f}, conf: {result['confidence']})")
                
        except Exception as e:
            print(f"Error: {e}")
    
    print("\n" + "="*50)
    print("Example completed!")
    print("="*50)


if __name__ == '__main__':
    main()
