# BODMAS Malware Detection Models

This repository contains trained machine learning models for malware detection using the BODMAS dataset. The models can classify PE (Portable Executable) files as either benign or malicious.

## Models Available

- **Random Forest**: Ensemble method with good interpretability
- **XGBoost**: Gradient boosting with high performance
- **Neural Network (MLP)**: Deep learning approach
- **SVM**: Support Vector Machine (Linear, calibrated)

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
pip install lief==0.9.0  # Required for PE file feature extraction
```

### 2. Use the Prediction Script

```python
from pe_malware_predictor import PEMalwarePredictor

# Initialize predictor with trained models
predictor = PEMalwarePredictor()

# Load models (adjust paths as needed)
predictor.load_models(
    model_files={
        'Random Forest': 'bodmas_malware_models_Random Forest_20250916_151423.joblib',
        'XGBoost': 'bodmas_malware_models_XGBoost_20250916_151423.joblib',
        'Neural Network': 'bodmas_malware_models_Neural Network_20250916_151423.joblib'
    },
    scaler_file='bodmas_malware_models_scaler_20250916_151423.joblib'
)

# Predict on a PE file
result = predictor.predict_pe_file('path/to/your/file.exe')
print(f"Prediction: {'Malware' if result['prediction'] == 1 else 'Benign'}")
print(f"Confidence: {result['confidence']}")
print(f"Probability: {result['probability']:.3f}")
```

### 3. Command Line Usage

```bash
python pe_malware_predictor.py path/to/file.exe
```

## Model Files

- `bodmas_malware_models_Random Forest_*.joblib`: Random Forest model
- `bodmas_malware_models_XGBoost_*.joblib`: XGBoost model  
- `bodmas_malware_models_Neural Network_*.joblib`: Neural Network model
- `bodmas_malware_models_scaler_*.joblib`: Feature scaler (required for Neural Network)
- `bodmas_malware_models_metadata_*.json`: Model metadata

## Features

The models expect 2,381 features extracted from PE files using the LIEF library. The feature extraction process includes:

- **PE Header Information**: Machine type, characteristics, entry point, etc.
- **Section Information**: Section names, characteristics, entropy, etc.
- **Import/Export Tables**: API calls, DLL imports, function exports
- **Resource Information**: Resource types, languages, versions
- **Debug Information**: Debug directories, timestamps
- **Rich Header**: Compiler information, build timestamps
- **TLS Information**: Thread Local Storage callbacks
- **Load Configuration**: Security features, exception handling
- **Relocations**: Base relocations, relocation types
- **Digital Signatures**: Certificate information, signature verification

## API Reference

### PEMalwarePredictor Class

#### `load_models(model_files, scaler_file=None)`
Load trained models from disk.

**Parameters:**
- `model_files` (dict): Dictionary mapping model names to file paths
- `scaler_file` (str): Path to scaler file (required for Neural Network)

#### `predict_pe_file(file_path, model_name=None)`
Predict malware for a single PE file.

**Parameters:**
- `file_path` (str): Path to the PE file
- `model_name` (str): Specific model to use (optional)

**Returns:**
- `dict`: Prediction results with 'prediction', 'probability', 'confidence'

#### `predict_pe_files(file_paths, model_name=None)`
Predict malware for multiple PE files.

**Parameters:**
- `file_paths` (list): List of PE file paths
- `model_name` (str): Specific model to use (optional)

**Returns:**
- `dict`: Prediction results for each file

#### `ensemble_predict_pe_file(file_path, voting='soft')`
Make ensemble prediction using all available models.

**Parameters:**
- `file_path` (str): Path to the PE file
- `voting` (str): 'soft' for probability voting, 'hard' for majority voting

**Returns:**
- `dict`: Ensemble prediction results

## Model Performance

Based on the BODMAS dataset evaluation:

| Model | Accuracy | Precision | Recall | F1-Score | AUC-ROC |
|-------|----------|-----------|--------|----------|---------|
| Random Forest | ~0.99 | ~0.99 | ~0.99 | ~0.99 | ~0.99 |
| XGBoost | ~0.99 | ~0.99 | ~0.99 | ~0.99 | ~0.99 |
| Neural Network | ~0.99 | ~0.99 | ~0.99 | ~0.99 | ~0.99 |

## Requirements

- Python 3.8+
- LIEF 0.9.0 (for PE file parsing)
- scikit-learn 1.7.2
- XGBoost 3.0.5
- NumPy 2.3.3
- Pandas 2.3.2

## Dataset Information

The models were trained on the BODMAS dataset:
- **Total samples**: 134,435
- **Malware samples**: 57,293
- **Benign samples**: 77,142
- **Features**: 2,381 (extracted using LIEF v0.9.0)
- **Malware families**: 581
- **Time period**: August 2019 to September 2020

## References

- BODMAS Dataset: https://github.com/bluehexagon/malware-datasets
- LIEF Project: https://lief.quarkslab.com/
- Original Paper: "BODMAS: An Open Dataset for Learning based Temporal Analysis of PE Malware"

## License

This project uses the BODMAS dataset and follows its licensing terms.