# Tri-ELM Secure E-Learning System

A security-oriented e-learning data processing and threat detection framework that integrates **Mem-PViT**, **EFAL-Pa**, and **TuWaSa-API** for memory-state analysis, data-security decisions, and API privilege/threat detection.

## Overview

The **Tri-ELM Secure E-Learning System** provides a unified preprocessing, feature extraction, security analysis, and threat detection pipeline for e-learning environments.

The framework processes multiple e-learning and security datasets, including API requests, authentication logs, authorization logs, examination responses, student activity, autosave states, delayed uploads, encryption events, security events, and other system-level records.

## Main Components

### 1. ELearningSecurityPreprocessor

The preprocessing module performs:

* CSV data loading
* Memory snapshot capture
* Memory tokenization
* Data cleaning
* Missing-value handling
* Numerical normalization
* Data sensitivity classification
* API request preprocessing
* Memory-behavior feature extraction
* Data-security feature extraction
* API feature extraction

The implementation recognizes **high-, medium-, and low-sensitivity** data categories based on the dataset structure.

### 2. Mem-PViT

**Mem-PViT (Memory Snapshot Tokenized LightWeight Plain Vision Transformer)** extracts features from transient memory snapshots.

The extracted features include:

* Token count
* Unique tokens
* Duplication rate
* Sensitive token ratio
* Temporal delay

These features are subsequently used for memory-based attack detection.

### 3. EFAL-Pa

The **EFAL-Pa** component extracts data-security characteristics such as:

* Sensitivity level
* Data type
* Confidentiality requirement
* Integrity requirement
* Authentication requirement
* Encryption applicability
* Digital signature requirement

Security operations are selected according to the sensitivity and data type of each data fragment.

### 4. TuWaSa-API

The **TuWaSa-API** component extracts API privilege and behavioral features, including:

* Permission level
* Request frequency
* Token age
* Behavioral entropy
* Failed attempts
* Permission overlap

These features are used to identify suspicious API activity and potential privilege-escalation attacks.

## Threat Detection

The detection engine provides three major security functions:

### Memory Attack Detection

Memory behavior is evaluated using indicators such as:

* High duplication
* High sensitive-token ratio
* Unusual temporal delays
* Excessive token counts

An anomaly score is calculated and used to identify suspicious memory events.

### Data-Security Enforcement

Security operations are selected based on sensitivity and data type. The framework supports operations involving:

* FALCON
* Paillier
* FALCON + Paillier
* Context-dependent protection
* Lightweight protection

### API Threat Detection

The API detection module evaluates:

* Elevated permissions
* High request frequency
* Stale tokens
* Multiple failed attempts
* Permission overlap

Potential attack categories include:

* Brute-force attack
* Token-reuse attack
* Privilege escalation
* DoS attempt
* Suspicious behavior

## Dataset Structure

The preprocessing pipeline is designed to work with CSV files representing different e-learning and security activities. Supported data categories include:

```text
api_anomalies
api_rate_limits
api_requests
api_responses
assignment_submissions
attack_events
attendance_logs
authentication_logs
authorization_logs
autosave_states
connection_logs
courses
delayed_uploads
device_events
discussion_logs
encryption_events
exam_responses
instructor_feedback
interservice_communication
key_rotation_logs
learning_progress
network_events
peer_interactions
performance_logs
scores
security_events
session_logs
student_activity
student_profiles
system_metadata
threat_detection
tls_events
token_events
traffic_statistics
tri_elm_master_education
tri_elm_master_security
```

## Pipeline

The complete workflow is:

```text
Raw E-Learning CSV Data
          |
          v
Data Loading
          |
          v
Memory Snapshot Capture
          |
          v
Memory Tokenization
          |
          v
Data Cleaning & Normalization
          |
          v
Sensitivity Classification
          |
          v
API Request Preprocessing
          |
          +-------------------+
          |                   |
          v                   v
      Mem-PViT             EFAL-Pa
   Feature Extraction   Feature Extraction
          |                   |
          +---------+---------+
                    |
                    v
              TuWaSa-API
           Feature Extraction
                    |
                    v
             Detection Engine
                    |
          +---------+---------+
          |                   |
          v                   v
    Memory Threats       API Threats
          |
          v
    Security Decisions
```

The complete pipeline is implemented through `run_preprocessing_pipeline()`.

## Requirements

Install the required Python packages:

```bash
pip install pandas numpy scikit-learn
```

## Usage

Set the path to the directory containing the CSV datasets:

```python
from your_script import run_preprocessing_pipeline

base_path = "path/to/Tri_ELM_Dataset"

results = run_preprocessing_pipeline(base_path)
```

The pipeline returns:

```text
preprocessing
features
detection
```

The feature results include:

```text
Mem-PViT
EFAL-Pa
TuWaSa-API
```

while the detection results include:

```text
memory_threats
api_threats
security_decisions
```

## Output

The pipeline reports:

* Number of loaded datasets
* Number of memory snapshots
* Number of extracted memory features
* Number of security features
* Number of API features
* Number of detected memory threats
* Number of detected API threats
* Number of applied security decisions

The supplied implementation also contains an example section that serializes the final results to `preprocessing_results.json`.

## Project Structure

A recommended repository structure is:

```text
Tri-ELM-Secure-E-Learning-System/
│
├── README.md
├── requirements.txt
├── src/
│   └── tri_elm_pipeline.py
│
├── dataset/
│   ├── api_requests.csv
│   ├── authentication_logs.csv
│   ├── authorization_logs.csv
│   ├── autosave_states.csv
│   └── ...
│
├── results/
│   └── preprocessing_results.json
│
└── .gitignore
```

## Security Features

The framework focuses on:

* E-learning data protection
* Transient memory-state analysis
* Sensitive academic-data classification
* API privilege analysis
* Authentication and authorization monitoring
* Encryption and signature decision support
* Suspicious memory-event detection
* API threat detection
* Privilege-escalation identification

## Technologies

* Python
* Pandas
* NumPy
* Scikit-learn
* Standard Python libraries
* CSV-based e-learning and security datasets

## License

Add the appropriate license for your research project before publishing the repository.

## Citation

If you use this repository in research or academic work, please cite the associated research work.

## Acknowledgement

This repository provides an implementation of the Tri-ELM security processing pipeline, integrating memory analysis, data-security feature extraction, API privilege analysis, and threat detection into a unified e-learning security framework.
