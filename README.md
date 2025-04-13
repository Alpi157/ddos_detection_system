# DDoS Detection using Machine Learning and Markov Chains

This project aims to provide a robust, two-layered defense mechanism against DDoS attacks by combining Machine Learning techniques for detection with Markov Chains for adaptive mitigation. It is designed for SDN scenarios but can be adapted to other network environments.

---

## Table of Contents

- [Overview](#1-overview)
- [Key Features](#2-key-features)
- [Project Structure](#3-project-structure)
- [Environment Setup](#4-environment-setup)
- [Usage](#5-usage)
- [System Architecture](#6-system-architecture)
- [How It Works](#7-how-it-works)
- [Detailed Explanation of Files](#8-detailed-explanation-of-files)
- [Logging & Monitoring](#9-logging--monitoring)
- [Experimental Notebook](#10-experimental-notebook)
- [Future Improvements](#11-future-improvements)

---

## 1. Overview

### Goal

To detect and mitigate DDoS attacks in real-time using:
- **Machine Learning** for detecting anomalies in network traffic (DDoS vs. benign)
- **Markov Chains** to dynamically choose and adapt mitigation strategies

### Approach

- A combination of a Deep Neural Network (DNN) and an SVM classifier that classify incoming traffic as either DDoS or benign.
- A finite-state Markov Chain with states: Normal, Suspicious, Under Attack, and Mitigation. Transitions are based on historical patterns and traffic statistics.
-  Adaptive strategies including Rate Limiting, Traffic Shaping, IP Blocking, and Dynamic Bandwidth Allocation.
- Each action is rewarded/penalized based on queue metrics, dropped packets, and overhead.

---

## 2. Key Features

- Two traffic queues: Benign and Malicious
- Stateful DDoS detection using Markov Chain transitions
- Adaptive mitigation using:
  - Rate Limiting
  - Traffic Shaping
  - IP Blocking (via Windows Firewall)
  - Dynamic Bandwidth Allocation
- Logging: key events to `.log` and `.csv` files
- Flask-based dashboard showing system status and metrics

---

## 3. Project Structure

```
.
├── static/                      # (Optional) Static files for Flask (CSS, JS, etc.)
├── templates/
│   └── dashboard.html           # Flask dashboard template
├── Diplom ddos analysis.ipynb   # Jupyter notebook with experiments, data analysis, and ML training
├── main.py                      # Main Flask app with detection & Markov Chain logic
├── sniff.py                     # Packet-sniffing script (Scapy)
├── simulate_benign.py           # Simulates benign traffic
├── attack_simulation.py         # Simulates DDoS traffic
├── svm_model.pkl                # Trained SVM model
├── model_deeper_state_dict.pth  # Trained PyTorch DNN model
├── scaler_joblib.pkl            # Feature scaler
├── encoder_joblib.pkl           # Categorical feature encoder
├── ddos_detection.log           # Detection and system events log
├── ddos_metrics_log.csv         # Metrics log (optional)
├── rewards_log.csv              # Rewards for reinforcement logic
└── requirements.txt             # Python dependencies
```

---

## 4. Environment Setup

1. Install Python 3.8+  
2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate   # Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing, manually install:

- Flask
- Flask-Limiter
- requests
- scapy
- torch (PyTorch)
- scikit-learn
- numpy, pandas, joblib

**Note:** IP blocking uses Windows Firewall. Run with admin privileges if required.

---

## 5. Usage

### 5.1 Launch the Flask App

```bash
python main.py
```

Server runs at `http://127.0.0.1:5000/`

### 5.2 Simulate Traffic

- **Benign:**

```bash
python simulate_benign.py
```

- **DDoS Attack:**

```bash
python attack_simulation.py
```

- **Real-Time Sniffing (Scapy):**

```bash
python sniff.py
```

---

### 5.3 View Dashboard

Open in browser:

```
http://127.0.0.1:5000/dashboard
```

Displays current state, queues, strategy, and reward statistics.


---

## 6. System Architecture

### Core Components

- **Flask web server** for:
  - Receiving and classifying traffic (`/predict` endpoint)
  - Displaying a dashboard (`/dashboard`)

- **Machine Learning Models**:
  - Deep Neural Network (PyTorch) – `model_deeper_state_dict.pth`
  - SVM model (joblib) – `svm_model.pkl`
  - Data Preprocessing – uses `scaler_joblib.pkl` and `encoder_joblib.pkl`

- **Markov Chain logic**:
  - State Transition Matrix (Normal, Suspicious, Under Attack, Mitigation)
  - Strategy Transition Matrix (RateLimiting, TrafficShaping, IPBlocking, DynamicBandwidth)

- **Queues**:
  - `benign_queue`
  - `attack_queue`

- **Reward Worker (Thread)**:
  - Computes queue metrics using M/M/1/B model
  - Calculates rewards for mitigation strategies
  - Logs results in `rewards_log.csv`

---

## 7. How It Works

### Traffic Arrival

Scripts (`attack_simulation.py`, `simulate_benign.py`, or `sniff.py`) send JSON data to:

```
http://127.0.0.1:5000/predict
```

### ML Detection

- Incoming data is encoded and scaled
- Both DNN and SVM predict classification
- If either predicts “DDoS,” traffic is marked malicious

### Queueing

- Benign traffic → `benign_queue`
- Malicious traffic → `attack_queue`

### Markov State Transitions

- State changes are based on volume of malicious traffic
- Possible states: Normal → Suspicious → Under Attack → Mitigation
- Telegram alerts can be enabled for state changes

### Mitigation Strategy Selection

- In Mitigation state, strategy is picked using Markov Chain & reward feedback
- Executed strategy can be:
  - Rate Limiting
  - Traffic Shaping
  - IP Blocking
  - Dynamic Bandwidth Allocation
- Rewards are logged and strategy effectiveness improves over time

### Reward Calculation

- M/M/1/B model used for queue metrics
- Metrics include queue length, waiting time, rejection rate
- Strategies rewarded/penalized based on thresholds
- Rewards logged in `rewards_log.csv`

---

## 8. Detailed Explanation of Files

### 8.1 main.py

- Entry point with Flask app
- Markov Chain definitions:
  - `state_transition_matrix`
  - `strategy_transition_matrix`
- `reward_worker()` – background thread to update strategy rewards
- Loads DNN & SVM models
- Endpoints:
  - `/predict`
  - `/dashboard`
  - `/start_simulation` & `/stop_simulation` (optional)

### 8.2 sniff.py

- Uses Scapy to sniff packets from a network interface
- Sends extracted features to Flask `/predict` endpoint

### 8.3 simulate_benign.py

- Simulates benign traffic with normal packet behavior

### 8.4 attack_simulation.py

- Simulates malicious traffic (e.g., high-rate traffic from IP `10.0.0.13`)

### 8.5 Diplom ddos analysis.ipynb

- Jupyter notebook with data preprocessing, model training & evaluation
- Models trained: DNN, SVM, KNN, Decision Tree
- Includes confusion matrices, loss plots, accuracy graphs

### 8.6 Model & Encoder Files

- `model_deeper_state_dict.pth` – PyTorch weights for DNN
- `svm_model.pkl` – Trained SVM classifier
- `scaler_joblib.pkl` – Scaler for numeric features
- `encoder_joblib.pkl` – Encoder for categorical data

### 8.7 Logs & CSVs

- `ddos_detection.log` – Logs actions, detections, transitions
- `ddos_metrics_log.csv` – Optional metrics for traffic
- `rewards_log.csv` – Strategy rewards over time

---

## 9. Logging and Monitoring

- Real-time events logged to `ddos_detection.log`
- Example entries:
  - "Blocked IP X"
  - "Rate limiting applied"
  - "Response time: Y seconds"

- Reward tracking in `rewards_log.csv`:
  - Strategy, reward value, penalties

**Real-time monitoring** (Linux/macOS):

```bash
tail -f ddos_detection.log
```

**On Windows (PowerShell):**

```powershell
Get-Content ddos_detection.log -Wait
```

---

## 10. Experimental Notebook

**File:** `Diplom ddos analysis.ipynb`

### Dataset

- CSV file (e.g., `ddos_sdn_dataset.csv`)

### Preprocessing

- Missing value handling
- Numeric scaling
- One-hot encoding for categories

### Models

- DNN, SVM, KNN, Decision Tree, Naive Bayes

### Tuning

- Keras Tuner used to optimize DNN

### Results

- DNN: Up to 99% accuracy
- SVM: ~98%

**Final models saved to:**

- `model_deeper_state_dict.pth`
- `svm_model.pkl`

---

## 11. Future Improvements

- **Cross-Platform Support**: Adapt firewall and mitigation for Linux/Mac
- **SDN Integration**: Deploy in SDN controllers (OpenDaylight, ONOS)
- **Advanced RL**: Replace Markov model with RL algorithms like Q-learning or DQN
- **Scalability**: Move to distributed/cloud-based deployment
- **Expanded Detection**: Add port scans, app-layer DDoS, etc.

---


