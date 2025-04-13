import random
from flask import Flask, request, jsonify, render_template
import time
import threading
import torch
import torch.nn as nn
import joblib
import pandas as pd
import logging
from queue import Queue
from collections import deque
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from threading import Lock
import subprocess
import requests
import csv  # Import CSV module

app = Flask(__name__)

# Flask limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["552000 per day", "31120 per hour"]
)

# Logging setup
logging.basicConfig(filename='ddos_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Initialize CSV file
with open('rewards_log.csv', mode='w', newline='') as csv_file:
    fieldnames = ['timestamp', 'strategy', 'reward', 'penalties', 'total_reward']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    writer.writeheader()

# Global variables
benign_queue = Queue()  # Queue for benign traffic
attack_queue = Queue()  # Queue for malicious traffic
benign_arrival_times = deque(maxlen=1000)
attack_arrival_times = deque(maxlen=1000)
rewards = {"RateLimiting": 0, "TrafficShaping": 0, "IPBlocking": 0, "DynamicBandwidth": 0}
traffic_stats = {"malicious_packets": 0, "legitimate_packets": 0}
current_state = "Normal"  # Initial state
current_strategy = "RateLimiting"
packet_counter = {"malicious": 0, "benign": 0}  # Tracks processed packets
ip_ban_list = []  # List of blocked IP addresses
blocked_ips = {}  # Format: {"ip_address": block_timestamp}
BLOCK_COOLDOWN_SECONDS = 300  # Cooldown before re-blocking an IP
detected_ip = None  # Tracks detected malicious IP

# Thread locks for thread safety
rewards_lock = Lock()
counts_lock = Lock()
strategy_counts = {"RateLimiting": 1, "TrafficShaping": 1, "IPBlocking": 1, "DynamicBandwidth": 1}  # Avoid division by zero

# State transition probabilities
state_transition_matrix = {
    "Normal": {"Normal": 85, "Suspicious": 10, "Under Attack": 5, "Mitigation": 0},
    "Suspicious": {"Normal": 20, "Suspicious": 60, "Under Attack": 20, "Mitigation": 0},
    "Under Attack": {"Normal": 0, "Suspicious": 15, "Under Attack": 20, "Mitigation": 65},
    "Mitigation": {"Normal": 10, "Suspicious": 20, "Under Attack": 10, "Mitigation": 60}
}

# Strategy transition probabilities
strategy_transition_matrix = {
    "RateLimiting": {"RateLimiting": 40, "TrafficShaping": 30, "IPBlocking": 10, "DynamicBandwidth": 20},
    "TrafficShaping": {"TrafficShaping": 50, "RateLimiting": 20, "IPBlocking": 10, "DynamicBandwidth": 20},
    "IPBlocking": {"IPBlocking": 40, "TrafficShaping": 30, "RateLimiting": 10, "DynamicBandwidth": 20},
    "DynamicBandwidth": {"DynamicBandwidth": 50, "RateLimiting": 20, "TrafficShaping": 20, "IPBlocking": 10}
}

# State messages
state_messages = {
    "Normal": "Traffic back to normal.",
    "Suspicious": "Initial signs of attack detected. Traffic shaping enabled.",
    "Under Attack": "Confirmed DDoS attack detected.",
    "Mitigation": "Defensive measures applied."
}

# Load models
class DeeperNN(nn.Module):
    def __init__(self):
        super(DeeperNN, self).__init__()
        self.fc1 = nn.Linear(68, 128)
        self.dropout1 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(128, 64)
        self.dropout2 = nn.Dropout(0.3)
        self.fc3 = nn.Linear(64, 32)
        self.fc4 = nn.Linear(32, 1)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.dropout1(x)
        x = self.relu(self.fc2(x))
        x = self.dropout2(x)
        x = self.relu(self.fc3(x))
        x = torch.sigmoid(self.fc4(x))
        return x

deep_model = DeeperNN()
deep_model.load_state_dict(torch.load('model_deeper_state_dict.pth'))
deep_model.eval()

svm_model = joblib.load('svm_model.pkl')
scaler = joblib.load("scaler_joblib.pkl")
encoder = joblib.load("encoder_joblib.pkl")

# Middleware to block requests from banned IPs
@app.before_request
def block_method():
    ip = request.remote_addr
    if ip in ip_ban_list:
        log_event(f"Blocked request from IP: {ip} (IP in ban list).")
        return jsonify({"error": "Access denied. Your IP has been blocked."}), 403

# Log events
def log_event(event):
    logging.info(event)

# Traffic monitoring
def monitor_traffic():
    global traffic_stats
    traffic_stats = {
        "malicious_packets": packet_counter["malicious"],
        "legitimate_packets": packet_counter["benign"]
    }
    return traffic_stats

# Send Telegram notifications
def send_telegram_message(message):
    # Note: Replace 'YOUR_TELEGRAM_TOKEN' and 'YOUR_TELEGRAM_CHAT_ID' with actual values
    TELEGRAM_TOKEN = 'YOUR_TELEGRAM_TOKEN'
    TELEGRAM_CHAT_ID = 'YOUR_TELEGRAM_CHAT_ID'
    TELEGRAM_URL = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    data = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'Markdown'}
    requests.post(TELEGRAM_URL, json=data)

# Block IP function with cooldown
def block_ip(ip):
    current_time = time.time()
    if ip in blocked_ips and current_time - blocked_ips[ip] < BLOCK_COOLDOWN_SECONDS:
        log_event(f"IP {ip} is in cooldown period and cannot be re-blocked.")
        return
    ip_ban_list.append(ip)
    blocked_ips[ip] = current_time
    log_event(f"Blocked IP: {ip}")

def block_ip_windows_firewall(ip):
    # Block the IP using Windows Firewall
    try:
        block_command = f'New-NetFirewallRule -DisplayName "BlockIP_{ip}" -Direction Inbound -RemoteAddress {ip} -Action Block'
        subprocess.run(['powershell', '-Command', block_command], capture_output=True)
        log_event(f"Blocked IP {ip} using Windows Firewall.")
    except Exception as e:
        log_event(f"Error blocking IP {ip} in Windows Firewall: {e}")

# Enable Traffic Shaping
def enable_traffic_shaping():
    log_event("Traffic shaping enabled")
    try:
        benign_cmd = 'New-NetQosPolicy -Name "BenignTraffic" -IPProtocolMatchCondition IPv4 -PriorityValue8021Action 0'
        attack_cmd = 'New-NetQosPolicy -Name "AttackTraffic" -IPProtocolMatchCondition IPv4 -ThrottleRateActionBitsPerSecond 1000000'
        subprocess.run(['powershell', '-Command', benign_cmd], capture_output=True)
        subprocess.run(['powershell', '-Command', attack_cmd], capture_output=True)
        log_event("Traffic shaping policies created.")
    except Exception as e:
        log_event(f"Error enabling traffic shaping: {e}")

# Disable Traffic Shaping
def disable_traffic_shaping():
    log_event("Traffic shaping disabled")
    try:
        benign_cmd = 'Remove-NetQosPolicy -Name "BenignTraffic" -Confirm:$false'
        attack_cmd = 'Remove-NetQosPolicy -Name "AttackTraffic" -Confirm:$false'
        subprocess.run(['powershell', '-Command', benign_cmd], capture_output=True)
        subprocess.run(['powershell', '-Command', attack_cmd], capture_output=True)
        log_event("Traffic shaping policies removed.")
    except Exception as e:
        log_event(f"Error disabling traffic shaping: {e}")

# Dynamic Bandwidth Allocation
def dynamic_bandwidth_allocation():
    log_event("Dynamic Bandwidth Allocation: Adjusting bandwidth.")
    try:
        # Remove existing policies if any
        remove_cmd = 'Get-NetQosPolicy -PolicyStore ActiveStore | Remove-NetQosPolicy -Confirm:$false'
        subprocess.run(['powershell', '-Command', remove_cmd], capture_output=True)
        # Create new policy with adjusted bandwidth
        # Example: Limit bandwidth to 10 Mbps for attack traffic
        attack_cmd = 'New-NetQosPolicy -Name "AttackTraffic" -IPProtocolMatchCondition IPv4 -ThrottleRateActionBitsPerSecond 10000000'
        subprocess.run(['powershell', '-Command', attack_cmd], capture_output=True)
        log_event("Dynamic Bandwidth Allocation: Bandwidth adjusted for attack traffic.")
    except Exception as e:
        log_event(f"Error adjusting bandwidth: {e}")

# Compute M/M/1/B metrics
def compute_mm1b_metrics(queue, arrival_rate, service_rate, buffer_size):
    print(f"Computing metrics: Arrival rate = {arrival_rate}, Service rate = {service_rate}, Queue length = {queue.qsize()}")
    rho = arrival_rate / service_rate if service_rate > 0 else 0
    queue_length = queue.qsize()

    if rho >= 1:
        print("System overloaded: Utilization (rho) >= 1")
        return {"L": float("inf"), "W": float("inf"), "P_reject": 1.0, "Queue_Length": queue_length}

    p_reject = (rho ** buffer_size) * (1 - rho) / (1 - rho ** (buffer_size + 1))
    l = (rho * (1 - (buffer_size + 1) * rho ** buffer_size + buffer_size * rho ** (buffer_size + 1))) / (
        (1 - rho) * (1 - rho ** (buffer_size + 1))
    )
    w = l / (arrival_rate * (1 - p_reject)) if arrival_rate > 0 else float("inf")

    print(f"Metrics: L = {l}, W = {w}, P_reject = {p_reject}, Queue_Length = {queue_length}")
    return {"L": l, "W": w, "P_reject": p_reject, "Queue_Length": queue_length}

# Reward calculation
def compute_reward(benign_metrics, attack_metrics, strategy):
    print(f"Benign Metrics: {benign_metrics}")
    print(f"Attack Metrics: {attack_metrics}")
    reward = 0
    penalties = []

    # Strategy-specific effectiveness goals
    strategy_effectiveness = {
        "RateLimiting": {"max_reject": 0.2, "min_attack_queue": 5, "max_benign_queue": 10},
        "TrafficShaping": {"max_reject": 0.1, "min_attack_queue": 3, "max_benign_queue": 8},
        "IPBlocking": {"max_reject": 0.05, "min_attack_queue": 1, "max_benign_queue": 5},
        "DynamicBandwidth": {"max_reject": 0.3, "min_attack_queue": 7, "max_benign_queue": 12},
    }

    # Action costs for strategies
    action_costs = {
        "RateLimiting": 1,
        "TrafficShaping": 2,
        "IPBlocking": 10,  # Increased cost to penalize overuse
        "DynamicBandwidth": 2,
    }

    # Get the effectiveness goals for the current strategy
    effectiveness = strategy_effectiveness.get(strategy, {})

    # Attack Queue Penalties
    if attack_metrics["Queue_Length"] > effectiveness["min_attack_queue"]:
        penalty = (attack_metrics["Queue_Length"] - effectiveness["min_attack_queue"]) * 10
        reward -= penalty
        penalties.append(penalty)
        print(f"Penalty for high attack queue length: {penalty}")

    if attack_metrics["P_reject"] > effectiveness["max_reject"]:
        penalty = (attack_metrics["P_reject"] - effectiveness["max_reject"]) * 50
        reward -= penalty
        penalties.append(penalty)
        print(f"Penalty for high attack rejection probability: {penalty}")

    # Benign Queue Penalties
    if benign_metrics["Queue_Length"] > effectiveness["max_benign_queue"]:
        penalty = (benign_metrics["Queue_Length"] - effectiveness["max_benign_queue"]) * 5
        reward -= penalty
        penalties.append(penalty)
        print(f"Penalty for high benign queue length: {penalty}")

    if benign_metrics["P_reject"] > effectiveness["max_reject"]:
        penalty = (benign_metrics["P_reject"] - effectiveness["max_reject"]) * 50
        reward -= penalty
        penalties.append(penalty)
        print(f"Penalty for high benign rejection probability: {penalty}")

    if benign_metrics["W"] > 0:
        penalty = benign_metrics["W"] * 5
        reward -= penalty
        penalties.append(penalty)
        print(f"Penalty for high benign waiting time: {penalty}")

    # Rewards for Improvements
    positive_reward = 0
    positive_reward += max(0, (effectiveness["min_attack_queue"] - attack_metrics["Queue_Length"]) * 10)
    positive_reward += max(0, (1 - benign_metrics["P_reject"]) * 50)
    reward += positive_reward

    # Subtract action cost
    action_cost_penalty = action_costs.get(strategy, 0)
    reward -= action_cost_penalty
    penalties.append(action_cost_penalty)
    print(f"Action cost for {strategy}: {action_cost_penalty}")

    # Scale down the reward
    total_reward = reward / 100
    print(f"Total Reward for {strategy}: {total_reward}")

    # Log to CSV
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    with open('rewards_log.csv', mode='a', newline='') as csv_file:
        fieldnames = ['timestamp', 'strategy', 'reward', 'penalties', 'total_reward']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writerow({
            'timestamp': timestamp,
            'strategy': strategy,
            'reward': positive_reward / 100,
            'penalties': sum(penalties) / 100,
            'total_reward': total_reward
        })

    return total_reward

# Select mitigation strategy
def select_mitigation_strategy():
    global current_strategy
    exploration_probability = 0.19  # 19% chance to explore

    if random.random() < exploration_probability:
        # Explore: Select a random strategy
        current_strategy = random.choice(["RateLimiting", "TrafficShaping", "IPBlocking", "DynamicBandwidth"])
        print(f"Exploration triggered: Selected {current_strategy}")
    else:
        # Exploit: Select the strategy with the highest average reward
        with rewards_lock, counts_lock:
            # Compute average rewards
            average_rewards = {}
            for strategy in rewards.keys():
                avg_reward = rewards[strategy] / strategy_counts[strategy]
                average_rewards[strategy] = avg_reward

            current_strategy = max(average_rewards, key=average_rewards.get)
            print(f"Exploitation triggered: Selected {current_strategy}")

    # Increment the strategy count
    with counts_lock:
        strategy_counts[current_strategy] += 1

    return current_strategy

# Apply mitigation strategy
def apply_mitigation(strategy):
    global attack_queue, benign_queue, detected_ip
    log_event(f"Applying mitigation strategy: {strategy}")

    try:
        if strategy == "RateLimiting":
            # Limit the rate at which packets are processed from the attack queue
            limit_rate = 5  # Process 5 packets per interval
            items_processed = 0
            for _ in range(limit_rate):
                try:
                    attack_queue.get_nowait()
                    items_processed += 1
                except:
                    # Queue is empty
                    break
            log_event(f"Rate Limiting applied: Processed {items_processed} attack packets.")
        elif strategy == "TrafficShaping":
            # Enable traffic shaping
            enable_traffic_shaping()
            log_event("Traffic Shaping applied: Network policies adjusted.")
        elif strategy == "IPBlocking":
            # Block the IP using Windows Firewall
            if detected_ip:
                block_ip_windows_firewall(detected_ip)
            # Also add to ip_ban_list to block at application level
            if detected_ip not in ip_ban_list:
                ip_ban_list.append(detected_ip)
            log_event(f"IP Blocking applied: Blocked IP {detected_ip}")
        elif strategy == "DynamicBandwidth":
            # Adjust bandwidth allocation
            dynamic_bandwidth_allocation()
            log_event("Dynamic Bandwidth Allocation applied: Bandwidth adjusted.")
    except Exception as e:
        print(f"Exception in apply_mitigation: {e}")
        log_event(f"Exception in apply_mitigation: {e}")

# Transition states
def transition_state():
    global current_state
    probabilities = state_transition_matrix[current_state]
    next_state = random.choices(list(probabilities.keys()), weights=probabilities.values(), k=1)[0]
    if next_state != current_state:
        current_state = next_state
        send_telegram_message(f"State changed to {current_state}: {state_messages[current_state]}")
        if current_state == "Mitigation":
            # Apply mitigation strategy
            strategy = select_mitigation_strategy()
            apply_mitigation(strategy)

# Reward worker
def reward_worker():
    print("Reward worker thread started.")
    buffer_size = 10  # Example: queue capacity
    strategy_service_rates = {
        "RateLimiting": 10,
        "TrafficShaping": 12,
        "IPBlocking": 15,
        "DynamicBandwidth": 8
    }

    try:
        while True:
            benign_queue_size = benign_queue.qsize()
            attack_queue_size = attack_queue.qsize()
            print(f"benign_queue size: {benign_queue_size}, attack_queue size: {attack_queue_size}")

            if benign_queue.empty() and attack_queue.empty():
                print("No traffic detected. Skipping reward calculation.")
                time.sleep(5)
                continue

            # Calculate arrival rates
            current_time = time.time()

            if benign_arrival_times and current_time != benign_arrival_times[0]:
                benign_arrival_rate = len(benign_arrival_times) / (current_time - benign_arrival_times[0])
            else:
                benign_arrival_rate = 0

            if attack_arrival_times and current_time != attack_arrival_times[0]:
                attack_arrival_rate = len(attack_arrival_times) / (current_time - attack_arrival_times[0])
            else:
                attack_arrival_rate = 0

            # Dynamic service rate based on current strategy
            service_rate = strategy_service_rates.get(current_strategy, 10)

            # Compute metrics for both queues
            benign_metrics = compute_mm1b_metrics(benign_queue, benign_arrival_rate, service_rate, buffer_size)
            attack_metrics = compute_mm1b_metrics(attack_queue, attack_arrival_rate, service_rate, buffer_size)

            # Select a strategy and apply it
            strategy = select_mitigation_strategy()
            apply_mitigation(strategy)

            # Compute rewards and update
            reward = compute_reward(benign_metrics, attack_metrics, strategy)
            with rewards_lock:
                rewards[strategy] += reward
            log_event(f"Strategy: {strategy}, Reward: {reward:.2f}")

            time.sleep(10)  # Process rewards every 10 seconds
    except Exception as e:
        print(f"Exception in reward_worker: {e}")
        log_event(f"Exception in reward_worker: {e}")

# Predict traffic
@app.route('/predict', methods=['POST'])
def predict():
    global detected_ip, packet_counter
    # Record the start time
    start_time = time.time()

    input_data = request.json
    detected_ip = input_data.get("src", "unknown")
    input_df = pd.DataFrame([input_data])

    try:
        encoded_data = encoder.transform(input_df[['switch', 'src', 'dst', 'Protocol']])
        scaled_data = scaler.transform(input_df.drop(['switch', 'src', 'dst', 'Protocol'], axis=1))
        processed_data = pd.concat([pd.DataFrame(encoded_data), pd.DataFrame(scaled_data)], axis=1)
    except Exception as e:
        log_event(f"Error during data preprocessing: {e}")
        return jsonify({"error": "Data preprocessing failed."}), 500

    # Prediction using models
    try:
        processed_data_tensor = torch.tensor(processed_data.values, dtype=torch.float32)
        with torch.no_grad():
            deep_output = deep_model(processed_data_tensor)
            deep_prediction = (deep_output > 0.5).float().item()

        svm_prediction = svm_model.predict(processed_data)
    except Exception as e:
        log_event(f"Error during model prediction: {e}")
        return jsonify({"error": "Model prediction failed."}), 500

    result = "DDoS Attack" if deep_prediction == 1 or svm_prediction[0] == 1 else "Benign"

    # Update packet counters and queues
    current_time = time.time()
    if result == "DDoS Attack":
        packet_counter["malicious"] += 1
        attack_queue.put(input_data)
        attack_arrival_times.append(current_time)
        print(f"Added to attack_queue. Queue size now: {attack_queue.qsize()}")
    else:
        packet_counter["benign"] += 1
        benign_queue.put(input_data)
        benign_arrival_times.append(current_time)
        print(f"Added to benign_queue. Queue size now: {benign_queue.qsize()}")

    log_event(f"Prediction: {result}, Detected IP: {detected_ip}, Data: {input_data}")

    # Transition states
    transition_state()

    # Record the end time
    end_time = time.time()

    # Calculate the response time
    response_time = end_time - start_time
    log_event(f"Response Time: {response_time:.4f} seconds")

    # Return the response along with the response time
    return jsonify({
        'prediction': result,
        'state': current_state,
        'rewards': rewards,
        'response_time': f"{response_time:.4f} seconds"
    })

# Dashboard
@app.route('/dashboard', methods=['GET'])
def dashboard():
    monitor_traffic()
    return render_template('dashboard.html',
                           current_state=current_state,
                           current_strategy=current_strategy,
                           rewards=rewards,
                           traffic_stats=traffic_stats,
                           benign_queue_length=benign_queue.qsize(),
                           attack_queue_length=attack_queue.qsize())

# Start and stop simulation (if applicable)
@app.route('/start_simulation', methods=['POST'])
def start_simulation():
    global simulation_active
    simulation_active = True
    log_event("Traffic simulation started.")
    return jsonify({"status": "Simulation started."})

@app.route('/stop_simulation', methods=['POST'])
def stop_simulation():
    global simulation_active
    simulation_active = False
    log_event("Traffic simulation stopped.")
    return jsonify({"status": "Simulation stopped."})

# Start the reward_worker thread inside the main block
if __name__ == "__main__":
    # Start reward worker thread
    reward_thread = threading.Thread(target=reward_worker, daemon=True)
    reward_thread.start()
    app.run(debug=True, use_reloader=False)
