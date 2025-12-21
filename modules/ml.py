import pandas as pd
import json
import re
import os
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# --- CONFIGURATION ---
LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'honeypot_logs.json'))

TRAINING_DATA_LABELS = [
	{"attempts": 15, "has_busybox": 0, "label": "Credential Stuffing"},
	{"attempts": 3, "has_busybox": 1, "label": "Mirai Scan"},
	{"attempts": 200, "has_busybox": 0, "label": "DoS/Brute Force"},
	{"attempts": 1, "has_busybox": 0, "label": "Benign/Probe"},
	{"attempts": 12, "has_busybox": 0, "label": "Credential Stuffing"},
	{"attempts": 5, "has_busybox": 1, "label": "Mirai Scan"},
	{"attempts": 1, "has_busybox": 0, "label": "Benign/Probe"},
	{"attempts": 180, "has_busybox": 0, "label": "DoS/Brute Force"},
	{"attempts": 25, "has_busybox": 0, "label": "Credential Stuffing"},
	{"attempts": 2, "has_busybox": 1, "label": "Mirai Scan"},
	{"attempts": 1, "has_busybox": 0, "label": "Benign/Probe"},
]


def load_and_preprocess_logs(log_file):
	"""
	Loads JSON logs and extracts features for ML.
	Params:
		log_file = Path to the json log file
	Returns:
		df_real = DataFrame of activity extracted from logs
	"""
	ip_activity = {}
	
	if not os.path.exists(log_file):
		return pd.DataFrame()

	with open(log_file, 'r') as f:
		for line in f:
			try:
				entry = json.loads(line.strip())
				ip = entry.get('src_ip')
				if not ip: continue

				if ip not in ip_activity:
					ip_activity[ip] = {"attempts": 0, "has_busybox": 0}
				
				ip_activity[ip]["attempts"] += 1
				
				content = str(entry.get('content', '')).lower()
				if any(word in content for word in ['busybox', 'wget', 'tftp', 'chmod']):
					ip_activity[ip]["has_busybox"] = 1
			except:
				continue
				
	return pd.DataFrame([{"src_ip": ip, **data} for ip, data in ip_activity.items()])


def update_log_classifications(predictions_dict):
	"""
	Updates the PENDING status in the actual JSON file.
	Params:
		predictions_dict = Dictionary mapping IP to ML label
	Returns:
		None
	"""
	if not os.path.exists(LOG_FILE):
		return
	
	updated_logs = []
	try:
		with open(LOG_FILE, 'r') as f:
			for line in f:
				log = json.loads(line.strip())
				ip = log.get("src_ip")
				if ip in predictions_dict:
					log["classification"] = predictions_dict[ip]
				updated_logs.append(log)

		with open(LOG_FILE, 'w') as f:
			for log in updated_logs:
				f.write(json.dumps(log) + "\n")
		print("[+] honeypot_logs.json updated with real-time classifications.")
	except Exception as e:
		print(f"[-] Log update failed: {e}")


def train_and_classify():
	"""
	Trains a Decision Tree and generates a Classification Report for validation.
	Params:
		None
	Returns:
		None
	"""
	df_train = pd.DataFrame(TRAINING_DATA_LABELS)
	le = LabelEncoder()
	X = df_train[['attempts', 'has_busybox']]
	y = le.fit_transform(df_train['label'])

	try:
		clf = DecisionTreeClassifier(max_depth=4, random_state=42)
		clf.fit(X, y)

		df_real = load_and_preprocess_logs(LOG_FILE)
		
		if df_real is not None and not df_real.empty:
			X_real = df_real[['attempts', 'has_busybox']]
			predictions = le.inverse_transform(clf.predict(X_real))
			df_real['classification'] = predictions
			
			# Map IPs to classifications and update the JSON file
			ip_to_class = dict(zip(df_real['src_ip'], df_real['classification']))
			update_log_classifications(ip_to_class)
			
			print("\n--- [INFERENCE] Live Honeypot Threat Intelligence ---")
			print(df_real[['src_ip', 'attempts', 'has_busybox', 'classification']])
		else:
			print("\n[DEBUG] Inference skipped: No entries found in honeypot_logs.json")

	except Exception as e:
		print(f"[!] ML Error: {e}")
