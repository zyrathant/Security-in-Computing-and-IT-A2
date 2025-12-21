import threading
import time
import os
import sys

# Import modules
from modules.honeypot import start_honeypot
from modules.integrity import check_integrity, TARGET_FILE, HASH_DB_FILE
from modules.ml import load_and_preprocess_logs, train_and_classify, LOG_FILE

# --- CONFIGURATION ---
# Sets how often the background threads wake up to perform checks
CHECK_INTERVAL = 10

def initialize_system():
	"""
	Sets up the environment, ensures log files exist, and establishes the baseline hash for the firmware integrity monitor.
	Returns:
		None
	"""
	print("\n[+] System Initialization")
	
	# Setup Firmware Simulation File
	if not os.path.exists(TARGET_FILE):
		print(f"[!] Baseline file missing. Generating secure default: {TARGET_FILE}")
		try:
			with open(TARGET_FILE, 'w') as f:
				f.write("SECURE_BOOT_CONFIG: v1.0.4\nSTATUS: VERIFIED")
		except Exception as e:
			print(f"[!] Error: critical failure creating target file: {e}")
			sys.exit(1)

	# Establish Integrity Baseline (Layer 2)
	print("Calculating initial firmware hashes for monitoring")
	check_integrity()
	
	# Prepare Honeypot Log Database
	if not os.path.exists(LOG_FILE):
		try:
			# Touch the file to ensure it exists for the ML module
			with open(LOG_FILE, 'w') as f:
				pass 
			print(f"[+] Initialized JSON log repository: {LOG_FILE}")
		except Exception as e:
			print(f"[!] Error: could not initialize log file: {e}")
			sys.exit(1)

	print("[+] System initialization successful. Baselines set.\n")


def run_integrity_monitor(interval):
	"""
	Background thread: Periodically verifies the hardware/firmware integrity.
	Params:
		interval = Time delay (seconds) between checks
	"""
	while True:
		# Separating logs for better readability in the terminal
		print("\n" + "="*40)
		print("[INTEGRITY MONITOR] Scanning for unauthorized tampering")
		check_integrity()
		time.sleep(interval)


def run_ml_analyzer(interval):
	"""
	Background thread: Analyzes honeypot logs and classifies threat actors.
	Params:
		interval = Time delay (seconds) between AI analysis cycles
	"""
	while True:
		# We wait for the interval first so the honeypot has time to collect data
		time.sleep(interval)
		print("\n" + "="*40)
		print("[ML ANALYZER] Running Layer 3 Threat Classification")
		try:
			train_and_classify()
		except Exception as e:
			print(f"[!] Error: analysis Cycle Failed: {e}")


if __name__ == "__main__":
	print("   SHSM IoT SECURITY PLATFORM - V1.0")
	print("==========================================")
	# Prepare the system environment
	initialize_system()

	# --- THREAD DEPLOYMENT ---
	# Layer 1: Passive Honeypot Defense
	honeypot_thread = threading.Thread(target=start_honeypot, daemon=True)
	
	# Layer 2: Active Integrity Monitoring
	integrity_thread = threading.Thread(target=run_integrity_monitor, args=(CHECK_INTERVAL,), daemon=True)
	
	# Layer 3: ML Analysis
	ml_thread = threading.Thread(target=run_ml_analyzer, args=(CHECK_INTERVAL,), daemon=True)

	# Launching modules
	honeypot_thread.start()
	integrity_thread.start()
	ml_thread.start()

	print("[+] Honeypot Service:   [ACTIVE]")
	print("[+] Integrity Monitor:  [ACTIVE]")
	print("[+] ML Analysis Layer:  [ACTIVE]")
	print("\n[READY] Monitoring for threats. Press CTRL+C to terminate.\n")

	# Keep the main process alive so daemon threads don't exit
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		print("\n[!] Shutdown signal received. Stopping IoT Security Platform.")
		sys.exit(0)
