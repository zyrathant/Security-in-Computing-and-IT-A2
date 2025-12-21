import hashlib
import os
import json
from datetime import datetime
import shutil

# --- CONFIGURATION ---
TARGET_FILE = 'simulated_router_firmware.bin'
HASH_DB_FILE = 'known_hashes.json'
BACKUP_FILE = 'backup_firmware.bin.bak'

def calculate_file_hash(file_path, hash_algorithm='sha256'):
	"""
	Calculates the hash of a file.
	Params: 
		file_path = Path of the file to hash
		hash_algorithm = Type of hash algorithm to calculate the file hash
	Return: 
		hasher.hexdigest()
	"""
	hasher = hashlib.new(hash_algorithm)
	try:
		with open(file_path, 'rb') as file:
			while chunk := file.read(65536):
				hasher.update(chunk)
		return hasher.hexdigest()
	except FileNotFoundError:
		return None
	except Exception as e:
		print(f"[!!] Error calculating hash for {file_path}: {e}")
		return None

def store_known_hash(file_path, current_hash):
	"""
	Stores the current hash as the known-good baseline.
	Params: 
		file_path = The file path
		current_hash = The current hash file to store
	Return: 
		Stores the known hash of the file and a printed message to indicate success
	"""
	data = {}
	if os.path.exists(HASH_DB_FILE):
		with open(HASH_DB_FILE, 'r') as f:
			data = json.load(f)

	data[file_path] = {
		"hash": current_hash,
		"algorithm": "sha256",
		"timestamp": datetime.now().isoformat()
	}

	with open(HASH_DB_FILE, 'w') as f:
		json.dump(data, f, indent=4)
		print(f"[+] New baseline hash set for {file_path}")

def check_integrity():
	"""
	Compares the current file hash against the stored baseline and restores if tampered.
	Params: 
		None
	Return: 
		Message printed to indicate success or failure of integrity check.
	"""
	if not os.path.exists(BACKUP_FILE) and os.path.exists(TARGET_FILE):
		shutil.copy(TARGET_FILE, BACKUP_FILE)
		print(f"Backup file created: {BACKUP_FILE}")
	current_hash = calculate_file_hash(TARGET_FILE)
		
	if not current_hash:
		print(f"[!!] ERROR: Target file '{TARGET_FILE}' not found.")
		return

	known_hash_data = {}
	if os.path.exists(HASH_DB_FILE):
		with open(HASH_DB_FILE, 'r') as f:
			known_hash_data = json.load(f)

	if TARGET_FILE not in known_hash_data:
		print(f"[!] WARNING: No known baseline hash for {TARGET_FILE}. Setting current hash as baseline.")
		store_known_hash(TARGET_FILE, current_hash)
		return

	known_hash = known_hash_data[TARGET_FILE]['hash']

	if current_hash == known_hash:
		print(f"[+] INTEGRITY CHECK SUCCESS: {TARGET_FILE} hash matches baseline.)")
	else:
		print(f"[-] INTEGRITY CHECK FAILED: {TARGET_FILE} has been tampered.")
		print(f"	Expected Hash: {known_hash}")
		print(f"	Found Hash:   {current_hash}")
		print("[!!] ALERT: Potential configuration compromise.")
		
		print("Automating restore procedure.")
		try:
			shutil.copy(BACKUP_FILE, TARGET_FILE)
			print(f"[+] SUCCESS: {TARGET_FILE} has been restored from secure backup.")
			
			# Re-verify
			new_hash = calculate_file_hash(TARGET_FILE)
			if new_hash == known_hash:
				print("[+] VERIFICATION: SYSTEM integrity restored.")
		except Exception as e:
			print(f"[-] RESTORATION FAILED: {e}")
