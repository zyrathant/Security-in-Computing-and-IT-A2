import socket
import threading
import json
import os
from datetime import datetime

# --- CONFIGURATION ---
HOST = '0.0.0.0'
PORT = 23
LOG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'honeypot_logs.json'))
WELCOME_MESSAGE = b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1f\r\nBusyBox v1.27.2 built-in shell (ash)\r\n(none) login: "

def log_attacker_data(ip, port, data_type, content):
	"""
	Logs the attacker's activity to a JSON file and prints a confirmation message.
	Params: 
		ip = The IP address of the attacker
		port = The port that is being used
		data_type = Data type
		content = Content being transmitted
	"""
	log_entry = {
		"timestamp": datetime.now().isoformat(),
		"src_ip": ip,
		"src_port": port,
		"data_type": data_type,
		"content": content,
		"classification": "PENDING"
	}
	with open(LOG_FILE, 'a') as f:
		# Appends the JSON entry followed by a newline
		f.write(json.dumps(log_entry) + '\n')
	print(f"[+] LOGGED: {ip}:{port} - {data_type}: {content}")

def handle_connection(connection, address):
	ip, port = address
	print(f"[+] Connection from {ip}:{port}")

	try:
		connection.settimeout(30)
		connection.sendall(WELCOME_MESSAGE)
        
		# Capture Username
		username = connection.recv(1024).strip().decode('utf-8', errors='ignore')
		log_attacker_data(ip, port, "username_attempt", username)

		# Capture Password
		connection.sendall(b"Password: ")
		password = connection.recv(1024).strip().decode('utf-8', errors='ignore')
		log_attacker_data(ip, port, "password_attempt", password)

		# Simulate Shell
		connection.sendall(b"\r\n\r\n# ") # Standard root prompt

		while True:
			data = connection.recv(1024)
			if not data:
				break
			
			command = data.strip().decode('utf-8', errors='ignore')
			log_attacker_data(ip, port, "command_attempt", command)

			if command.lower() == 'exit':
				break
			
			response = b"\r\n# "
			connection.sendall(response)

	except (BrokenPipeError, ConnectionResetError):
		# Handle cases of Attacker disconnecting.
		print(f"[-] Client {ip} disconnected abruptly.")
	except Exception as e:
		print(f"[-] Error handling connection from {ip}: {e}")
	finally:
		connection.close()

def start_honeypot():
	"""
	Starts the main socket listener.
	"""
	# Create socket
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Set socket options
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	try:
		# Bind socket to IP and PORT
		server_socket.bind((HOST, PORT))
		server_socket.listen(5)
		print(f"[+] SHSM Honeypot listening on {HOST}:{PORT}")

		while True:
			conn, addr = server_socket.accept()
			# Handle each connection in a new thread
			client_handler = threading.Thread(target=handle_connection, args=(conn, addr))
			client_handler.start()

	except PermissionError:
		print(f"[!] ERROR: Port {PORT} requires sudo.")
	except Exception as e:
		print(f"[!!] FATAL ERROR: {e}")
	finally:
		server_socket.close()

