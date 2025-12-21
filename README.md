# Security-in-Computing-and-IT A2
## Assignment 2: Individual Programming Project - Smart Home Security Monitor (SHSM) 
## Student Name: Phyu Phyu Shinn Thant (Zyra)
## Student ID: S4022136
## Course: Security in Computing & IT (RMIT Vietnam)

### Project Overview
This repository contains the source code and threat modeling artifacts used for Assignment 2: Smart Home Security Monitor (SHSM). The project implements a Defense-in-Depth (DiD) security solution for a simulated smart home IoT environment. It focuses on vulnerable IoT assets such as home routers and smart cameras/baby monitors and applies STRIDE threat modeling, deception-based honeypots, cryptographic file integrity monitoring with self-healing, and machine learning–based attack classification.

### Repository Contents
main.py: Main script coordinating all security layers.

modules/honeypot.py: Telnet honeypot implementing the deception layer.

modules/integrity.py: File integrity monitoring and self-healing module using SHA-256 hashing.

modules/ml.py: Machine learning–based monitoring and analysis module.

ThreatDragonModels/IoT Security Threat Model: OWASP Threat Dragon STRIDE model files (JSON and diagrams).

### Installation
Kali Linux or Windows with Python version 3.x.

Install dependencies:

pip install pandas scikit-learn

### Usage
Run the system to initialize all security layers and begin monitoring:

**python3 main.py**

The script launches the honeypot, continuously monitors file integrity, and classifies captured attacks in real time.
