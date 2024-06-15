# 🔍 Nmap-vulners: A Python Script TO Automate Vulnerability Scanning and Reporting using Nmap Vulners Script

## Overview

Nmap-vulners is a Python script helps to automates vulnerability scanning using Nmap's vulners script. This tool executes the scan, parses the results, and saves them into structured CSV files for easy analysis and reporting.

## Features

- **Automated Nmap Scan**: Runs Nmap with the vulners script enabled.
- **Results Parsing**: Extracts detailed vulnerability information from the scan results.
- **CSV Reporting**: Saves exploitable and non-exploitable vulnerabilities to separate CSV files.
- **Complete Output Storage**: Stores the full Nmap scan output in a CSV file.

## Installation

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/sivasakthi037/nmap-vulners.git
    cd nmap-vulners
    ```

2. **Install Dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. **Run the Script**:
    ```sh
    python nmap_vulners.py
    ```

2. **Enter the target IP address or hostname when prompted**.

## Files and Directories

- `nmap_vulners.py`: Main script to run the Nmap scan and process results.
- `requirements.txt`: Dependencies for the project.
- `README.md`: Project overview and instructions.

## Example

1. **Run the script**:
    ```sh
    python nmap_vulners.py
    ```

2. **Enter the target IP address or hostname**:
    ```
    Enter the target IP address or hostname: 192.168.1.1
    ```

3. **View the results in the generated CSV files**:
    - `Exploitable.csv`
    - `Non_Exploitable.csv`
    - `complete_results.csv`

## Dependencies

- `libnmap`: Library for parsing Nmap XML results.

---

🚀 Happy Scanning!
