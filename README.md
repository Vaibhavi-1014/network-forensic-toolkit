# Network Forensics and Session Reconstruction Toolkit
**PS Code 108 | Basic working prototype**

A local Streamlit application for offline analysis of PCAP/PCAPNG captures. It displays packet metadata, groups TCP/UDP traffic into basic sessions, flags a few simple indicators for review, calculates the capture file's SHA-256 hash, and exports CSV/TXT reports.

## Requirements
- Windows 10/11
- Python 3.10 or newer
- VS Code with the Python extension

## Installation in VS Code terminal
Open this folder in VS Code, then run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt terminal and run:
```bat
.venv\Scripts\activate.bat
```

## Generate a demo capture
```powershell
python generate_sample.py
```
This creates `samples/sample_traffic.pcap`, a synthetic capture with private lab IP addresses, a small HTTP-like exchange, a DNS query, and repeated SYN packets for testing the indicator logic.

## Run the app
```powershell
streamlit run app.py
```
A browser tab should open. If not, open the local URL printed in the terminal, usually `http://localhost:8501`.

## Demonstration
1. Upload `samples/sample_traffic.pcap`.
2. Show packet count, unique IP addresses, session count, and SHA-256 hash.
3. Open Packet Explorer and filter by TCP or UDP.
4. Open Sessions and explain endpoint-pair grouping.
5. Open Indicators and explain the repeated SYN finding.
6. Download the packet, session, and indicator CSV files.

## Limitations
- This is an educational prototype, not a commercial forensic suite.
- Session grouping is basic flow grouping; full TCP sequence-number reassembly is not implemented.
- HTTPS/TLS payloads are not decrypted.
- Heuristic findings can be false positives and must be validated by an analyst.
- The application analyzes uploaded captures; it does not perform live capture.
- Keep original evidence unchanged and analyze a copy. Record the hash and document evidence handling.
