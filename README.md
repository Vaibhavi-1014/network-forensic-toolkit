# network-forensic-toolkit
# Network Forensics and Session Reconstruction Toolkit

## Project Overview

The Network Forensics and Session Reconstruction Toolkit is a Python-based web application designed to analyze network packet capture files (`.pcap` and `.pcapng`). It helps users understand network communication, examine packet details, identify suspicious traffic patterns, and export analysis results.

The project provides a simple and user-friendly dashboard for learning and demonstrating basic network forensics.

## Objectives

- Analyze network packet capture files.
- Extract source and destination IP addresses, protocols, and port numbers.
- Group TCP and UDP packets into basic communication sessions.
- Identify potentially suspicious traffic patterns using simple detection rules.
- Calculate the SHA-256 hash of an uploaded capture file for integrity verification.
- Export analysis results for further investigation.

## Features

- Upload PCAP and PCAPNG files.
- View packet counts and IP address statistics.
- Examine packet details and communication endpoints.
- View basic TCP and UDP session summaries.
- Detect indicators such as repeated TCP SYN packets and connections to multiple destination ports.
- Calculate a SHA-256 file hash.
- Download analysis results in CSV or text format.
- Generate sample network traffic for testing.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Streamlit | Web dashboard and user interface |
| Scapy | Reading and analyzing packet capture files |
| Pandas | Organizing and displaying analysis results |
| Hashlib | Calculating SHA-256 file hashes |
| PCAP/PCAPNG | Network traffic capture formats |

## Project Architecture

1. **Input:** The user uploads a PCAP or PCAPNG file.
2. **File Integrity:** The application calculates the file's SHA-256 hash.
3. **Packet Analysis:** Scapy extracts available packet and network information.
4. **Session Grouping:** TCP and UDP packets are grouped using endpoint and port information.
5. **Traffic Indicators:** Simple rules identify patterns that may require further investigation.
6. **Dashboard:** Streamlit displays packet statistics, session summaries, and indicators.
7. **Export:** The user downloads selected analysis results.

## Installation and Setup

### Prerequisites

- Python 3.10 or a compatible Python version.
- pip package manager.
- GitHub account (for hosting the source code).
- A modern web browser.

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/network-forensics-toolkit.git
cd network-forensics-toolkit
```

Replace `YOUR-USERNAME` with your GitHub username.

### Step 2: Install Dependencies

On Windows, run:

```powershell
python -m pip install -r requirements.txt
```

If you are using the existing virtual environment in `C:\PS108`, you can run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Step 3: Run the Application

```powershell
python -m streamlit run app.py
```

If using the existing virtual environment:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL displayed in the terminal, usually:

`http://localhost:8501`

## Generate Sample Traffic

If `generate_sample.py` is included in the repository, run:

```powershell
python generate_sample.py
```

This generates synthetic packet capture data for testing. Upload the generated PCAP file through the dashboard to explore the application's features.

## How to Use

1. Start the application.
2. Upload a supported PCAP or PCAPNG file.
3. Review the packet statistics and network addresses.
4. Explore packet information and basic session summaries.
5. Review any suspicious traffic indicators.
6. Export the available results for documentation or further analysis.

## Limitations

- The current implementation performs basic packet analysis and session grouping; it does not provide complete TCP stream reconstruction.
- It does not decrypt HTTPS/TLS traffic.
- Detection rules identify suspicious patterns, not confirmed attacks.
- The SHA-256 hash helps verify file integrity when compared with a trusted reference hash; it does not prove that the capture is authentic.
- Results depend on the quality and contents of the uploaded capture file.

## Future Enhancements

- TCP stream reconstruction and conversation following.
- Advanced protocol analysis.
- Improved detection rules and anomaly scoring.
- Interactive session timelines and traffic visualizations.
- More detailed forensic reporting.
- Additional export formats and analysis options.

## Ethical Use

This toolkit is intended for educational purposes, authorized network investigations, and analysis of packet captures that you have permission to examine. Do not upload captures containing confidential or personal information to a public hosting service.

## Conclusion

The Network Forensics and Session Reconstruction Toolkit demonstrates how Python and open-source libraries can support basic network traffic analysis. It provides a foundation for learning packet inspection, network session analysis, file integrity checking, and suspicious traffic investigation.

## Author

**Project:** Network Forensics and Session Reconstruction Toolkit  
**Project Code:** PS Code 108  
**Department:** Cyber Security  
**University:** Sanjivani University
