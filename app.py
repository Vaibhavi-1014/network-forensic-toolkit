import hashlib
import io
from pathlib import Path

import pandas as pd
import streamlit as st
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, Raw

st.set_page_config(page_title="Network Forensics Toolkit", page_icon="🕵️", layout="wide")
st.title("🕵️ Network Forensics and Session Reconstruction Toolkit")
st.caption("PS Code 108 | Basic educational prototype for offline PCAP/PCAPNG analysis")

st.info(
    "Use only packet captures you are authorized to examine. This prototype analyzes saved captures; "
    "it does not capture traffic from the network or decrypt TLS/HTTPS."
)

uploaded = st.file_uploader("Upload a packet capture (.pcap or .pcapng)", type=["pcap", "pcapng"])

def sha256_bytes(data: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()

def packet_protocol(pkt):
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if DNS in pkt:
        return "DNS"
    return "Other"

def packet_ips(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return "Unknown", "Unknown"

def packet_ports(pkt):
    if TCP in pkt:
        return int(pkt[TCP].sport), int(pkt[TCP].dport)
    if UDP in pkt:
        return int(pkt[UDP].sport), int(pkt[UDP].dport)
    return None, None

def tcp_flags(pkt):
    if TCP in pkt:
        return str(pkt[TCP].flags)
    return ""

def payload_preview(pkt, max_chars=100):
    if Raw in pkt:
        raw = bytes(pkt[Raw].load)
        # Keep a short printable preview only; do not attempt to decrypt encrypted traffic.
        preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:max_chars])
        return preview
    return ""

def build_rows(packets):
    rows = []
    for i, pkt in enumerate(packets, start=1):
        src, dst = packet_ips(pkt)
        sport, dport = packet_ports(pkt)
        try:
            timestamp = pd.to_datetime(float(pkt.time), unit="s", utc=True).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            timestamp = "Unknown"
        rows.append({
            "Packet #": i,
            "Timestamp": timestamp,
            "Source IP": src,
            "Source Port": sport,
            "Destination IP": dst,
            "Destination Port": dport,
            "Protocol": packet_protocol(pkt),
            "Length (bytes)": len(pkt),
            "TCP Flags": tcp_flags(pkt),
            "Payload Preview": payload_preview(pkt),
        })
    return pd.DataFrame(rows)

def session_key(row):
    # Canonicalize endpoints so both directions of a TCP/UDP conversation group together.
    if pd.isna(row["Source Port"]) or pd.isna(row["Destination Port"]):
        return None
    left = (str(row["Source IP"]), int(row["Source Port"]))
    right = (str(row["Destination IP"]), int(row["Destination Port"]))
    endpoints = sorted([left, right])
    return f'{row["Protocol"]} | {endpoints[0][0]}:{endpoints[0][1]} ↔ {endpoints[1][0]}:{endpoints[1][1]}'

def build_sessions(df):
    network = df[df["Protocol"].isin(["TCP", "UDP"])].copy()
    if network.empty:
        return pd.DataFrame(columns=["Session", "Packets", "Total Bytes", "First Seen", "Last Seen"])
    network["Session"] = network.apply(session_key, axis=1)
    network = network[network["Session"].notna()]
    if network.empty:
        return pd.DataFrame(columns=["Session", "Packets", "Total Bytes", "First Seen", "Last Seen"])
    grouped = network.groupby("Session", dropna=False).agg(
        Packets=("Packet #", "count"),
        **{"Total Bytes": ("Length (bytes)", "sum")},
        **{"First Seen": ("Timestamp", "first")},
        **{"Last Seen": ("Timestamp", "last")},
    ).reset_index()
    return grouped.sort_values("Packets", ascending=False)

def detect_indicators(df):
    findings = []
    tcp = df[df["Protocol"] == "TCP"].copy()
    if not tcp.empty:
        # A SYN-only packet commonly has flag text 'S' in Scapy. This is a heuristic, not proof of an attack.
        syn_only = tcp[tcp["TCP Flags"].astype(str).str.contains("S", na=False) &
                       ~tcp["TCP Flags"].astype(str).str.contains("A", na=False)]
        for src, group in syn_only.groupby("Source IP"):
            if len(group) >= 5:
                findings.append({
                    "Severity": "Review",
                    "Indicator": "Repeated TCP SYN packets",
                    "Source IP": src,
                    "Count": int(len(group)),
                    "Explanation": "At least 5 SYN packets without ACK from this source were observed. Could be scanning, retries, or normal activity."
                })
    for src, group in df.groupby("Source IP"):
        unique_ports = group["Destination Port"].dropna().nunique()
        if unique_ports >= 10:
            findings.append({
                "Severity": "Review",
                "Indicator": "Many destination ports contacted",
                "Source IP": src,
                "Count": int(unique_ports),
                "Explanation": "This source contacted 10 or more destination ports. Investigate context before drawing conclusions."
            })
    return pd.DataFrame(findings, columns=["Severity", "Indicator", "Source IP", "Count", "Explanation"])

if uploaded:
    raw_file = uploaded.getvalue()
    st.subheader("Evidence file")
    col1, col2 = st.columns(2)
    col1.metric("File size", f"{len(raw_file):,} bytes")
    col2.metric("SHA-256", sha256_bytes(raw_file)[:16] + "…")
    st.caption("The full SHA-256 hash is shown below and can be recorded in your investigation notes.")
    st.code(sha256_bytes(raw_file))

    try:
        packets = rdpcap(io.BytesIO(raw_file))
        if len(packets) == 0:
            st.warning("This capture contains no packets.")
        else:
            df = build_rows(packets)
            sessions = build_sessions(df)
            findings = detect_indicators(df)

            st.subheader("Capture overview")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Packets", f"{len(df):,}")
            c2.metric("Unique source IPs", f"{df['Source IP'].nunique():,}")
            c3.metric("Unique destination IPs", f"{df['Destination IP'].nunique():,}")
            c4.metric("TCP/UDP sessions", f"{len(sessions):,}")

            tab1, tab2, tab3, tab4 = st.tabs(["Packet Explorer", "Sessions", "Indicators", "Export"])
            with tab1:
                st.subheader("Protocol distribution")
                counts = df["Protocol"].value_counts().rename_axis("Protocol").reset_index(name="Packets")
                st.bar_chart(counts.set_index("Protocol"))
                chosen_protocol = st.selectbox("Filter by protocol", ["All"] + sorted(df["Protocol"].unique().tolist()))
                view = df if chosen_protocol == "All" else df[df["Protocol"] == chosen_protocol]
                st.dataframe(view, use_container_width=True, hide_index=True)
            with tab2:
                st.subheader("Conversation/session summary")
                st.caption("TCP/UDP packets are grouped by protocol and endpoint pair. This is basic flow grouping, not full TCP reassembly.")
                st.dataframe(sessions, use_container_width=True, hide_index=True)
            with tab3:
                st.subheader("Heuristic indicators for review")
                st.caption("These rules are simple educational heuristics and may produce false positives.")
                if findings.empty:
                    st.success("No configured indicators were triggered in this capture.")
                else:
                    st.dataframe(findings, use_container_width=True, hide_index=True)
            with tab4:
                st.subheader("Download results")
                st.download_button("Download packet summary CSV", df.to_csv(index=False).encode("utf-8"),
                                   "packet_summary.csv", "text/csv")
                st.download_button("Download session summary CSV", sessions.to_csv(index=False).encode("utf-8"),
                                   "session_summary.csv", "text/csv")
                st.download_button("Download indicator report CSV", findings.to_csv(index=False).encode("utf-8"),
                                   "indicator_report.csv", "text/csv")
                report = (
                    "Network Forensics and Session Reconstruction Toolkit\n"
                    f"File name: {uploaded.name}\n"
                    f"Packet count: {len(df)}\n"
                    f"SHA-256: {sha256_bytes(raw_file)}\n"
                    f"Unique source IPs: {df['Source IP'].nunique()}\n"
                    f"Unique destination IPs: {df['Destination IP'].nunique()}\n"
                    f"TCP/UDP sessions: {len(sessions)}\n"
                    f"Indicators flagged: {len(findings)}\n"
                    "Note: Indicators are heuristic and require analyst validation.\n"
                )
                st.download_button("Download investigation summary TXT", report.encode("utf-8"),
                                   "investigation_summary.txt", "text/plain")
    except Exception as exc:
        st.error("Could not read this capture file. Check that it is a valid PCAP/PCAPNG file.")
        st.caption(f"Technical detail: {exc}")
else:
    st.markdown("### How to use")
    st.markdown("1. Upload a `.pcap` or `.pcapng` file.  \n2. Review packet details and protocol counts.  \n3. Inspect grouped TCP/UDP sessions.  \n4. Review heuristic indicators and export CSV reports.")
    st.markdown("To create a small demonstration capture, run `python generate_sample.py` from the project folder.")
