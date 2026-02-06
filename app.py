import sys
import streamlit as st

if "detections" not in st.session_state:
    st.session_state["detections"] = []

import pandas as pd
import joblib, json
from glob import glob
from pathlib import Path
import threading
import time
from scapy.all import IP, TCP, send

def run_demo_attack():
    """
    This generates a SYN flood simulation that is visible in Wireshark.
    It does NOT require live sniffing – used only for demonstration.
    """
    target = "10.252.225.168"                  #"192.168.29.240"     <-- My Wi-Fi's IPv4
    print("Running SYN burst attack...")

    for i in range(300):
        try:
            pkt = IP(dst=target)/TCP(dport=80, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.002)
        except Exception as e:
            print("Error:", e)
            break

    print("Attack burst completed.")


BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))


MODEL_PATH = Path("models/rf_baseline.joblib")
FEAT_PATH = Path("models/feature_cols.json")

model_loaded = False

if MODEL_PATH.exists() and FEAT_PATH.exists():
    clf = joblib.load(MODEL_PATH)
    with open(FEAT_PATH) as f:
        feature_cols = json.load(f)
    model_loaded = True


chunks = sorted(glob("mini-ids/data/processed_parquet/*.parquet"))



st.set_page_config(
    page_title="Mini IDS — Dashboard",
    layout="wide",
    page_icon="🛡️"
)


st.markdown("""
<style>
.stApp { 
    background: linear-gradient(135deg, #020b13, #062b2b); 
    color: #00FFAA; 
}

.sidebar .sidebar-content {
    background: #04151f !important;
}

.stButton>button {
    background-color:#00c78c;
    color:black;
    font-weight:bold;
    border-radius:8px;
    border:2px solid #00FFAA;
}

.stButton>button:hover {
    background-color:#00ffaa;
    color:black;
}

h1,h2,h3,h4 {
    color:#00FFAA !important;
}

.dataframe {
    background:#071018;
    color:#00FFAA;
}

</style>
""", unsafe_allow_html=True)


st.title("Mini Intrusion Detection System")
st.caption("Hybrid ML + Rule-based IDS")
st.caption("Project By:- Rudraksh Bhatia")
st.caption("BCA - C")
st.caption("Roll No:- 63")

st.markdown("### Offline Detection + Realistic SYN Attack Simulation")


st.sidebar.header(" Control Panel")

# OFFLINE MODE
st.sidebar.subheader("Offline Detection (CICIDS 2017) Dataset")

if not chunks:
    st.sidebar.error("No processed Parquet files found!")
else:
    chunk_idx = st.sidebar.slider("Select Data Chunk", 0, len(chunks)-1, 0)
    if st.sidebar.button("Run Offline Detection"):
        df = pd.read_parquet(chunks[chunk_idx])
        if model_loaded:
            preds = clf.predict(df[feature_cols].fillna(0))
            alerts = df[preds == 1]
            st.session_state.detections = alerts.to_dict(orient='records')
            st.success("Offline Detection Completed! Below is the parquet dataset:-")
        else:
            st.warning("Model not loaded. Showing first 100 rows.")
            st.session_state.detections = df.head(100).to_dict(orient='records')


st.sidebar.subheader("Demo Attack Simulation")
if st.sidebar.button("Launch SYN Flood Simulation"):
    threading.Thread(target=run_demo_attack, daemon=True).start()
    st.warning("SYN attack simulation launched! Capture the Attack Simulation under **Adaptor for Loopback Traffic**")


if st.sidebar.button("Clear Detections"):
    st.session_state.detections = []


st.subheader("Detection Dashboard")

if st.session_state.detections:
    df_display = pd.DataFrame(st.session_state.detections)

    # Fix tuple → string
    if "flow_key" in df_display.columns:
        df_display["flow_key"] = df_display["flow_key"].astype(str)

    st.dataframe(df_display.head(200), height=400, use_container_width=True)

    if "destination_port" in df_display.columns:
        st.markdown("#### Top Targeted Ports")
        st.bar_chart(df_display["destination_port"].value_counts().head(10))

else:
    st.info("No detections yet. Run Offline Detection or launch Demo Attack.")


st.markdown("---")
st.subheader("System Log")

log_output = [
    f"Total Offline Alerts: {len(st.session_state.detections)}",
    "Demo Attack uses Wireshark for visualization.",
    "IDS detection logic via CICIDS dataset + ML model.",
]

st.code("\n".join(log_output), language="bash")
