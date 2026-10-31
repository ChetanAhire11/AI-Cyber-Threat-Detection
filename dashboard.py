from pathlib import Path
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import streamlit as st
import json
import os
import subprocess
import sys


# ============================================================
# Configuration
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "saved_model" / "cyber_model.pkl"
FEATURE_PATH = BASE_DIR / "saved_model" / "features.pkl"
CSV_PATH = BASE_DIR / "live_flows.csv"
WORKER_PATH = BASE_DIR / "live_monitor.py"
RUNTIME_DIR = BASE_DIR / "runtime"
STOP_FLAG = RUNTIME_DIR / "stop_capture.flag"
STATUS_FILE = RUNTIME_DIR / "capture_status.json"
WORKER_LOG = RUNTIME_DIR / "live_monitor.log"
ALERT_HISTORY_FILE = RUNTIME_DIR / "alert_history.csv"
TRAINING_DATASET_PATH = BASE_DIR / "dataset" / "Friday-WorkingHours-Morning.pcap_ISCX.csv"
RUNTIME_DIR.mkdir(exist_ok=True)

st.set_page_config(
    page_title="Cyber Threat Detection | Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# Styling
# ============================================================
st.markdown(
    """
    <style>
    :root {
        --bg: #0b1220;
        --panel: #111c2f;
        --panel-2: #15243a;
        --border: rgba(148, 163, 184, 0.18);
        --muted: #91a4bd;
        --text: #e8eef7;
        --blue: #60a5fa;
        --green: #34d399;
        --red: #fb7185;
        --amber: #fbbf24;
    }

    .stApp {
        background:
            radial-gradient(circle at 15% 0%, rgba(37, 99, 235, 0.15), transparent 28%),
            radial-gradient(circle at 95% 8%, rgba(16, 185, 129, 0.08), transparent 25%),
            var(--bg);
        color: var(--text);
    }

    [data-testid="stHeader"] { background: rgba(11, 18, 32, 0.75); }
    [data-testid="stSidebar"] {
        background: #0e192b;
        border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] * { color: var(--text); }

    .block-container {
        padding-top: 1.7rem;
        padding-bottom: 2.5rem;
        max-width: 1500px;
    }

    h1, h2, h3 { color: var(--text) !important; }
    p, label, .stCaption { color: var(--muted); }

    .hero {
        padding: 1.45rem 1.6rem;
        border: 1px solid rgba(96, 165, 250, 0.23);
        border-radius: 20px;
        background: linear-gradient(115deg, rgba(30, 64, 110, 0.78), rgba(17, 28, 47, 0.94) 58%, rgba(15, 45, 52, 0.82));
        box-shadow: 0 16px 38px rgba(0, 0, 0, 0.18);
        margin-bottom: 1.2rem;
    }
    .hero-eyebrow {
        color: #93c5fd;
        text-transform: uppercase;
        letter-spacing: 0.14em;
        font-size: 0.72rem;
        font-weight: 800;
        margin-bottom: 0.4rem;
    }
    .hero-title {
        color: #f8fafc;
        font-size: clamp(1.55rem, 3vw, 2.3rem);
        font-weight: 800;
        line-height: 1.15;
        margin: 0;
    }
    .hero-subtitle {
        color: #bdcce0;
        margin-top: 0.55rem;
        font-size: 0.95rem;
    }
    .status-pill {
        display: inline-block;
        padding: 0.38rem 0.7rem;
        border-radius: 999px;
        border: 1px solid rgba(52, 211, 153, 0.35);
        background: rgba(16, 185, 129, 0.11);
        color: #6ee7b7;
        font-size: 0.76rem;
        font-weight: 700;
        white-space: nowrap;
    }
    .section-kicker {
        color: #93c5fd;
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        margin: 0.55rem 0 0.25rem 0;
    }
    .section-heading {
        color: #e8eef7;
        font-size: 1.2rem;
        font-weight: 750;
        margin: 0 0 0.85rem 0;
    }
    .metric-card {
        background: linear-gradient(145deg, rgba(21, 36, 58, 0.98), rgba(15, 27, 45, 0.98));
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1.1rem;
        min-height: 112px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.13);
    }
    .metric-label {
        color: #9fb1c8;
        font-size: 0.78rem;
        font-weight: 650;
        margin-bottom: 0.45rem;
    }
    .metric-value {
        color: #f8fafc;
        font-size: 1.85rem;
        line-height: 1.05;
        font-weight: 800;
    }
    .metric-note {
        color: #8296b0;
        font-size: 0.72rem;
        margin-top: 0.45rem;
    }
    .panel {
        background: rgba(17, 28, 47, 0.83);
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 1rem 1.15rem;
    }
    .small-muted { color: #91a4bd; font-size: 0.82rem; }
    .alert-safe {
        border: 1px solid rgba(52, 211, 153, 0.28);
        background: rgba(16, 185, 129, 0.09);
        color: #a7f3d0;
        border-radius: 12px;
        padding: 0.8rem 1rem;
        margin: 0.65rem 0 1rem 0;
    }
    .alert-bot {
        border: 1px solid rgba(251, 113, 133, 0.35);
        background: rgba(244, 63, 94, 0.10);
        color: #fecdd3;
        border-radius: 12px;
        padding: 0.8rem 1rem;
        margin: 0.65rem 0 1rem 0;
    }
    .footer-note {
        border-top: 1px solid var(--border);
        margin-top: 1.8rem;
        padding-top: 0.9rem;
        color: #8093aa;
        font-size: 0.75rem;
    }

    div[data-testid="stMetric"] {
        background: rgba(21, 36, 58, 0.88);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 0.8rem 0.95rem;
    }
    div[data-testid="stMetricLabel"] { color: #9fb1c8; }
    div[data-testid="stMetricValue"] { color: #f8fafc; }

    .stButton > button, .stDownloadButton > button {
        border-radius: 10px;
        border: 1px solid rgba(96, 165, 250, 0.35);
        background: rgba(37, 99, 235, 0.17);
        color: #dbeafe;
        font-weight: 700;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #60a5fa;
        color: #ffffff;
        background: rgba(37, 99, 235, 0.28);
    }
    div[data-baseweb="select"] > div, div[data-baseweb="input"] > div {
        background: #142239;
        border-color: var(--border);
    }
    [data-testid="stDataFrame"] {
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# Model and feature helpers
# ============================================================
@st.cache_resource

def load_model(model_path: str):
    return joblib.load(model_path)


@st.cache_data

def load_model_features(feature_path: str):
    return joblib.load(feature_path)


@st.cache_data(show_spinner=False)
def load_shap_background(dataset_path: str, model_features: tuple):
    """Build a small SHAP background sample from the original training split."""
    from sklearn.model_selection import train_test_split

    training = pd.read_csv(dataset_path, low_memory=False)
    training.columns = training.columns.str.strip()
    training.replace([np.inf, -np.inf], np.nan, inplace=True)
    training.dropna(inplace=True)
    training.drop_duplicates(inplace=True)

    if "Label" not in training.columns:
        raise ValueError("Training dataset does not contain the Label column.")

    X = training.drop("Label", axis=1)
    y = training["Label"].astype(str).str.strip().map({"BENIGN": 0, "Bot": 1})
    keep = y.notna()
    X = X.loc[keep]
    y = y.loc[keep].astype(int)

    X_train, _, _, _ = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    missing = [feature for feature in model_features if feature not in X_train.columns]
    if missing:
        raise ValueError(f"Training dataset is missing model features: {missing}")

    return X_train[list(model_features)].sample(
        n=min(30, len(X_train)), random_state=42
    ).copy()


def read_capture_status():
    if not STATUS_FILE.exists():
        return {"state": "stopped", "message": "Capture has not been started."}
    try:
        return json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"state": "unknown", "message": "Could not read capture status."}


@st.cache_resource
def capture_process_state():
    return {"process": None}


RENAME_MAP = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

TIME_FEATURES = [
    "Flow Duration",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def build_predictions(raw: pd.DataFrame, model, model_features):
    required_metadata = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    missing_metadata = [c for c in required_metadata if c not in raw.columns]
    if missing_metadata:
        raise ValueError(f"Live CSV is missing required flow columns: {missing_metadata}")

    features = raw.rename(columns=RENAME_MAP).copy()

    # The training CSV contains two identical Fwd Header Length columns.
    if "Fwd Header Length" in features.columns and "Fwd Header Length.1" not in features.columns:
        features["Fwd Header Length.1"] = features["Fwd Header Length"]

    available_time = [c for c in TIME_FEATURES if c in features.columns]
    features[available_time] = features[available_time] * 1_000_000

    missing = [c for c in model_features if c not in features.columns]
    if missing:
        raise ValueError(f"Missing model features: {missing}")

    X = features[model_features].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    valid_mask = ~X.isna().any(axis=1)

    output = raw[required_metadata].copy()
    output["protocol_name"] = output["protocol"].map({6: "TCP", 17: "UDP"}).fillna("Other")
    output["prediction"] = "Invalid features"
    output["bot_probability"] = np.nan

    if valid_mask.any():
        valid_X = X.loc[valid_mask]
        predicted = model.predict(valid_X)
        probability_matrix = model.predict_proba(valid_X)
        classes = list(model.classes_)
        if 1 not in classes:
            raise ValueError("Loaded model does not contain Bot class label 1.")
        bot_index = classes.index(1)
        bot_probability = probability_matrix[:, bot_index] * 100

        output.loc[valid_mask, "prediction"] = [
            "Bot" if value == 1 else "Normal" for value in predicted
        ]
        output.loc[valid_mask, "bot_probability"] = bot_probability

    return output, int(valid_mask.sum()), int((~valid_mask).sum()), X


def update_alert_history(raw: pd.DataFrame, predictions: pd.DataFrame):
    """Persist newly Bot-flagged flows once, without duplicating on reruns."""
    if ALERT_HISTORY_FILE.exists() and ALERT_HISTORY_FILE.stat().st_size > 0:
        try:
            history = pd.read_csv(ALERT_HISTORY_FILE)
        except (OSError, pd.errors.EmptyDataError):
            history = pd.DataFrame()
    else:
        history = pd.DataFrame()

    bot_mask = predictions["prediction"].eq("Bot")
    if not bot_mask.any():
        return history, 0

    bot_raw = raw.loc[bot_mask].copy()
    bot_results = predictions.loc[bot_mask]
    # A deterministic row fingerprint prevents the same cumulative CSV row
    # from generating a new alert on every Streamlit rerun.
    event_ids = pd.util.hash_pandas_object(
        bot_raw.astype(str), index=False
    ).astype("uint64").astype(str)

    detected_at = datetime.now().astimezone().isoformat(timespec="seconds")
    new_alerts = pd.DataFrame({
        "event_id": event_ids.to_numpy(),
        "detected_at": detected_at,
        "flow_timestamp": (
            bot_raw["timestamp"].astype(str).to_numpy()
            if "timestamp" in bot_raw.columns
            else [""] * len(bot_raw)
        ),
        "src_ip": bot_raw["src_ip"].astype(str).to_numpy(),
        "dst_ip": bot_raw["dst_ip"].astype(str).to_numpy(),
        "src_port": bot_raw["src_port"].to_numpy(),
        "dst_port": bot_raw["dst_port"].to_numpy(),
        "protocol": bot_results["protocol_name"].astype(str).to_numpy(),
        "bot_probability_pct": bot_results["bot_probability"].to_numpy(),
        "prediction": "Bot",
        "review_status": "Unreviewed",
    })

    known_ids = set(history["event_id"].astype(str)) if "event_id" in history.columns else set()
    fresh_alerts = new_alerts[~new_alerts["event_id"].isin(known_ids)].copy()
    if not fresh_alerts.empty:
        history = pd.concat([history, fresh_alerts], ignore_index=True)
        history = history.drop_duplicates(subset=["event_id"], keep="first")
        history = history.tail(5000)
        temp_file = ALERT_HISTORY_FILE.with_suffix(".tmp.csv")
        history.to_csv(temp_file, index=False)
        os.replace(temp_file, ALERT_HISTORY_FILE)

    return history, len(fresh_alerts)


# ============================================================
# Sidebar
# ============================================================
with st.sidebar:
    st.markdown("## 🛡️ CyberGuard")
    st.caption("Network threat monitoring")
    st.divider()

    capture_status = read_capture_status()
    process_state = capture_process_state()
    worker_process = process_state.get("process")
    worker_alive = worker_process is not None and worker_process.poll() is None
    worker_reported_running = capture_status.get("state") == "running"
    capture_running = worker_alive or worker_reported_running

    st.markdown("### Live capture controls")
    start_col, stop_col = st.columns(2)
    with start_col:
        start_clicked = st.button("▶ Start", use_container_width=True, disabled=capture_running)
    with stop_col:
        stop_clicked = st.button("■ Stop", use_container_width=True, disabled=not capture_running)

    if start_clicked:
        if not WORKER_PATH.exists():
            st.error("live_monitor.py was not found beside dashboard.py.")
        else:
            RUNTIME_DIR.mkdir(exist_ok=True)
            STOP_FLAG.unlink(missing_ok=True)
            # Start a fresh monitoring session rather than mixing old and new flows.
            CSV_PATH.unlink(missing_ok=True)
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                with WORKER_LOG.open("a", encoding="utf-8") as log_file:
                    process_state["process"] = subprocess.Popen(
                        [sys.executable, str(WORKER_PATH)],
                        cwd=str(BASE_DIR),
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        creationflags=creation_flags,
                    )
                st.success("Capture worker started. First flow results will appear after the first capture window is processed.")
                st.rerun()
            except OSError as exc:
                st.error(f"Could not start capture worker: {exc}")

    if stop_clicked:
        RUNTIME_DIR.mkdir(exist_ok=True)
        STOP_FLAG.touch()
        st.info("Stop requested. The current capture window and flow extraction will finish first.")
        st.rerun()

    capture_status = read_capture_status()
    current_state = capture_status.get("state", "stopped")
    if current_state == "running" or worker_alive:
        st.success("● CAPTURE RUNNING")
    elif current_state == "error":
        st.error("● CAPTURE ERROR")
    elif current_state == "stopping":
        st.warning("● STOPPING")
    else:
        st.caption("● CAPTURE STOPPED")
    st.caption(str(capture_status.get("message", "")))
    if capture_status.get("last_batch_at"):
        st.caption(f"Last processed batch: {capture_status['last_batch_at']}")

    # Auto-refresh while capture runs so new flow batches and Bot alerts appear.
    if current_state == "running" or worker_alive:
        try:
            from streamlit_autorefresh import st_autorefresh
            st_autorefresh(interval=5000, key="cyberguard_live_refresh")
        except ImportError:
            st.info("Install streamlit-autorefresh for automatic dashboard updates.")

    st.divider()
    if st.button("↻ Refresh dashboard", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown("### Data source")
    st.code(str(CSV_PATH), language="text")

    st.markdown("### Model")
    st.write("**Algorithm:** HistGradientBoosting")
    st.write("**Classes:** Normal / Bot")
    st.write("**Input:** 78 features")

    st.divider()
    st.caption("Start runs repeated 10-second capture windows, CICFlowMeter extraction and CSV updates. Predictions refresh as new batches arrive.")


# ============================================================
# Load files and data
# ============================================================
if not MODEL_PATH.exists() or not FEATURE_PATH.exists():
    st.error("Model files not found. Check the saved_model folder.")
    st.stop()

if not CSV_PATH.exists():
    st.markdown(
        '<div class="hero"><div class="hero-eyebrow">Network security console</div>'
        '<div class="hero-title">No traffic data available</div>'
        '<div class="hero-subtitle">Run packet capture and CICFlowMeter to create live_flows.csv, then refresh this dashboard.</div></div>',
        unsafe_allow_html=True,
    )
    st.stop()

try:
    model = load_model(str(MODEL_PATH))
    model_features = load_model_features(str(FEATURE_PATH))
    raw_data = pd.read_csv(CSV_PATH)
except pd.errors.EmptyDataError:
    st.warning("live_flows.csv is empty. Capture traffic and generate flows first.")
    st.stop()
except Exception as exc:
    st.error(f"Could not load dashboard data: {exc}")
    st.stop()

if raw_data.empty:
    st.warning("No network flows found in live_flows.csv.")
    st.stop()

try:
    results, valid_count, invalid_count, model_input = build_predictions(raw_data, model, model_features)
    alert_history, new_alert_count = update_alert_history(raw_data, results)
except Exception as exc:
    st.error(f"Could not prepare model predictions or alert history: {exc}")
    st.stop()

if new_alert_count > 0:
    st.toast(f"{new_alert_count} new flow(s) flagged as Bot by the model.", icon="🚨")

# Summary numbers
flow_count = len(results)
normal_count = int((results["prediction"] == "Normal").sum())
bot_count = int((results["prediction"] == "Bot").sum())
bot_rate = (bot_count / flow_count * 100) if flow_count else 0.0
max_probability = results["bot_probability"].max()
file_updated = datetime.fromtimestamp(CSV_PATH.stat().st_mtime).strftime("%d %b %Y, %I:%M:%S %p")


# ============================================================
# Header
# ============================================================
header_left, header_right = st.columns([5, 1.4], vertical_alignment="center")
with header_left:
    st.markdown(
        """
        <div class="hero">
            <div class="hero-eyebrow">AI · Network intelligence · Threat monitoring</div>
            <div class="hero-title">Cyber Threat Detection Center</div>
            <div class="hero-subtitle">Monitor network flows, inspect model predictions and review suspicious activity.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with header_right:
    capture_status = (
        "CAPTURE RUNNING"
        if read_capture_status().get("state") == "running"
        else "DATA LOADED"
    )
    st.markdown(
        '<div style="text-align:right; padding: 0.5rem 0.2rem;">'
        f'<span class="status-pill">● {capture_status}</span>'
        f'<div class="small-muted" style="margin-top:0.75rem;">Updated<br><b>{file_updated}</b></div>'
        '</div>',
        unsafe_allow_html=True,
    )

if bot_count > 0:
    st.markdown(
        f'<div class="alert-bot"><b>⚠ Bot-labelled flows in current results:</b> {bot_count}. Review the flow table and validate before taking action.</div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="alert-safe"><b>✓ No flows classified as Bot</b> in this CSV. This is a model result, not proof that the network is attack-free.</div>',
        unsafe_allow_html=True,
    )


# ============================================================
# KPI cards
# ============================================================
st.markdown('<div class="section-kicker">At a glance</div><div class="section-heading">Traffic overview</div>', unsafe_allow_html=True)

k1, k2, k3, k4, k5 = st.columns(5)
metrics = [
    (k1, "TOTAL FLOWS", f"{flow_count:,}", "Flows in current CSV"),
    (k2, "NORMAL", f"{normal_count:,}", "Classified as Normal"),
    (k3, "BOT", f"{bot_count:,}", "Classified as Bot"),
    (k4, "BOT SHARE", f"{bot_rate:.2f}%", "Of all current flows"),
    (k5, "INVALID", f"{invalid_count:,}", "Rows not sent to model"),
]
for col, label, value, note in metrics:
    with col:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div><div class="metric-note">{note}</div></div>',
            unsafe_allow_html=True,
        )


# ============================================================
# Tabs
# ============================================================
tab_overview, tab_flows, tab_alerts, tab_explain, tab_quality, tab_about = st.tabs(
    ["📊 Overview", "🔎 Flow explorer", "🚨 Alert history", "🧠 Explain prediction", "🧪 Data quality", "ℹ️ About"]
)

with tab_overview:
    left, right = st.columns([1.1, 1])

    with left:
        st.markdown('<div class="section-kicker">Classification</div><div class="section-heading">Prediction distribution</div>', unsafe_allow_html=True)
        prediction_counts = (
            results["prediction"].value_counts()
            .reindex(["Normal", "Bot", "Invalid features"], fill_value=0)
            .rename_axis("Class")
            .to_frame("Flows")
        )
        st.bar_chart(prediction_counts, y="Flows", use_container_width=True)

    with right:
        st.markdown('<div class="section-kicker">Protocols</div><div class="section-heading">Traffic by protocol</div>', unsafe_allow_html=True)
        protocol_counts = (
            results["protocol_name"].value_counts()
            .rename_axis("Protocol")
            .to_frame("Flows")
        )
        st.bar_chart(protocol_counts, y="Flows", use_container_width=True)

    st.markdown('<div class="section-kicker">Threat alerts</div><div class="section-heading">Model-flagged Bot flows</div>', unsafe_allow_html=True)
    current_bot_flows = results[results["prediction"] == "Bot"].copy()
    if current_bot_flows.empty:
        st.success("No flows are currently classified as Bot by the model.")
    else:
        st.error(
            f"🚨 {len(current_bot_flows)} flow(s) flagged as Bot. "
            "This is a model alert, not a confirmed incident. Verify the traffic before taking action."
        )
        bot_display = current_bot_flows.rename(
            columns={
                "src_ip": "Source IP",
                "dst_ip": "Destination IP",
                "src_port": "Source Port",
                "dst_port": "Destination Port",
                "protocol_name": "Protocol",
                "bot_probability": "Bot Probability (%)",
            }
        )
        st.dataframe(
            bot_display[["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Bot Probability (%)"]],
            use_container_width=True,
            hide_index=True,
        )

    st.markdown('<div class="section-kicker">Probability</div><div class="section-heading">Bot probability spread</div>', unsafe_allow_html=True)
    probability_values = results["bot_probability"].dropna()
    if probability_values.empty:
        st.info("No valid probability values are available.")
    else:
        probability_frame = probability_values.reset_index(drop=True).to_frame("Bot probability (%)")
        probability_frame.index.name = "Flow"
        st.line_chart(probability_frame, use_container_width=True)
        st.caption(
            f"Highest Bot probability: {max_probability:.6f}% · "
            f"Valid model inputs: {valid_count}"
        )

    st.markdown('<div class="section-kicker">Endpoints</div><div class="section-heading">Top destination IPs</div>', unsafe_allow_html=True)
    destination_counts = (
        results["dst_ip"].astype(str).value_counts().head(10)
        .rename_axis("Destination IP").to_frame("Flows")
    )
    st.bar_chart(destination_counts, y="Flows", use_container_width=True)

with tab_flows:
    st.markdown('<div class="section-kicker">Investigate</div><div class="section-heading">Network flow explorer</div>', unsafe_allow_html=True)
    filter1, filter2, filter3 = st.columns([1, 1, 2])

    with filter1:
        prediction_options = ["All", "Normal", "Bot", "Invalid features"]
        selected_prediction = st.selectbox("Prediction", prediction_options)
    with filter2:
        protocol_options = ["All"] + sorted(results["protocol_name"].dropna().unique().tolist())
        selected_protocol = st.selectbox("Protocol", protocol_options)
    with filter3:
        search_text = st.text_input("Search IP address", placeholder="Type a source or destination IP")

    filtered = results.copy()
    if selected_prediction != "All":
        filtered = filtered[filtered["prediction"] == selected_prediction]
    if selected_protocol != "All":
        filtered = filtered[filtered["protocol_name"] == selected_protocol]
    if search_text.strip():
        search_mask = (
            filtered["src_ip"].astype(str).str.contains(search_text.strip(), case=False, na=False)
            | filtered["dst_ip"].astype(str).str.contains(search_text.strip(), case=False, na=False)
        )
        filtered = filtered[search_mask]

    display = filtered.rename(
        columns={
            "src_ip": "Source IP",
            "dst_ip": "Destination IP",
            "src_port": "Source Port",
            "dst_port": "Destination Port",
            "protocol_name": "Protocol",
            "prediction": "Prediction",
            "bot_probability": "Bot Probability (%)",
        }
    )
    display = display[[
        "Source IP", "Destination IP", "Source Port", "Destination Port",
        "Protocol", "Prediction", "Bot Probability (%)"
    ]]

    st.caption(f"Showing {len(display):,} of {flow_count:,} flows")
    st.dataframe(
        display,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Bot Probability (%)": st.column_config.NumberColumn(
                "Bot Probability (%)", format="%.6f%%"
            ),
            "Source Port": st.column_config.NumberColumn("Source Port", format="%d"),
            "Destination Port": st.column_config.NumberColumn("Destination Port", format="%d"),
        },
    )

    export_data = display.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇ Download filtered flows",
        data=export_data,
        file_name="filtered_cyber_threat_flows.csv",
        mime="text/csv",
    )

with tab_alerts:
    st.markdown('<div class="section-kicker">Incident review</div><div class="section-heading">Threat alert history</div>', unsafe_allow_html=True)
    st.caption("Each unique flow flagged as Bot is recorded once. Alerts are model outputs and need human verification.")
    if alert_history.empty:
        st.success("No Bot alerts have been recorded yet.")
    else:
        total_alerts = len(alert_history)
        unreviewed_alerts = int((alert_history.get("review_status", pd.Series(dtype=str)) == "Unreviewed").sum())
        a1, a2 = st.columns(2)
        a1.metric("Recorded alerts", total_alerts)
        a2.metric("Unreviewed alerts", unreviewed_alerts)
        alert_view = alert_history.drop(columns=["event_id"], errors="ignore").sort_values(
            "detected_at", ascending=False
        )
        st.dataframe(alert_view, use_container_width=True, hide_index=True)
        alert_export = alert_view.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇ Download alert history",
            data=alert_export,
            file_name="cyberguard_alert_history.csv",
            mime="text/csv",
        )

with tab_explain:
    st.markdown('<div class="section-kicker">Explainable AI</div><div class="section-heading">Why did the model make this prediction?</div>', unsafe_allow_html=True)
    st.caption(
        "Select a flow to explain the model's Bot probability. SHAP values describe the model's "
        "behaviour; they are not proof that a flow is malicious."
    )

    valid_indices = [idx for idx in model_input.index if model_input.loc[idx].notna().all()]
    if not valid_indices:
        st.info("There are no valid flows available to explain.")
    elif not TRAINING_DATASET_PATH.exists():
        st.error(
            "Training CSV not found. Expected: "
            f"{TRAINING_DATASET_PATH}. The dataset is needed to build the SHAP background sample."
        )
    else:
        def _flow_label(idx):
            row = results.loc[idx]
            return (
                f"Row {idx} · {row['src_ip']} → {row['dst_ip']}:{row['dst_port']} · "
                f"{row['prediction']} · Bot {row['bot_probability']:.6f}%"
            )

        selected_index = st.selectbox(
            "Choose a network flow",
            options=valid_indices,
            format_func=_flow_label,
            key="shap_flow_index",
        )
        selected_result = results.loc[selected_index]
        exp_col1, exp_col2, exp_col3 = st.columns(3)
        exp_col1.metric("Prediction", str(selected_result["prediction"]))
        exp_col2.metric("Bot probability", f"{selected_result['bot_probability']:.6f}%")
        exp_col3.metric("Protocol", str(selected_result["protocol_name"]))

        if st.button("🧠 Explain selected flow", type="primary", key="run_shap_explanation"):
            try:
                import shap
                import matplotlib.pyplot as plt

                with st.spinner("Calculating SHAP values for this flow..."):
                    background = load_shap_background(
                        str(TRAINING_DATASET_PATH), tuple(model_features)
                    )
                    explainer = shap.Explainer(
                        model.predict_proba,
                        background,
                        algorithm="permutation",
                    )
                    selected_row = model_input.loc[[selected_index], list(model_features)]
                    shap_values = explainer(
                        selected_row,
                        max_evals=2 * len(model_features) + 1,
                    )

                bot_class_index = list(model.classes_).index(1)
                st.markdown("#### SHAP waterfall — contribution to Bot probability")
                shap.plots.waterfall(
                    shap_values[0, :, bot_class_index],
                    max_display=15,
                    show=False,
                )
                st.pyplot(plt.gcf(), use_container_width=True)
                plt.close("all")

                contribution_values = np.asarray(
                    shap_values.values[0, :, bot_class_index], dtype=float
                )
                contribution_table = pd.DataFrame({
                    "Feature": list(model_features),
                    "SHAP value (Bot class)": contribution_values,
                    "Live feature value": selected_row.iloc[0].to_numpy(),
                })
                contribution_table["Absolute impact"] = contribution_table[
                    "SHAP value (Bot class)"
                ].abs()
                contribution_table = contribution_table.sort_values(
                    "Absolute impact", ascending=False
                ).head(15)

                st.markdown("#### Top 15 influential features")
                st.dataframe(
                    contribution_table.drop(columns=["Absolute impact"]),
                    use_container_width=True,
                    hide_index=True,
                )
                st.caption(
                    "Positive SHAP values push the model towards Bot; negative values push it towards Normal. "
                    "Interpret this only as an explanation of the model output, conditional on the live feature mapping."
                )
            except ImportError:
                st.error("SHAP or Matplotlib is not installed in the dashboard environment. Run: pip install shap matplotlib")
            except Exception as exc:
                st.error(f"Could not generate SHAP explanation: {type(exc).__name__}: {exc}")

with tab_quality:
    st.markdown('<div class="section-kicker">Input validation</div><div class="section-heading">Feature and data quality</div>', unsafe_allow_html=True)
    q1, q2, q3 = st.columns(3)
    q1.metric("Model features expected", len(model_features))
    q2.metric("Valid rows", valid_count)
    q3.metric("Rows with invalid values", invalid_count)

    st.markdown("#### Feature mapping status")
    prepared = raw_data.rename(columns=RENAME_MAP).copy()
    if "Fwd Header Length" in prepared.columns and "Fwd Header Length.1" not in prepared.columns:
        prepared["Fwd Header Length.1"] = prepared["Fwd Header Length"]
    missing_features = [f for f in model_features if f not in prepared.columns]
    matched_features = len(model_features) - len(missing_features)
    st.progress(matched_features / len(model_features) if model_features else 0.0)
    st.write(f"**Mapped feature names:** {matched_features} / {len(model_features)}")
    if missing_features:
        st.error("Missing features: " + ", ".join(missing_features))
    else:
        st.success("All required feature names are present.")

    st.markdown("#### Missing / infinite values")
    prepared_features = prepared.reindex(columns=model_features)
    prepared_features = prepared_features.apply(pd.to_numeric, errors="coerce")
    missing_cells = int(prepared_features.isna().sum().sum())
    infinite_cells = int(np.isinf(prepared_features.to_numpy(dtype=float, na_value=np.nan)).sum())
    dq1, dq2 = st.columns(2)
    dq1.metric("Missing / non-numeric cells", f"{missing_cells:,}")
    dq2.metric("Infinite cells", f"{infinite_cells:,}")

    st.warning(
        "Column names and time units are mapped in this prototype, but matching names do not prove "
        "that every CICFlowMeter feature is calculated identically to the CIC-IDS2017 training pipeline. "
        "Validate feature definitions before relying on detections."
    )

with tab_about:
    st.markdown('<div class="section-kicker">System details</div><div class="section-heading">About this prototype</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="panel">
            <b>Model</b><br>HistGradientBoostingClassifier<br><br>
            <b>Training dataset</b><br>CIC-IDS2017 Friday Morning CSV<br><br>
            <b>Supported labels</b><br>BENIGN (Normal) and Bot<br><br>
            <b>Flow source</b><br>CICFlowMeter CSV generated from a packet capture<br><br>
            <b>Dashboard mode</b><br>Start / Stop controls run repeated 10-second capture windows and update predictions as new flow batches arrive
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.warning(
        "This is an experimental decision-support dashboard. Capture is processed in short 10-second "
        "windows, so alerts are near-real-time rather than packet-by-packet instant. It does not block "
        "IP addresses or prevent attacks. A Normal result does not guarantee that traffic is safe."
    )


# ============================================================
# Footer
# ============================================================
st.markdown(
    '<div class="footer-note">Cyber Threat Detection Prototype · '
    'Predictions are model outputs and require independent validation before operational use.</div>',
    unsafe_allow_html=True,
)
