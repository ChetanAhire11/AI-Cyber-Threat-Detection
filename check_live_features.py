import pandas as pd
import joblib

data = pd.read_csv("live_flows.csv")
model_features = joblib.load("saved_model/features.pkl")

# CICFlowMeter column name -> Model column name
rename_map = {
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
    "idle_min": "Idle Min"
}

# Rename live CSV columns
data.rename(columns=rename_map, inplace=True)
# Dataset contains two identical Fwd Header Length columns
data["Fwd Header Length.1"] = data["Fwd Header Length"]

time_features = [
    "Flow Duration",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",

    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",

    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",

    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",

    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]

data[time_features] = data[time_features] * 1_000_000

matched = [
    feature for feature in model_features
    if feature in data.columns
]

missing = [
    feature for feature in model_features
    if feature not in data.columns
]

print("Model Feature Count:", len(model_features))
print("Matched Features:", len(matched))

print("\nMissing Features:")
for feature in missing:
    print(feature)

# Check duplicated training feature
train = pd.read_csv(
    "dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv",
    low_memory=False
)

train.columns = train.columns.str.strip()

if (
    "Fwd Header Length" in train.columns
    and "Fwd Header Length.1" in train.columns
):
    same = train["Fwd Header Length"].equals(
        train["Fwd Header Length.1"]
    )

    print("\nFwd Header Length columns identical:", same)
else:
    print("\nDuplicate Fwd Header Length columns not found.")

missing = [
    feature for feature in model_features
    if feature not in data.columns
]

print("Missing Features:", missing)

if not missing:
    X_live = data[model_features]
    print("Live Model Input Shape:", X_live.shape)
    print("All 78 Features Ready!")


import numpy as np

# Load trained ML model
model = joblib.load("saved_model/cyber_model.pkl")

if not missing:

    X_live = data[model_features].copy()

    # Ensure all values are numeric
    X_live = X_live.apply(pd.to_numeric, errors="coerce")

    # Handle infinite values
    X_live.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Validate input
    if X_live.isna().any().any():
        print("\nInvalid values found!")
        print(X_live.isna().sum()[lambda x: x > 0])

    else:
        # Predict
        predictions = model.predict(X_live)

        probabilities = model.predict_proba(X_live)

        bot_index = list(model.classes_).index(1)
        bot_probability = probabilities[:, bot_index]

        # Create result
        results = data[
            ["src_ip", "dst_ip", "src_port", "Destination Port", "protocol"]
        ].copy()

        results.rename(
            columns={"Destination Port": "dst_port"},
            inplace=True
        )

        results["Prediction"] = [
            "Bot" if p == 1 else "Normal"
            for p in predictions
        ]

        results["Bot Probability (%)"] = (
            bot_probability * 100
        ).round(6)

        print("\nLive Traffic Predictions:")
        print(results.to_string(index=False))