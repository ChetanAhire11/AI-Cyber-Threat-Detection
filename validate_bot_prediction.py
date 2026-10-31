import pandas as pd
import joblib

from sklearn.model_selection import train_test_split

# Load dataset
data = pd.read_csv(
    "dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv"
)

data.columns = data.columns.str.strip()
data["Label"] = data["Label"].astype(str).str.strip()

# Clean dataset
data.replace([float("inf"), float("-inf")], pd.NA, inplace=True)
data.dropna(inplace=True)
data.drop_duplicates(inplace=True)

# Separate features and labels
X = data.drop("Label", axis=1)

y = data["Label"].map({
    "BENIGN": 0,
    "Bot": 1
})

# Recreate the original test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Load saved model
model = joblib.load("saved_model/cyber_model.pkl")
features = joblib.load("saved_model/features.pkl")

# Select actual Bot records from test data
bot_samples = X_test.loc[y_test == 1].sample(
    n=10,
    random_state=42
)

# Predict
predictions = model.predict(bot_samples[features])
probabilities = model.predict_proba(bot_samples[features])

bot_index = list(model.classes_).index(1)

# Display results
results = pd.DataFrame({
    "Actual": y_test.loc[bot_samples.index].map({
        0: "Normal",
        1: "Bot"
    }).values,
    "Predicted": [
        "Bot" if p == 1 else "Normal"
        for p in predictions
    ],
    "Bot Probability (%)": (
        probabilities[:, bot_index] * 100
    ).round(4)
})

print("\nKnown Bot Detection Test:")
print(results.to_string(index=False))