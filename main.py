
import pandas as pd
import numpy as np

# ==========================================
# 1. Load Dataset
# ==========================================

file_path = "dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv"

data = pd.read_csv(file_path)

data.columns = data.columns.str.strip()

print("Dataset Loaded Successfully!")
print("Original Dataset Shape:", data.shape)


# ==========================================
# 2. Data Cleaning
# ==========================================

# Replace Infinity values with NaN
data.replace([np.inf, -np.inf], np.nan, inplace=True)

# Remove missing values
data.dropna(inplace=True)

# Remove duplicate rows
data.drop_duplicates(inplace=True)

print("\nData Cleaning Completed!")

print("Remaining Rows:", data.shape[0])
print("Remaining Columns:", data.shape[1])

print("Missing Values:", data.isnull().sum().sum())

print(
    "Infinity Values:",
    np.isinf(data.select_dtypes(include=np.number)).sum().sum()
)

print("Duplicate Rows:", data.duplicated().sum())


# ==========================================
# 3. Separate Features and Target
# ==========================================

X = data.drop("Label", axis=1)

y = data["Label"].map({
    "BENIGN": 0,
    "Bot": 1
})

print("\nFeatures Shape:", X.shape)
print("Target Shape:", y.shape)

print("\nTarget Distribution:")
print(y.value_counts().rename({
    0: "Normal",
    1: "Bot"
}))


# ==========================================
# 4. Split Training and Testing Data
# ==========================================

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining Data:", X_train.shape)
print("Testing Data:", X_test.shape)

print("\nTraining Labels:")
print(y_train.value_counts())

print("\nTesting Labels:")
print(y_test.value_counts())


# ==========================================
# 5. Check Feature Data Types
# ==========================================

print("\nFeature Data Types:")
print(X.dtypes.value_counts())

print("\nNon-Numeric Columns:")
print(X.select_dtypes(exclude=["number"]).columns)


# ==========================================
# 6. Train Decision Tree Model
# ==========================================
from sklearn.ensemble import HistGradientBoostingClassifier

model = HistGradientBoostingClassifier(
    max_iter=100,
    learning_rate=0.1,
    max_leaf_nodes=31,
    l2_regularization=1.0,
    random_state=42
)

model.fit(X_train, y_train)

print("\nHistGradientBoosting Model Training Completed!")

# ==========================================
# 7. Make Predictions
# ==========================================

y_pred = model.predict(X_test)

print("\nPrediction Completed!")
print("Total Predictions:", len(y_pred))

print("\nFirst 10 Predictions:")
print(y_pred[:10])


# ==========================================
# 8. Evaluate Model
# ==========================================

from sklearn.metrics import confusion_matrix, classification_report

cm = confusion_matrix(y_test, y_pred)

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Bot"],
        zero_division=0
    )
)


# ==========================================
# 9. Prediction Distribution
# ==========================================

print("\nPrediction Distribution:")

prediction_counts = pd.Series(y_pred).value_counts().reindex(
    [0, 1],
    fill_value=0
)

prediction_counts.index = ["Normal", "Bot"]

print(prediction_counts)

# ==========================================
# Feature Importance
# ==========================================

from sklearn.inspection import permutation_importance

print("\nCalculating Feature Importance...")

# Use a smaller sample to reduce memory usage
X_sample = X_test.sample(
    n=min(5000, len(X_test)),
    random_state=42
)

y_sample = y_test.loc[X_sample.index]

result = permutation_importance(
    model,
    X_sample,
    y_sample,
    n_repeats=2,
    random_state=42,
    scoring="f1",
    n_jobs=1
)

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": result.importances_mean
})

feature_importance = feature_importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 10 Important Features:")
print(feature_importance.head(10).to_string(index=False))

# ==========================================
# 11. SHAP Explainability
# ==========================================

import shap

print("\nStarting SHAP Explanation...")

# Select background data
background = X_train.sample(30, random_state=42)

# Select one actual Bot record
bot_index = y_test[y_test == 1].index[0]
bot_record = X_test.loc[[bot_index]]

# Create SHAP Explainer
explainer = shap.Explainer(
    model.predict_proba,
    background,
    algorithm="permutation"
)

# Calculate SHAP values
shap_values = explainer(
    bot_record,
    max_evals=2 * X.shape[1] + 1
)

# Show actual and predicted labels
prediction = model.predict(bot_record)[0]

print("Actual Label:", y_test.loc[bot_index])
print("Predicted Label:", prediction)

# Explain Bot prediction
shap.plots.waterfall(
    shap_values[0, :, 1]
)
import joblib
import os

os.makedirs("saved_model", exist_ok=True)

joblib.dump(model, "saved_model/cyber_model.pkl")
joblib.dump(list(X.columns), "saved_model/features.pkl")

print("\nModel Saved Successfully!")
print("Feature List Saved Successfully!")