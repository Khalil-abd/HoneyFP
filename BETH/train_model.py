import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import config

def run_training():
    # Ensure models directory exists
    os.makedirs("models", exist_ok=True)
    
    # Load the cleaned, encoded data from load_beth.py
    beth_df = pd.read_csv(f"{config.DATA_DIR}/beth_clean.csv")
    
    # Train only on normal samples (evil=0)
    normal = beth_df[beth_df['evil'] == 0]
    X_train = normal[config.FEATURES]
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Isolation forest
    model = IsolationForest(
        n_estimators=100,
        contamination=config.CONTAMINATION_RATE,
        random_state=42
    )
    model.fit(X_train_scaled)
    
    # Predict on FULL dataset
    X_all_scaled = scaler.transform(beth_df[config.FEATURES])
    beth_df['pred_label'] = model.predict(X_all_scaled)
    beth_df['anomaly_score'] = -model.score_samples(X_all_scaled)
    
    # Save models and predictions
    joblib.dump(model, "models/isolation_forest.pkl")
    joblib.dump(scaler, "models/scaler.pkl")
    beth_df.to_csv(f"{config.DATA_DIR}/beth_predictions.csv", index=False)
    
    print("Model saved. Predictions Saved.")

if __name__ == "__main__":
    run_training()