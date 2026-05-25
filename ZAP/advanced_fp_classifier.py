import json
import pandas as pd
from sklearn.ensemble import IsolationForest

def classify_zap_alerts(input_file="mock_zap_dataset.json", output_file="fp_alerts.json"):
    print(f"[*] Chargement des alertes depuis {input_file}...")
    
    with open(input_file, 'r') as f:
        data = json.load(f)
        
    df = pd.DataFrame(data)
    
    print("[*] Extraction des caractéristiques (Feature Engineering)...")
    
  
    endpoint_counts = df['endpoint'].value_counts().to_dict()
    df['endpoint_freq'] = df['endpoint'].map(endpoint_counts)
    
   
    features = ['risk_level', 'confidence_level', 'endpoint_freq']
    X = df[features]
    
   
    print("[*] Entraînement du modèle Isolation Forest...")
    

    
    model = IsolationForest(contamination=0.15, random_state=42)
    df['ml_label'] = model.fit_predict(X)
    
    
    df['classification'] = df['ml_label'].apply(lambda x: "False Positive" if x == 1 else "True Positive")
    
    
    fp_df = df[df['classification'] == "False Positive"]
    
    print(f"[+] Classification terminée !")
    print(f"    - Alertes totales : {len(df)}")
    print(f"    - Vraies Attaques ignorées (TP) : {len(df[df['classification'] == 'True Positive'])}")
    print(f"    - Faux Positifs ciblés pour le LLM (FP) : {len(fp_df)}")
    
    
    fp_df = fp_df.drop(columns=['ml_label', 'endpoint_freq'])
    fp_alerts = fp_df.to_dict(orient='records')
    
    with open(output_file, 'w') as f:
        json.dump(fp_alerts, f, indent=4)
        
    print(f"[+] Fichier prêt pour le module Strategy Generator : {output_file}")

if __name__ == "__main__":
    classify_zap_alerts()