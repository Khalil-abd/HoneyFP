import pandas as pd
import matplotlib.pyplot as plt
import config

def classify(row):
    pred_anomaly = row['pred_label'] == -1
    truly_evil = row['evil'] == 1
    if pred_anomaly and truly_evil: return 'TP'
    if pred_anomaly and not truly_evil: return 'FP'
    if not pred_anomaly and truly_evil: return 'FN'
    return 'TN'

def run_identification():
    df = pd.read_csv(f"{config.DATA_DIR}/beth_predictions.csv")
    df['classification'] = df.apply(classify, axis=1)
    
    print(df['classification'].value_counts())
    
    # Extract only FPs
    fp_df = df[df['classification'] == 'FP'].copy()
    print(f"\nFPs found: {len(fp_df)}")
    print(f"FP rate: {len(fp_df)/len(df)*100:.1f}%")
    
    # Save the updated main file AND the isolated FP file
    df.to_csv(f"{config.DATA_DIR}/beth_predictions.csv", index=False)
    fp_df.to_csv(f"{config.DATA_DIR}/false_positives.csv", index=False)
    
    # Visualization
    counts = df['classification'].value_counts()
    counts.plot(kind='bar', color=['green','red','orange','gray'])
    plt.title("Classification results")
    plt.tight_layout()
    plt.savefig(f"{config.OUTPUT_DIR}/classification_counts.png")

if __name__ == "__main__":
    run_identification()