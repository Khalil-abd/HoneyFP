import pandas as pd
import matplotlib.pyplot as plt
import config

def run_extraction():
    fp = pd.read_csv(f"{config.DATA_DIR}/false_positives_labeled.csv", low_memory=False)
    tp = pd.read_csv(f"{config.DATA_DIR}/beth_predictions.csv", low_memory=False)
    
    # Filter for TP
    tp = tp[tp['classification'] == 'TP']
    
    FEATURES = ['processId', 'userId', 'eventId', 'returnValue']
    
    # 1. Compare FP vs TP feature distributions
    fig, axes = plt.subplots(1, len(FEATURES), figsize=(16, 4))
    for i, feat in enumerate(FEATURES):
        axes[i].hist(fp[feat].dropna(), bins=30, alpha=0.6, label='FP', color='red')
        axes[i].hist(tp[feat].dropna(), bins=30, alpha=0.6, label='TP', color='green')
        axes[i].set_title(feat)
        axes[i].legend()
    plt.tight_layout()
    plt.savefig(f"{config.OUTPUT_DIR}/fp_patterns.png")
    
    # 2. Top recurring FP event types
    top_events = fp['eventId'].value_counts().head(10)
    print("Top FP event types:")
    print(top_events)
    
    # 3. Export pattern summary for honeypot config
    pattern_summary = fp.groupby(['fp_label', 'eventId']).agg(
        count=('eventId', 'size'),
        avg_score=('anomaly_score', 'mean'),
        avg_return=('returnValue', 'mean')
    ).reset_index().sort_values('count', ascending=False)
    
    pattern_summary.to_csv(f"{config.DATA_DIR}/fp_pattern_summary.csv", index=False)
    print(pattern_summary.head(10))

if __name__ == "__main__":
    run_extraction()