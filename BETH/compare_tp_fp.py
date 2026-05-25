import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("data/beth_predictions.csv")
fp = df[df['classification'] == 'FP']
tp = df[df['classification'] == 'TP']

FEATURES = ['userId', 'eventId', 'returnValue', 'anomaly_score']

# Mean comparison table
comparison = pd.DataFrame({
    'FP_mean': fp[FEATURES].mean(),
    'TP_mean': tp[FEATURES].mean(),
})
comparison['difference'] = comparison['FP_mean'] - comparison['TP_mean']
print(comparison)
comparison.to_csv("outputs/tp_fp_comparison.csv")

# Anomaly score distribution: FP vs TP
plt.figure(figsize=(8, 4))
plt.hist(fp['anomaly_score'], bins=40, alpha=0.6, label='FP', color='red')
plt.hist(tp['anomaly_score'], bins=40, alpha=0.6, label='TP', color='green')
plt.xlabel('Anomaly score')
plt.legend()
plt.title('Anomaly score: FP vs TP')
plt.savefig("outputs/score_distribution.png")
print("Comparison saved.")