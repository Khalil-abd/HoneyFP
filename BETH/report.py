import pandas as pd

df   = pd.read_csv("data/beth_predictions.csv")
fp   = pd.read_csv("data/false_positives_labeled.csv")
llm  = pd.read_csv("outputs/llm_analysis_results.csv")

total = len(df)
fp_count = len(fp)
fp_rate = fp_count / total * 100

print("=== False Positive Report ===")
print(f"Total events:       {total}")
print(f"False positives:    {fp_count} ({fp_rate:.1f}%)")
print(f"\nFP label breakdown:")
print(fp['fp_label'].value_counts())
print(f"\nLLM analyzed:       {len(llm)} FP events")
print(f"\nSample LLM output:")
print(llm['llm_analysis'].iloc[0])

# Merge LLM analysis back into full FP table
full_report = fp.merge(llm[['eventId','llm_analysis']],
                        on='eventId', how='left')
full_report.to_csv("outputs/full_fp_report.csv", index=False)
print("\nFull report saved to outputs/full_fp_report.csv")