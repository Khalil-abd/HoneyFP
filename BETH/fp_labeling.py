import pandas as pd
import config

def auto_label(row):
    if row['userId'] == 0 and row['returnValue'] == 0:
        return 'benign'
    if row['userId'] == 0 and row['returnValue'] < 0:
        return 'suspicious'
    if row['sus'] == 0:
        return 'misclassified'
    return 'benign' #default

def describe_event(row):
    return (
        f"Event {row['eventId']} ({row.get('eventName','unknown')}), "
        f"processId={row['processId']}, userId={row['userId']}, "
        f"returnValue={row['returnValue']}, score={row.get('anomaly_score', 0):.3f}"
    )

def run_labeling():
    fp_df = pd.read_csv(f"{config.DATA_DIR}/false_positives.csv")
    fp_df['fp_label'] = fp_df.apply(auto_label, axis=1)
    
    print(fp_df['fp_label'].value_counts())
    
    fp_df['description'] = fp_df.apply(describe_event, axis=1)
    fp_df.to_csv(f"{config.DATA_DIR}/false_positives_labeled.csv", index=False)
    print("Saved false_positives_labeled.csv")

if __name__ == "__main__":
    run_labeling()