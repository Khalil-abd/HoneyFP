import pandas as pd
import json
import config

def run_config_gen():
    patterns = pd.read_csv(f"{config.DATA_DIR}/fp_pattern_summary.csv")
    
    # Build a honeypot config: which events to simulate
    honeypot_scenarios = []
    for _, row in patterns.iterrows():
        scenario = {
            "fp_label": row["fp_label"],
            "eventId": int(row["eventId"]),
            "count": int(row["count"]),
            "honeypot_type": (
                "cowrie_ssh"    if row["fp_label"] == "benign"
                else "llm_honeypot" if row["fp_label"] == "suspicious"
                else "fp_validator"
            ),
            "simulate": f"event {int(row['eventId'])} with return {row['avg_return']:.0f}"
        }
        honeypot_scenarios.append(scenario)
    
    with open(f"{config.DATA_DIR}/honeypot_config.json", "w") as f:
        json.dump(honeypot_scenarios, f, indent=2)
    
    print(f"Honeypot config saved to {config.DATA_DIR}/honeypot_config.json")
    print(f"{len(honeypot_scenarios)} scenarios defined")

if __name__ == "__main__":
    run_config_gen()