# llm_analysis.py
import pandas as pd
import requests
import time
import config

def analyze_fp(description: str, fp_label: str) -> str:
    prompt = f"""You are a DevSecOps security analyst.
A kernel-level anomaly detection model flagged this event as anomalous,
but ground truth shows it is NORMAL (false positive).

Event: {description}
Auto-label: {fp_label}

Answer these 3 questions concisely:
1. WHY is this a false positive? What legitimate behaviour does it represent?
2. HIDDEN RISK: Could there be a real threat hidden in this pattern? (yes/no + 1 sentence)
3. IMPROVEMENT: Suggest one concrete rule or threshold change to reduce this FP type."""

    # Ollama API Payload
    payload = {
        "model": config.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(config.OLLAMA_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "No response generated.")
    except Exception as e:
        return f"Error connecting to Ollama: {str(e)}"

def run_llm_analysis():
    print("Connecting to local Ollama...")
    fp_df = pd.read_csv(f"{config.DATA_DIR}/false_positives_labeled.csv")
    results = []

    # Run on first 10 FPs to save time during testing
    for _, row in fp_df.head(10).iterrows():
        analysis = analyze_fp(row['description'], row['fp_label'])
        results.append({
            'eventId': row['eventId'],
            'fp_label': row['fp_label'],
            'description': row['description'],
            'llm_analysis': analysis
        })
        print(f"Analyzed event {row['eventId']}")
        time.sleep(0.5)

    out_df = pd.DataFrame(results)
    out_df.to_csv(f"{config.OUTPUT_DIR}/llm_analysis_results.csv", index=False)
    print("LLM analysis complete. Results saved.")

if __name__ == "__main__":
    run_llm_analysis()