# main_pipeline.py
import load_beth
import train_model
import fp_identification
import fp_labeling
import fp_pattern_extraction
import llm_analysis
import honeypot_config

def execute_brain_pipeline():
    print("=== STARTING AI HONEYPOT ANALYTICAL ENGINE ===")
    
    print("\n[1/7] Loading and Encoding BETH Data...")
    load_beth.run_load_data()
    
    print("\n[2/7] Training Isolation Forest...")
    train_model.run_training()
    
    print("\n[3/7] Isolating False Positives...")
    fp_identification.run_identification()
    
    print("\n[4/7] Auto-Labeling Events...")
    fp_labeling.run_labeling()
    
    print("\n[5/7] Extracting Patterns...")
    fp_pattern_extraction.run_extraction()
    
    print("\n[6/7] Running Local AI (Ollama) Analysis...")
    llm_analysis.run_llm_analysis()
    
    print("\n[7/7] Generating Honeypot Config Blueprint...")
    honeypot_config.run_config_gen()

    print("\n=== PIPELINE COMPLETE ===")
    print("Blueprint generated: data/honeypot_config.json")

if __name__ == "__main__":
    execute_brain_pipeline()