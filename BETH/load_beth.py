# load_beth.py
import pandas as pd
import glob
import os
from sklearn.preprocessing import LabelEncoder
import config

def run_load_data():
    all_files = glob.glob(os.path.join(config.RAW_DATA_PATH, "*.csv"))
    
    ind_df_list = []
    for filename in all_files:
        df = pd.read_csv(filename, header=0)
        df['source_file'] = os.path.basename(filename)
        ind_df_list.append(df)

    beth_df = pd.concat(ind_df_list, axis=0, ignore_index=True)

    # NEW: Encode text columns to numbers (e.g., "systemd" -> 1, "bash" -> 2)
    le = LabelEncoder()
    for cat_col in config.CATEGORICAL_FEATURES:
        # Fill missing values to avoid errors
        beth_df[cat_col] = beth_df[cat_col].fillna('unknown').astype(str)
        beth_df[cat_col] = le.fit_transform(beth_df[cat_col])

    # Save the cleaned dataframe so train_model.py can use it
    beth_df.to_csv(f"{config.DATA_DIR}/beth_clean.csv", index=False)
    print(f"Loaded and encoded {len(beth_df)} rows. Saved to beth_clean.csv")

if __name__ == "__main__":
    run_load_data()