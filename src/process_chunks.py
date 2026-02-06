import os
from preprocessing import Preprocessor 

#  Paths relative to project root
feature_file = os.path.join("models", "feature_cols.json")
chunk_dir = os.path.join("mini-ids", "data", "processed_parquet")
csv_file = os.path.join("mini-ids", "data", "cicids2017_cleaned.csv")

preprocessor = Preprocessor(feature_file_path=feature_file, label_column="Attack type")

def process_single_file(file_path):
    print(f"\n[PROCESSING]: {file_path}")
    X, y = preprocessor.process(file_path)
    print(f"[DONE] File processed. Features shape: {X.shape}")
    return X, y

if __name__ == "__main__":
    # Process CSV file
    if os.path.exists(csv_file):
        print("\n=== Processing Full CSV File ===")
        process_single_file(csv_file)
    else:
        print(f"[ERROR] CSV file not found: {csv_file}")

    # Process all parquet chunks
    if os.path.exists(chunk_dir):
        print("\n=== Processing Parquet Chunks ===")
        files = sorted(f for f in os.listdir(chunk_dir) if f.endswith(".parquet"))
        if not files:
            print("[ERROR] No .parquet files found in the folder!")
        else:
            for file_name in files:
                file_path = os.path.join(chunk_dir, file_name)
                process_single_file(file_path)
    else:
        print(f"[ERROR] Chunk directory not found: {chunk_dir}")
