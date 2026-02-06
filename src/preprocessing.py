import pandas as pd
import numpy as np
import json
import os

class Preprocessor:
    def __init__(self, feature_file_path, label_column="Attack type"):
        self.label_column = label_column
        self.feature_columns = self._load_feature_columns(feature_file_path)
        print(f"[INFO] Loaded {len(self.feature_columns)} ML feature columns.")

    def _load_feature_columns(self, feature_file_path):
        try:
            with open(feature_file_path,'r') as f:
                features = json.load(f)

            if isinstance(features, dict):
                return list(features.values())
            elif isinstance(features, list):
                return features
            else:
                raise ValueError("Invalid feature file format.")
        except Exception as e:
            raise FileNotFoundError(f"Error reading feature file: {e}")

    def load_data(self, file_path):
        print(f"[INFO] Loading file: {file_path}")
        if file_path.endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.endswith('.parquet'):
            df = pd.read_parquet(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_path}")

        print(f"[INFO] Loaded dataset with {df.shape[0]} rows and {df.shape[1]} columns.")
        return df

    def clean_data(self, df):
        print("[INFO] Cleaning data...")
        df = df.replace([np.inf,-np.inf],np.nan)
        df = df.dropna()
        df = df.drop_duplicates()
        print(f"[INFO] Cleaned Dataset now has {df.shape[0]} rows.")
        return df

    def select_features(self, df):
        print("[INFO] Selecting ML features...")
        for col in self.feature_columns:
            if col not in df.columns:
                print(f"[WARNING] Missing Column in Data: {col}, filling with 0.")
                df[col] = 0
        x = df[self.feature_columns]
        return x

    def get_labels(self, df):
        if self.label_column in df.columns:
            return df[self.label_column]
        else:
            print(f"[WARNING] Label Column '{self.label_column}' not found. Returning None.")
            return None

    def process(self, file_path):
        df = self.load_data(file_path)
        df = self.clean_data(df)

        X = self.select_features(df)
        y = self.get_labels(df)

        print(f"[INFO] Final feature matrix shape: {X.shape}")
        if y is not None:
            print(f"[INFO] Labels Extracted. Unique classes: {y.unique()[:10]}...")
        return X,y