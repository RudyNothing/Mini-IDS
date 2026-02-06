import joblib
import numpy as np
from rule_engine import RuleEngine

class FusionEngine:
    def __init__(self, model_path="models/rf_baseline.joblib", strict=True):
        self.strict = strict  # strict = rule OR ML triggers attack
        self.rule_engine = RuleEngine()

        try:
            self.ml_model = joblib.load(model_path)
            print(f"[INFO] ML model loaded successfully from: {model_path}")
        except Exception as e:
            print(f"[ERROR] Could not load ML model: {e}")
            self.ml_model = None

    def predict_ml(self, features, feature_names):
        if self.ml_model is None:
            return None, 0.0

        try:
            import pandas as pd

            # Wrap features into a DataFrame with correct column names
            df = pd.DataFrame([features], columns=feature_names)

            prediction = self.ml_model.predict(df)[0]
            confidence = max(self.ml_model.predict_proba(df)[0])

            return prediction, confidence

        except Exception as e:
            print(f"[ERROR] ML prediction failed: {e}")
            return None, 0.0

    def fuse(self, features, feature_names):

        # For rule engine
        sample = {feature_names[i]: features[i] for i in range(len(feature_names))}
        label_rule, conf_rule = self.rule_engine.apply(sample)

        # ML prediction using corrected DataFrame format
        label_ml, conf_ml = self.predict_ml(features, feature_names)

        # Fusion Logic
        if self.strict:
            if label_rule != "Normal":
                final_label = label_rule
                final_conf = conf_rule
            elif label_ml != "Normal":
                final_label = label_ml
                final_conf = conf_ml
            else:
                final_label = "Normal"
                final_conf = max(conf_rule, conf_ml)
        else:
            if conf_ml >= 0.7:
                final_label = label_ml
                final_conf = conf_ml
            else:
                final_label = label_rule
                final_conf = conf_rule

        return {
            "rule_label": label_rule,
            "rule_confidence": conf_rule,
            "ml_label": label_ml,
            "ml_confidence": conf_ml,
            "final_label": final_label,
            "final_confidence": final_conf
        }


if __name__ == "__main__":
    # === TEST BLOCK ===
    import pandas as pd

    # Sample fake input matching your ML feature order
    test_features = np.array([5000, 50, 300, 200, 500, 5, 1000, 10, 10000, 4000, 10000])
    feature_names = [
        "Total Fwd Packets", "Fwd Packet Length Mean", "Bwd Packet Length Mean",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Fwd Packet Length Max",
        "Flow IAT Mean", "Flow IAT Min", "Flow IAT Max",
        "Packet Length Mean", "Average Packet Size"
    ]

    fusion = FusionEngine(strict=True)
    result = fusion.fuse(test_features, feature_names)
    print("\n=== Fusion Result ===")
    for key, value in result.items():
        print(f"{key}: {value}")
