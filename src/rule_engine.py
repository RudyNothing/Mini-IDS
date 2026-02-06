import numpy as np
import pandas as pd

class RuleEngine:

    def __init__(self):
        self.rules = [
            self.detect_ddos,
            self.detect_portscan,
            self.detect_botnet,
            self.detect_web_attack,
            self.detect_bruteforce
        ]

    def apply(self, row):
        
        for rule in self.rules:
            label, confidence = rule(row)
            if label is not None:
                return label, confidence
        return "Normal", 0.0

    # === STRICT RULES BELOW ===

    def detect_ddos(self, row):
        try:
            if (row['Flow Packets/s'] > 50000) and (row['Idle Min'] == 0) and (row['Flow IAT Min'] < 50):
                return "DDoS", 1.0
        except KeyError:
            pass
        return None, 0.0

    def detect_portscan(self, row):
        try:
            if (row['Destination Port'] > 10000) and (row['Packet Length Mean'] < 200) and (row['Flow Packets/s'] > 20000):
                return "PortScan", 1.0
        except KeyError:
            pass
        return None, 0.0

    def detect_botnet(self, row):
        try:
            if (row['Init_Win_bytes_forward'] == 0) and (row['Flow Bytes/s'] > 100000) and (row['Active Mean'] < 1000):
                return "Bot", 1.0
        except KeyError:
            pass
        return None, 0.0

    def detect_web_attack(self, row):
        try:
            if (row['Fwd Packet Length Max'] > 1000) and (row['Flow IAT Std'] > 1000000):
                return "Web Attack", 1.0
        except KeyError:
            pass
        return None, 0.0

    def detect_bruteforce(self, row):
        try:
            if (row['ACK Flag Count'] > 50000) and (row['FIN Flag Count'] < 5):
                return "Brute Force", 1.0
        except KeyError:
            pass
        return None, 0.0
        
if __name__ == "__main__":
    import pandas as pd

    # Create a fake row that should trigger a rule
    sample = pd.Series({
        'Flow Packets/s': 60000,
        'Idle Min': 0,
        'Flow IAT Min': 30,
        'Destination Port': 80,
        'Packet Length Mean': 100,
        'Init_Win_bytes_forward': 0,
        'Flow Bytes/s': 200000,
        'Active Mean': 500,
        'Fwd Packet Length Max': 2000,
        'Flow IAT Std': 2000000,
        'ACK Flag Count': 10,
        'FIN Flag Count': 0
    })

    engine = RuleEngine()
    label, confidence = engine.apply(sample)
    print(f"Detected: {label}, Confidence: {confidence}")
