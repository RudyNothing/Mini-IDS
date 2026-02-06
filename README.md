Mini Intrusion Detection System (IDS)

This project is a Mini Intrusion Detection System (IDS) built to practically understand how security monitoring and attack detection works, instead of just reading theory. The system focuses on detecting suspicious activity by analyzing network traffic and system behavior, with a clean and interactive dashboard built using Streamlit.

The project uses Python to process traffic data and apply rule-based detection. Simple but effective rules were written to flag abnormal behavior, such as unusually high packet counts from a single source, repeated connection attempts, or irregular traffic spikes within a short time window. These rules help identify potential brute-force or scanning-like activities.

The system uses the CICIDS2017 cleaned dataset, which contains labeled network traffic representing both normal behavior and multiple attack types. This dataset helped validate the detection logic against realistic and diverse traffic patterns.

The detection logic follows a rule-based approach, where traffic features such as packet counts, flow duration, and request frequency are analyzed to identify suspicious behavior like brute-force attempts, scanning activity, or traffic floods. These rules were intentionally kept simple and transparent to clearly demonstrate how an IDS makes decisions at a fundamental level.


The CICIDS2017_cleaned datasent can be downloaded from Kaggle or HuggingFace.
