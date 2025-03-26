import pandas as pd
import matplotlib.pyplot as plt
import time

import pandas as pd
import matplotlib.pyplot as plt

# Load captured packets
csv_file = "network_traffic.csv"
df = pd.read_csv(csv_file)

# Mapping protocol numbers to names
protocol_mapping = {1: "ICMP", 6: "TCP", 17: "UDP"}
df["Protocol Name"] = df["Protocol"].map(protocol_mapping).fillna("Other")

# Count packet types
protocol_counts = df["Protocol Name"].value_counts()

# Count normal vs suspicious packets
suspicious_counts = df["Alert"].value_counts()

# Create subplots
fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# Graph 1: Protocol Distribution
protocol_counts.plot(kind="bar", color="blue", ax=axes[0], edgecolor="black")
axes[0].set_title("Protocol Distribution")
axes[0].set_xlabel("Protocol Type")
axes[0].set_ylabel("Packet Count")

# Graph 2: Suspicious Activity
suspicious_counts.plot(kind="bar", color=["green", "red"], ax=axes[1], edgecolor="black")
axes[1].set_title("Suspicious Traffic Detection")
axes[1].set_xlabel("Activity Type")
axes[1].set_ylabel("Count")

# Display the graphs
plt.tight_layout()
plt.show()
