import pandas as pd

# Load CSV file
df = pd.read_csv("network_traffic.csv")

# Display CSV in a formatted table
print(df.to_string(index=False))
