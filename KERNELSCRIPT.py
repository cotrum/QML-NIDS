import numpy as np
import pandas as pd

# --- Configuration ---
input_csv = "SORTEDDATA/KERNEL_Hoic1_sorted.csv"  

# Columns to extract
columns = [
    "timestamp", "src_ip","dst_ip", "duration", "packets_rate", "total_payload_bytes",
    "bytes_rate", "syn_flag_counts", "avg_segment_size",
    "fwd_bytes_rate", "bwd_bytes_rate", "label"
]
zero_cols = ["duration", "packets_rate", "total_payload_bytes",
    "bytes_rate", "syn_flag_counts", "avg_segment_size",
    "fwd_bytes_rate", "bwd_bytes_rate"]

# columns = ["timestamp", "fwd_payload_bytes_variance", "total_payload_bytes", "bytes_rate", "max_packets_delta_len", "active_mean", "idle_median", "fwd_avg_segment_size", "duration", "label"]
# --- Load and process data ---
df = pd.read_csv(input_csv, low_memory=False)

# Find the index of the first "Bot" occurrence
first_bot_index = df[df["label"] == "DDoS_HOIC"].index[0]

# convert in place on df
df.loc[first_bot_index:, zero_cols] = (
    df.loc[first_bot_index:, zero_cols]
      .apply(pd.to_numeric, errors='coerce')
)

# then your subsequent filtering will also work on the modified df
df_after_bot = df.loc[first_bot_index:]

# Drop rows with NaNs in key columns (optional but recommended)
df_after_bot = df_after_bot.dropna(subset=zero_cols)

# Filter out rows where ALL key features are 0.0
df_after_bot = df_after_bot[~(df_after_bot[zero_cols] == 0.0).all(axis=1)]


# Filter and collect 200 of each class
bots = df_after_bot[df_after_bot["label"] == "DDoS_HOIC"].iloc[:400]
benigns = df_after_bot[df_after_bot["label"] == "Benign"].iloc[:400]

# Select only the needed columns
bots = bots[columns]
benigns = benigns[columns]

# Save as .npy files
np.save('hoic1attack_400.npy', bots.to_numpy())
np.save('hoic1benign_400.npy', benigns.to_numpy())

# Combine and sort by timestamp
combined = pd.concat([bots, benigns]).sort_values(by="timestamp").reset_index(drop=True)

# Save combined data
combined.to_csv("800-Hoic1-combined.csv", index=False)
# np.save(output_combined_npy, combined.to_numpy())