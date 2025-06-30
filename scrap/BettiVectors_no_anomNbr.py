import numpy as np
import gudhi
from sklearn.preprocessing import StandardScaler

# Load your .npy data file
data = np.load("100-botnet-attack.npy")  
# normalize data
scaler = StandardScaler()
data_scaled = scaler.fit_transform(data)

# Parameters
window_size = 10
max_edge_length = 10
max_dimension = 2

betti_vectors = []

# Process in chunks of 10
for i in range(0, len(data), window_size):
    if i + window_size > len(data):
        break  # Skip incomplete windows
    pts = data[i:i + window_size]
    rips = gudhi.RipsComplex(points=pts, max_edge_length=max_edge_length)
    st = rips.create_simplex_tree(max_dimension=max_dimension)
    st.compute_persistence()
    betti_vec = st.betti_numbers()
    # Pad with zeros if needed
    betti_vec += [0] * (max_dimension + 1 - len(betti_vec))
    betti_vectors.append(betti_vec)

# Convert to array and save
betti_array = np.array(betti_vectors)
np.save("betti_vectors.npy", betti_array)
print("Saved betti_vectors.npy with shape:", betti_array.shape)
