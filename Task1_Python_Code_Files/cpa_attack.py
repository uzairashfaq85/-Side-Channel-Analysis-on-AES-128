#!/usr/bin/env python

import struct
import numpy as np
import sys
from datetime import datetime
import matplotlib
from matplotlib import pyplot as plt

def load_u8(filename):
    with open(filename, "rb") as fp:
        return np.array(list(fp.read()), dtype="uint8")

# Matrix with 10000 lines, each representing a message. Each message takes 16
# Load data
# bytes, split over 16 columns.
plaintexts_SCA = load_u8("plaintexts_SCA.bin").reshape((16, 10000)).T
# Power measurements. Matrix with 10000 lines, one for each of the messages in
# plaintexts_SCA, showing measurements of power consumption in the first round
# of encrypting the mssage for AES. There are 1000 measurements over the time
# period of the first round, so the matrix is 10000 rows, 1000 columns.
with open("datapoints.bin", "rb") as fp:
    datapoints = struct.unpack("<10000000d", fp.read())
    datapoints = np.array(datapoints, dtype="float64").reshape((1000,10000)).T
# AES SubBytes function: array of size 256 with values between 0 and 255
SubBytes = load_u8("SubBytes.bin")
# Hamming Weight: array of 256 entries where HW[n] is the number of 1 bits in n
HW = load_u8("HW.bin")

# This controls how many samples we use for analysis
samples = datapoints.shape[0]
# Function that uses CPA to find the byte #bytenum of the key.
def CPA_find_key_byte(bytenum: int) -> int:
    # Keep only byte #bytenum in all the plaintexts
    D = plaintexts_SCA[:, bytenum]
    traces = datapoints[:samples,:]
    trace_length = datapoints.shape[1]
    # All hypotheses for the value of key byte #bytenum: 0..255
    K = np.arange(256, dtype=np.uint8)
    # Calculate the intermediate values of AES' first round for all of these
    # hypothetical keys
    V = SubBytes[np.bitwise_xor(D[:, None].astype(np.uint8), K[None, :])]
    # Calculate hypothetical power consumption with the Hamming Weight model.
    # Here, we bet that the power consumption will be proportional to how many
    # 1 bits there are in the intermdiate value. If this is correct, we can
    # check which key hypothesis matches traces the best to find the key.
    H = HW[V]
    # Calculate the correlations between estimated power consumption and the
    # real power consumption traces.
    R = np.zeros((len(K), trace_length), dtype="float64")
    #for key_index in range(len(K)):
    
    
    '''
    print("Working on key guess =", key_index, end="")
    # (trick to overwrite the same line multiple times in the terminal)
    sys.stdout.flush(); sys.stdout.buffer.write(b'\r\x1b[K')
    # Compute the correlation coefficient between the predicted power
        # consumption of key hypothesis #key_index, and the real power
        # consumption of trace #trace_index.
        for trace_index in range(trace_length):
            R[key_index, trace_index] = ... # TODO (use np.corrcoef())

    # Find the key_index/trace_index pair with the best correlation and deduce
    # that this key hypothesis is the most likely value of secret key byte
    # #bytenum.
    key_found = ... # TODO (you can use abs(R).argmax())
    # Also return the max correlation for each key hypothesis, so we can plot
    # it and see how key_found correlates much better than other hypotheses.
    '''

    
    # Vectorized correlation computation for fast 
    traces_f = traces.astype("float64")
    H_f = H.astype("float64")
    H_centered = H_f - H_f.mean(axis=0)
    traces_centered = traces_f - traces_f.mean(axis=0)
    numerator = H_centered.T @ traces_centered
    h_ss = np.sum(H_centered**2, axis=0)
    t_ss = np.sum(traces_centered**2, axis=0)
    denominator = np.sqrt(h_ss[:, None] * t_ss[None, :])
    denominator[denominator == 0] = np.nan
    R = numerator / denominator

    # Ensure a final newline
    try:
        sys.stdout.buffer.write(b'\n')
    except Exception:
        sys.stdout.write("\n")
        sys.stdout.flush()

    max_pos = np.unravel_index(np.nanargmax(np.abs(R)), R.shape)
    key_index_best = max_pos[0]
    key_found = int(K[key_index_best])
    correlations = [max(abs(R[i,:])) for i in range(len(K))]

    return key_found, correlations

def color(corr):
    x = min(corr, 0.25)
    return (0.75 - 3 * x, 0.75 - 2 * x, 1 - x)

    
    '''
    # Make a plot for a single key byte
def plot_single_byte(bytenum: int, key_found: int, correlations: list[float]):
    title = "CPA attack of Tiny AES (GitHub) [{}]\n"
    title += "Key byte #{} = {}"
    title = title.format(datetime.now().strftime("%Y-%m-%d %H:%M"), bytenum, key_found)
    filename = "Tiny_AES_CPA_attack_key_byte_{}.png".format(bytenum)
    fig, ax = plt.subplots()
    ax.set_xticks([0, key_found, 255])
    ax.get_xticklabels()[1].set_weight("bold")
    colors = [color(abs(c)) for c in correlations]
    plt.bar(range(256), width=1, height=correlations, color=colors)
    plt.xlabel("Key hypothesis")
    plt.ylabel("Correlation")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(filename, dpi=600)
    print("Done! Open {} for the plot.".format(filename))
# Make a plot for all key bytes
    '''

def plot_full_key(keys_found: list[int], correlations: list[list[float]]):
    title = "CPA Attack of Tiny AES [{}]\nKey: {}".format(
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        " ".join("{:02x}".format(b) for b in keys_found)
    )
    filename = "Tiny_AES_CPA_attack_full_key.png"

    matplotlib.rc("font", size=6)
    fig, axs = plt.subplots(4, 4, figsize=(12, 8))  # Adjusted figure size for clarity
    for i in range(16):
        x, y = i % 4, i // 4
        axs[y,x].set_xticks([0, keys_found[i], 255])
        axs[y,x].get_xticklabels()[1].set_weight("bold")
        colors = [color(abs(c)) for c in correlations[i]]
        axs[y,x].bar(range(256), width=1, height=correlations[i], color=colors)
        axs[y,x].set_title(f"Byte #{i}")
        if x == 0:
            axs[y,x].set_ylabel("Correlation")
        if y == 3:
            axs[y,x].set_xlabel("Key Hypothesis")
    fig.suptitle(title, fontsize=10)
    plt.tight_layout(rect=[0, 0, 1, 0.95])  # Adjust layout to fit title
    plt.savefig(filename, dpi=600)
    print(f"Done! Open {filename} for the plot.")

    
    '''
# Basic example: attack a single byte
byte_to_attack = 0
key_found, correlations = CPA_find_key_byte(byte_to_attack)
plot_single_byte(byte_to_attack, key_found, correlations)
'''
    
# Attack the entire key
keys_found, correlations = [], []
for i in range(16):
    print(f"Finding key byte #{i}...")
    k, c = CPA_find_key_byte(i)
    keys_found.append(k)
    correlations.append(c)
plot_full_key(keys_found, correlations)