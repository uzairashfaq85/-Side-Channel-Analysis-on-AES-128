#!/usr/bin/env python
# =============================================================================
# File    : cpa_attack.py
# Project : Side-Channel Analysis on AES-128
# Author  : Uzair Ashfaq
# Created : November 2025
# Purpose : Correlation Power Analysis (CPA) attack on AES-128.
#           Loads 10 000 power traces and their corresponding plaintexts,
#           models the Hamming-weight leakage of the first-round SubBytes
#           output, and recovers all 16 key bytes via Pearson correlation.
#           Produces a 4x4 grid plot showing the correlation profile for
#           every key byte hypothesis.
# =============================================================================

import struct
import numpy as np
import sys
from datetime import datetime
import matplotlib
from matplotlib import pyplot as plt

def load_u8(filename):
    with open(filename, "rb") as fp:
        return np.array(list(fp.read()), dtype="uint8")


def _load_data():
    """Load plaintexts, traces, SubBytes table and HW table from binary files.

    The binary files are expected to be in the current working directory.
    Returns a tuple (plaintexts_SCA, datapoints, SubBytes, HW).
    """
    # Matrix with 10000 lines, each representing a message. Each message takes
    # 16 bytes, split over 16 columns.
    plaintexts_SCA = load_u8("plaintexts_SCA.bin").reshape((16, 10000)).T
    # Power measurements. Matrix with 10000 lines, one for each of the messages
    # in plaintexts_SCA, showing measurements of power consumption in the first
    # round of encrypting the message for AES. There are 1000 measurements over
    # the time period of the first round, so the matrix is 10000 rows x 1000 cols.
    with open("datapoints.bin", "rb") as fp:
        datapoints = struct.unpack("<10000000d", fp.read())
        datapoints = np.array(datapoints, dtype="float64").reshape((1000, 10000)).T
    # AES SubBytes function: array of size 256 with values between 0 and 255
    SubBytes = load_u8("SubBytes.bin")
    # Hamming Weight: array of 256 entries where HW[n] is the number of 1 bits in n
    HW = load_u8("HW.bin")
    return plaintexts_SCA, datapoints, SubBytes, HW


def CPA_find_key_byte(bytenum: int, plaintexts_SCA, datapoints, SubBytes, HW) -> tuple:
    # Keep only byte #bytenum in all the plaintexts
    D = plaintexts_SCA[:, bytenum]
    samples = datapoints.shape[0]
    traces = datapoints[:samples, :]
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
    #for key_index in range(len(K)):    (vectorised below — no loop needed)

    # Vectorized correlation computation
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
    except AttributeError:
        sys.stdout.write("\n")
        sys.stdout.flush()

    max_pos = np.unravel_index(np.nanargmax(np.abs(R)), R.shape)
    key_index_best = max_pos[0]
    key_found = int(K[key_index_best])
    # Use nanmax so that any zero-denominator NaN sentinels are safely ignored.
    correlations = [float(np.nanmax(np.abs(R[i, :]))) for i in range(len(K))]

    return key_found, correlations

def color(corr):
    x = min(corr, 0.25)
    return (0.75 - 3 * x, 0.75 - 2 * x, 1 - x)


def plot_single_byte(bytenum: int, key_found: int, correlations: list):
    """Save a bar-chart of CPA correlations for a single key byte."""
    title = "CPA attack of Tiny AES (GitHub) [{}]\nKey byte #{} = {}".format(
        datetime.now().strftime("%Y-%m-%d %H:%M"), bytenum, key_found
    )
    filename = "Tiny_AES_CPA_attack_key_byte_{}.png".format(bytenum)
    fig, ax = plt.subplots()
    ax.set_xticks([0, key_found, 255])
    ax.get_xticklabels()[1].set_weight("bold")
    colors = [color(abs(c)) for c in correlations]
    ax.bar(range(256), width=1, height=correlations, color=colors)
    ax.set_xlabel("Key hypothesis")
    ax.set_ylabel("Correlation")
    ax.set_title(title)
    plt.tight_layout()
    plt.savefig(filename, dpi=600)
    plt.close(fig)
    print("Done! Open {} for the plot.".format(filename))

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


if __name__ == "__main__":
    import os
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("Loading data files...")
    plaintexts_SCA, datapoints, SubBytes, HW = _load_data()
    # Attack the entire key
    keys_found, correlations_all = [], []
    for i in range(16):
        print(f"Finding key byte #{i}...")
        k, c = CPA_find_key_byte(i, plaintexts_SCA, datapoints, SubBytes, HW)
        keys_found.append(k)
        correlations_all.append(c)
    plot_full_key(keys_found, correlations_all)