"""
cleaned_cpa_attack_transposed.py
================================

This module contains a clear and well‑organised implementation of a
Correlation Power Analysis (CPA) attack against an AES‑128
implementation.  It is designed to work with the same binary
files and data layout as the original script provided by the user,
where the trace file is reshaped with a transpose (i.e. each
trace is stored column‑wise in the raw data).  The code is
structured into modular functions with descriptive names and
docstrings and prints status messages to the console so you can
follow the progress of the attack.

The key steps performed by this script are:

    1. Load plaintexts from a binary file and reshape into a
       (num_traces, 16) array.  Each row corresponds to a single
       AES block.
    2. Load power traces from a binary file of double‑precision
       samples and reshape into a (num_traces, num_samples) array
       using the transpose method (the same as the original script).
    3. Load the AES S‑Box and Hamming weight lookup tables.
    4. Recover each of the 16 key bytes using a vectorised CPA
       attack.
    5. Display the recovered key and plot per‑byte correlation
       profiles in a 4×4 grid.

If your trace file is organised differently (e.g. each trace’s
samples are contiguous in the file), you should instead use the
``cleaned_cpa_attack.py`` module which reshapes the data without
transposition.

Usage:

    python3 cleaned_cpa_attack_transposed.py

You may need to adjust the constants in the ``main`` function to
match your dataset dimensions and file names.
"""

from __future__ import annotations

import numpy as np
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt


def load_u8_file(filepath: str | Path) -> np.ndarray:
    """Load a binary file as an array of uint8 values.

    Parameters
    ----------
    filepath : str or Path
        Path to the binary file to load.

    Returns
    -------
    numpy.ndarray
        1‑D array of ``uint8`` values representing the contents of
        the file.
    """
    filepath = Path(filepath)
    with filepath.open("rb") as fp:
        return np.frombuffer(fp.read(), dtype=np.uint8)


def load_plaintexts(path: str | Path, num_traces: int) -> np.ndarray:
    """Load plaintexts from a binary file and reshape into a matrix.

    The file must contain exactly ``num_traces × 16`` bytes.  The
    returned array has shape ``(num_traces, 16)``, where each row
    corresponds to a plaintext block.

    Parameters
    ----------
    path : str or Path
        File containing concatenated plaintext bytes.
    num_traces : int
        Number of traces (and hence plaintexts) in the file.

    Returns
    -------
    numpy.ndarray
        Array of shape ``(num_traces, 16)`` with dtype ``uint8``.
    """
    data = load_u8_file(path)
    expected_size = num_traces * 16
    if data.size != expected_size:
        raise ValueError(
            f"Plaintext file {path} contains {data.size} bytes, expected {expected_size}."
        )
    # Reshape to (16, num_traces) then transpose to (num_traces, 16).
    return data.reshape((16, num_traces)).T


def load_traces_transposed(path: str | Path, num_traces: int, num_samples: int) -> np.ndarray:
    """Load power traces from a binary file and reshape using transpose.

    The raw file is interpreted as ``num_traces × num_samples``
    double‑precision values.  Each sample for a given trace is
    stored column‑wise, so we reshape the data into
    ``(num_samples, num_traces)`` and then transpose it to
    ``(num_traces, num_samples)``.  This matches the behaviour of
    the original script.

    Parameters
    ----------
    path : str or Path
        Path to the binary file containing the power samples.
    num_traces : int
        Number of traces recorded.
    num_samples : int
        Number of samples per trace.

    Returns
    -------
    numpy.ndarray
        2‑D array of shape ``(num_traces, num_samples)`` with
        dtype ``float64``.
    """
    path = Path(path)
    total_samples = num_traces * num_samples
    with path.open("rb") as fp:
        data = np.frombuffer(fp.read(), dtype="<d")
    if data.size != total_samples:
        raise ValueError(
            f"Trace file {path} contains {data.size} samples, expected {total_samples}."
        )
    # Reshape to (num_samples, num_traces) and transpose to (num_traces, num_samples).
    return data.reshape((num_samples, num_traces)).T


def compute_hamming_weight_table() -> np.ndarray:
    """Compute a lookup table for the Hamming weight of 0 through 255.

    Returns
    -------
    numpy.ndarray
        Array of shape (256,) where the element at index ``i`` is the
        number of set bits in the binary representation of ``i``.
    """
    return np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)


def cpa_recover_key_byte(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    byte_index: int,
    subbytes_table: np.ndarray,
    hw_table: np.ndarray,
) -> tuple[int, np.ndarray]:
    """Recover one AES key byte via correlation power analysis.

    Parameters
    ----------
    traces : numpy.ndarray
        Array of shape ``(num_traces, num_samples)`` containing measured
        power traces.
    plaintexts : numpy.ndarray
        Array of shape ``(num_traces, 16)`` containing plaintext blocks.
    byte_index : int
        Index (0–15) of the key byte to recover.
    subbytes_table : numpy.ndarray
        Lookup table for the AES S‑Box (256 entries).
    hw_table : numpy.ndarray
        Lookup table for the Hamming weight of 0–255 (256 entries).

    Returns
    -------
    tuple[int, numpy.ndarray]
        A pair ``(best_key, correlations)`` where ``best_key`` is the
        recovered key byte and ``correlations`` is a 1‑D array of length
        256 containing the maximum absolute correlation for each key
        hypothesis.
    """
    # Extract plaintext byte vector.
    p = plaintexts[:, byte_index]
    num_traces, num_samples = traces.shape
    # Hypotheses for this key byte.
    key_guesses = np.arange(256, dtype=np.uint8)
    # Compute SBOX(P ⊕ K) for each guess.
    intermediates = subbytes_table[np.bitwise_xor(p[:, None], key_guesses[None, :])]
    # Convert to Hamming weight predictions.
    hyp_power = hw_table[intermediates]
    # Cast to float and center.
    hyp_power_f = hyp_power.astype(float)
    traces_f = traces.astype(float)
    hyp_centered = hyp_power_f - hyp_power_f.mean(axis=0)
    traces_centered = traces_f - traces_f.mean(axis=0)
    # Correlate each hypothesis with each sample.
    numerator = hyp_centered.T @ traces_centered
    hyp_variance = np.sum(hyp_centered ** 2, axis=0)
    trace_variance = np.sum(traces_centered ** 2, axis=0)
    denom = np.sqrt(hyp_variance[:, None] * trace_variance[None, :])
    # Safe division: fill zeros where denom is zero.
    corr = np.divide(numerator, denom, out=np.zeros_like(numerator), where=denom != 0)
    # Maximum absolute correlation per hypothesis.
    max_corr = np.nanmax(np.abs(corr), axis=1)
    best_guess = int(np.nanargmax(max_corr))
    return best_guess, max_corr


def recover_full_aes_key(
    traces: np.ndarray,
    plaintexts: np.ndarray,
    subbytes_table: np.ndarray,
    hw_table: np.ndarray,
) -> tuple[list[int], list[np.ndarray]]:
    """Recover all 16 bytes of the AES key.

    Parameters
    ----------
    traces : numpy.ndarray
        Measured power traces (num_traces × num_samples).
    plaintexts : numpy.ndarray
        Matrix of plaintext bytes (num_traces × 16).
    subbytes_table : numpy.ndarray
        AES S‑Box lookup table.
    hw_table : numpy.ndarray
        Hamming weight lookup table.

    Returns
    -------
    tuple[list[int], list[np.ndarray]]
        A pair ``(keys, correlations)`` where ``keys`` is a list of
        recovered key bytes and ``correlations`` is a list of
        correlation profiles (one per byte).
    """
    recovered = []
    profiles = []
    for idx in range(plaintexts.shape[1]):
        key_byte, corr = cpa_recover_key_byte(traces, plaintexts, idx, subbytes_table, hw_table)
        recovered.append(key_byte)
        profiles.append(corr)
    return recovered, profiles


def plot_key_correlations(
    keys: list[int],
    correlations: list[np.ndarray],
    output_path: str | Path = "CPA_attack_full_key.png",
    title_prefix: str | None = None,
) -> None:
    """Generate a 4×4 grid of correlation bar charts.

    Each subplot shows the maximum absolute correlation for each of
    the 256 key hypotheses for a single key byte.  The bar for the
    recovered key hypothesis is highlighted in red.

    Parameters
    ----------
    keys : list[int]
        List of 16 recovered key bytes.
    correlations : list[np.ndarray]
        List of 16 arrays of length 256 containing max correlations.
    output_path : str or Path, optional
        Path to save the resulting plot image.
    title_prefix : str or None, optional
        Prefix to add to the plot title.
    """
    if len(keys) != 16 or len(correlations) != 16:
        raise ValueError("Expected 16 key bytes and 16 correlation arrays.")
    plt.rcParams.update({"font.size": 6})
    fig, axes = plt.subplots(4, 4, figsize=(12, 8))
    for i in range(16):
        r, c = divmod(i, 4)
        ax = axes[r, c]
        bars = correlations[i]
        colors = ["red" if j == keys[i] else "lightblue" for j in range(256)]
        ax.bar(range(256), bars, color=colors, width=1)
        ax.set_title(f"Byte #{i}")
        ax.set_xticks([0, keys[i], 255])
        if c == 0:
            ax.set_ylabel("Correlation")
        if r == 3:
            ax.set_xlabel("Key Hypothesis")
        ax.grid(axis='y', alpha=0.3)
    key_hex = " ".join(f"{b:02X}" for b in keys)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    title = f"{title_prefix or 'CPA Attack Results'} [{timestamp}]\nRecovered Key: {key_hex}"
    fig.suptitle(title, fontsize=10)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(output_path, dpi=600)
    plt.show()


def main() -> None:
    """Perform a CPA attack on AES using transposed trace data.

    Adjust the constants in this function to match your dataset
    dimensions and file names.  The script prints progress messages
    mirroring the original output and generates a correlation plot
    summarising the attack results.
    """
    # Configuration: adjust to your dataset
    NUM_TRACES = 10000
    NUM_SAMPLES = 1000
    PLAINTEXTS_FILE = "plaintexts_SCA.bin"
    TRACES_FILE = "datapoints.bin"
    SUBBYTES_FILE = "SubBytes.bin"
    HW_FILE = "HW.bin"
    OUTPUT_PLOT = "CPA_attack_full_key.png"
    TITLE_PREFIX = "CPA Attack of Tiny AES (Transposed)"
    # Step 1: Load data
    print("Loading plaintexts…")
    pts = load_plaintexts(PLAINTEXTS_FILE, NUM_TRACES)
    print(f"Loaded {pts.shape[0]} plaintexts of {pts.shape[1]} bytes each.")
    print("Loading power traces…")
    traces = load_traces_transposed(TRACES_FILE, NUM_TRACES, NUM_SAMPLES)
    print(f"Loaded {traces.shape[0]} traces with {traces.shape[1]} samples each.")
    print("Loading S‑Box and Hamming weight tables…")
    sbox = load_u8_file(SUBBYTES_FILE)
    hw = load_u8_file(HW_FILE)
    if sbox.size != 256 or hw.size != 256:
        raise ValueError("SubBytes and HW tables must each contain 256 entries.")
    # Step 2: Recover key
    print("Recovering AES key using CPA…")
    key, corr_profiles = recover_full_aes_key(traces, pts, sbox, hw)
    print("Recovered key:", " ".join(f"{b:02X}" for b in key))
    # Step 3: Plot results
    print("Generating correlation plots…")
    plot_key_correlations(key, corr_profiles, output_path=OUTPUT_PLOT, title_prefix=TITLE_PREFIX)


if __name__ == "__main__":
    main()