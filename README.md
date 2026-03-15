# Side-Channel Analysis on AES-128

A practical **Correlation Power Analysis (CPA)** attack against a hardware AES-128 implementation running on an STM32 Nucleo microcontroller.  By capturing power consumption traces during encryption we recover the full 128-bit secret key using statistical leakage models.

> **Key Achievement:** 100% key recovery rate — all 16 key bytes recovered from power traces using the Hamming Weight leakage model.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Hardware Setup & Modification](#hardware-setup--modification)
3. [Attack Methodology](#attack-methodology)
4. [Repository Structure](#repository-structure)
5. [Task 1 — Python CPA Attack](#task-1--python-cpa-attack)
6. [Task 2 — MATLAB Power-Model Comparison](#task-2--matlab-power-model-comparison)
7. [Jupyter Notebook (Scared)](#jupyter-notebook-scared)
8. [Results](#results)
9. [Tech Stack](#tech-stack)
10. [Setup & Usage](#setup--usage)

---

## Project Overview

Side-channel attacks exploit unintentional physical information leakage (power, EM radiation, timing) rather than attacking the mathematical structure of a cipher.  This project performs a **CPA attack** on AES-128:

- The target device (STM32 Nucleo) encrypts random plaintext blocks while we record its instantaneous power consumption with an oscilloscope.
- For each of the 16 key bytes we test all 256 possible hypotheses, model the expected power consumption (using the Hamming Weight of `SubBytes(plaintext ⊕ key_guess)`), and find the hypothesis whose modelled power correlates most strongly with the real traces.
- The correct key hypothesis produces a sharp correlation peak; all others remain near zero.

---

## Hardware Setup & Modification

To maximise the signal-to-noise ratio (SNR) the STM32 Nucleo board was physically modified:

| Modification | Purpose |
|---|---|
| **Shunt resistor** inserted in the VDD power line | Converts current draw to a measurable voltage |
| **Decoupling capacitors** removed from the power rail | Prevents signal smoothing, exposes high-frequency power spikes |
| **GPIO trigger** added to AES firmware | Synchronises the oscilloscope capture to the exact start of encryption |

Power traces were captured with a low-noise oscilloscope probe.  Each trace covers the full first round of AES (1 000 samples).  A dataset of **10 000 traces** with corresponding plaintexts was collected for the attack.

---

## Attack Methodology

```
PC  --[UART]--> STM32 Nucleo
                   |  (AES-128 encryption + GPIO trigger)
             Oscilloscope  --> power_trace.bin
             PC            --> plaintext.bin
```

### CPA Workflow

1. **Data Collection**
   - PC sends random 128-bit plaintexts over UART.
   - Oscilloscope captures the power trace starting at the GPIO trigger.
   - Dataset: 10 000 traces × 1 000 samples, stored as `double`-precision binary.

2. **Leakage Modelling**
   - **Target:** First-round `SubBytes` output — `V = SubBytes(P ⊕ K)`.
   - **Model:** Hamming Weight (HW) — power is assumed proportional to the number of set bits in `V`.
   - For each of the 16 key bytes, 256 power hypotheses are generated: `H[k] = HW(SubBytes(P ⊕ k))`.

3. **Statistical Analysis**
   - Pearson Correlation Coefficient between `H[k]` and each sample column of the trace matrix.
   - The key byte hypothesis with the highest absolute correlation is the recovered key byte.
   - Attack is repeated independently for all 16 bytes.

4. **Power Model Comparison** (Task 2)
   - The MATLAB script additionally evaluates **8 single-bit leakage models** (bit 0 through bit 7) alongside the Hamming Weight model.
   - Minimum number of traces needed for successful recovery is measured for each model.

---

## Repository Structure

```
.
├── AES_CPA_Scared.ipynb              # End-to-end CPA attack using the Scared library
├── README.md
├── .gitignore
├── Task1_Python_Code_Files/
│   ├── CPA_Attack_Simple.py          # Modular, fully vectorised CPA attack (main script)
│   └── cpa_attack.py                 # Alternative implementation (struct-based loader)
└── Task2_MATLAB_Code_Files/
    ├── lab_task2_123.m               # CPA attack + 9-model comparison in MATLAB
    ├── attack_data_10k.mat           # [gitignored] 10 000 captured power traces
    ├── constants.mat                 # [gitignored] SubBytes table and HW lookup
    ├── dpa_attack_results.mat        # [gitignored] Saved attack results
    └── matlab_code.mat               # [gitignored] Auxiliary MATLAB data
```

> **Note:** Binary data files (`.bin`, `.mat`) and generated plots (`.png`) are excluded from version control via `.gitignore`.  You must supply your own dataset to run the scripts.

---

## Task 1 — Python CPA Attack

Two Python scripts are provided, both implementing the same attack with slightly different code organisation.

### `CPA_Attack_Simple.py` (recommended)

A clean, fully-modular implementation:

| Function | Description |
|---|---|
| `load_plaintexts()` | Loads and reshapes the plaintext binary file to `(N, 16)` |
| `load_traces_transposed()` | Loads trace binary, transposes column-wise storage to `(N, 1000)` |
| `compute_hamming_weight_table()` | Builds a 256-entry HW lookup table |
| `cpa_recover_key_byte()` | Vectorised correlation for one key byte — returns best guess + 256 correlation values |
| `recover_full_aes_key()` | Loops over all 16 bytes, returns full key + profiles |
| `plot_key_correlations()` | Saves a 4×4 grid of correlation bar charts to PNG |

Correct key highlighted in **red**; all other hypotheses in light blue.

### `cpa_attack.py`

An equivalent implementation using `struct.unpack` for trace loading.  The core correlation computation is identical.  This script also provides a `plot_single_byte()` helper for quick per-byte inspection.

### Running

```bash
cd Task1_Python_Code_Files
# Place plaintexts_SCA.bin, datapoints.bin, SubBytes.bin, HW.bin here
python CPA_Attack_Simple.py
# Output: CPA_attack_full_key.png + recovered key printed to console
```

---

## Task 2 — MATLAB Power-Model Comparison

`lab_task2_123.m` compares **9 leakage models** across all 16 key bytes:

| # | Model | Description |
|---|---|---|
| 1 | Hamming Weight | Sum of set bits in the intermediate value |
| 2–9 | Bit 0 – Bit 7 | A single bit (LSB to MSB) of the intermediate value |

For each model and each key byte, the script:
1. Computes `V = SubBytes(D XOR K)` for all 256 key hypotheses.
2. Builds the hypothetical power matrix `H` according to the selected model.
3. Computes the **full-set** Pearson correlation (using all 10 000 traces) to establish the true key byte.
4. Finds the **minimum trace count** from `[100, 500, 1000, 2000, 5000, 10000]` that already recovers the same key byte.

Results are saved in a `results` struct and the average traces needed is printed for each model.

### Running

Open MATLAB, navigate to `Task2_MATLAB_Code_Files/`, and run:

```matlab
lab_task2_123
```

---

## Jupyter Notebook (Scared)

`AES_CPA_Scared.ipynb` demonstrates the same attack using the **[Scared](https://gitlab.com/eshard/scared)** SCA framework:

| Step | Description |
|---|---|
| 1 | Load plaintexts and traces into a `TraceHolderSet` (THS) |
| 2 | Define `FirstSubBytes` selection function |
| 3 | Instantiate `CPAAttack` with `HammingWeight` model and `maxabs` discriminant |
| 4 | Run `att.run(container)` |
| 5 | Extract key via `np.argmax(att.scores, axis=0)` |
| 6 | Visualise per-byte correlation traces (correct vs. wrong hypotheses) |

Install dependencies:

```bash
pip install scared numpy matplotlib
```

---

## Results

| Metric | Value |
|---|---|
| Total key bytes recovered | 16 / 16 |
| Success rate | 100% |
| Best model | Hamming Weight |
| Typical traces needed (HW) | ~1 000 – 2 000 |
| Dataset size | 10 000 traces × 1 000 samples |

The Hamming Weight model consistently requires the fewest traces.  Single-bit models require more traces but can succeed with sufficient data, with higher-order bits (closer to MSB) generally performing slightly better due to higher variance in leakage.

---

## Tech Stack

| Layer | Tools |
|---|---|
| **Hardware** | STM32 Nucleo, oscilloscope, low-noise probes |
| **Firmware** | C (STM32 HAL/LL), GPIO trigger |
| **Python Analysis** | Python 3.10+, NumPy, Matplotlib, Scared |
| **MATLAB Analysis** | MATLAB R2022b+ |
| **Notebook** | Jupyter, ipykernel |

---

## Setup & Usage

### Python (Task 1 & Notebook)

```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux / macOS

# Install dependencies
pip install numpy matplotlib scared

# Run Task 1
cd Task1_Python_Code_Files
python CPA_Attack_Simple.py

# Run Notebook
cd ..
jupyter notebook AES_CPA_Scared.ipynb
```

### MATLAB (Task 2)

1. Open MATLAB.
2. Change directory to `Task2_MATLAB_Code_Files/`.
3. Ensure `attack_data_10k.mat` and `constants.mat` are present.
4. Run `lab_task2_123`.

---

**Author:** Uzair Ashfaq  
**Date:** November 2025

