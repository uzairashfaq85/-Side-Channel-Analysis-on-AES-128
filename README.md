📖 Overview

This project demonstrates a practical Correlation Power Analysis (CPA) attack against a hardware implementation of AES-128 running on an STM32 Nucleo microcontroller. By modifying the board's power delivery network and capturing power consumption traces during encryption, we successfully recovered the full 128-bit secret key using statistical leakage models.

Key Achievement: Recovered the full 128-bit AES key by analyzing power consumption fluctuations, exploiting the Hamming Weight leakage model.

🔧 Hardware Modification & Setup
To perform the attack, the target STM32 Nucleo board was physically modified to maximize signal-to-noise ratio (SNR):

•	Shunt Resistor: Inserted a low-resistance shunt in the VDD power line to measure current draw.

•	Decoupling Capacitors: Removed specific capacitors to prevent signal smoothing, exposing high-frequency power spikes.

•	Trigger Mechanism: Implemented a GPIO trigger in the AES firmware to synchronize the oscilloscope capture exactly at the start of encryption.

🔬 Attack Methodology

The attack follows a standard CPA workflow:

1.	Data Collection:

  	•	The PC sends random plaintexts to the STM32 via UART.

  	•	The oscilloscope captures the power trace during the first round of AES.

  	•	Dataset: N traces recorded with corresponding plaintexts.

2.	Leakage Modeling:

  	•	Target: First Round S-Box output.

  	•	Model: Hamming Weight (HW) of the intermediate value.


4.	Statistical Analysis:

  	•	For each of the 16 key bytes, we hypothesized all 256 possible values (0x00 to 0xFF).

  	•	Computed the Pearson Correlation Coefficient between the modeled power consumption and the actual oscilloscope traces.

  	•	The correct key byte corresponds to the hypothesis with the highest correlation peak.

📊 Results
   
   •	Success Rate: 100% key recovery.
   
   •	Leakage Validation: Verified that the physical power consumption aligns with the Hamming Weight model at specific clock cycles.
 
🛠️ Tech Stack

  •	Hardware: STM32 Nucleo, Oscilloscope, Low-noise Probes.
  
  •	Firmware: C (HAL/LL), ASM optimizations.
  
  •	Analysis: Python (NumPy, SciPy), Matplotlib for trace visualization.
 
Author: Uzair Ashfaq
