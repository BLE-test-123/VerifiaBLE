# BLE Communication Protocol Vulnerability Detection Framework

This repository contains scripts and tools for detecting potential vulnerabilities in BLE communication protocols of Android applications. The approach involves decompilation, code analysis, formal verification, and iterative repair and evaluation, ensuring security and reliability of BLE-based applications.

## Overview

The entire process is divided into **five main phases**. Each script corresponds to a specific phase:

1. **`BLE_app_choose`**  
   This script is responsible for selecting the BLE-related Android application for analysis. It identifies the target APK file that will be decompiled and analyzed in subsequent steps.

2. **`OpenAI-encrypt-features-extract`**  
   This script extracts BLE-related features and relevant code segments from the decompiled source code. It applies code slicing to manage token limits when using LLM-based processing.

3. **`server_auth_identify`**  
   This script verifies whether the extracted BLE-related code snippets contain authentication operations. It uses LLM to assess the presence of these security-critical operations and filters out irrelevant code.

4. **`server_proverif_generate and Repair`**  
   This script generates corresponding ProVerif code from the verified BLE code segments. The generated ProVerif code will be used for formal verification of BLE protocol security. It uses a RAG (Retrieval-Augmented Generation) framework and a dedicated ProVerif knowledge base to automatically fix these issues.

## Features

✅ APK decompilation and BLE-related code extraction  
✅ LLM-based static analysis and authentication verification  
✅ Automatic ProVerif code generation for formal verification  
✅ ProVerif code repair to ensure correctness  
✅ BLE protocol vulnerability detection and security assurance

## Usage

Each script is numbered according to the execution order. Please ensure you run them sequentially:

```bash
python BLE_app_choose.py
python OpenAI-encrypt-features-extract.py
python server_auth_identify.py
python server_proverif_generate.py
python command-proverif-error-exact.py
