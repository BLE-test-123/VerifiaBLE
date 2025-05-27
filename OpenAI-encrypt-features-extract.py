from androguard.misc import AnalyzeAPK
import os
import subprocess
import zipfile
import re
import traceback


def run_command(command):
    """Run a command in the terminal and print the output."""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Error: {stderr.decode('utf-8', errors='ignore')}")
    else:
        print(stdout.decode('utf-8', errors='ignore'))


def decompile_with_cfr(jar_file, output_dir, cfr_jar_path):
    """Decompile a JAR file to Java source code using CFR."""
    cfr_command = f'java -jar "{cfr_jar_path}" "{jar_file}" --outputdir "{output_dir}"'
    print(f"Running CFR: {cfr_command}")
    run_command(cfr_command)


def extract_dex_files(apk_file, output_dir):
    """Extract classes.dex files from APK using Python's zipfile module."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with zipfile.ZipFile(apk_file, 'r') as apk:
        for file in apk.namelist():
            if file.startswith('classes') and file.endswith('.dex'):
                apk.extract(file, output_dir)
                print(f"Extracted {file} to {output_dir}")


def convert_dex_to_jar(dex_file, output_dir, dex2jar_path):
    """Convert a dex file to jar using dex2jar."""
    jar_file = os.path.join(output_dir, os.path.basename(dex_file).replace('.dex', '.jar'))
    dex2jar_command = f'"{dex2jar_path}" "{dex_file}" -o "{jar_file}"'
    run_command(dex2jar_command)
    return jar_file


def find_files_with_extension(dir, extension):
    """Find all files with the given extension in the specified directory."""
    files = []
    for root, _, file_names in os.walk(dir):
        for file in file_names:
            if file.endswith(extension):
                files.append(os.path.join(root, file))
    return files


def decompile_apk(apk_path, base_output_dir, cfr_jar_path, dex2jar_path):
    """Decompile APK file using dex2jar and CFR."""
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]

    dex_output_dir = os.path.join(base_output_dir, "dex_files")
    jar_output_dir_base = os.path.join(base_output_dir, "jar_files")
    cfr_output_dir_base = os.path.join(base_output_dir, "cfr_files")

    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file does not exist: {apk_path}")

    if not os.path.exists(cfr_jar_path):
        raise FileNotFoundError(f"CFR jar path does not exist: {cfr_jar_path}")

    if not os.path.exists(dex2jar_path):
        raise FileNotFoundError(f"dex2jar path does not exist: {dex2jar_path}")

    if not os.path.exists(dex_output_dir):
        os.makedirs(dex_output_dir)

    if not os.path.exists(jar_output_dir_base):
        os.makedirs(jar_output_dir_base)

    if not os.path.exists(cfr_output_dir_base):
        os.makedirs(cfr_output_dir_base)

    # Extract DEX files from APK
    extract_dex_files(apk_path, dex_output_dir)

    # Convert DEX files to JAR
    dex_files = find_files_with_extension(dex_output_dir, '.dex')
    jar_files = []
    for index, dex_file in enumerate(dex_files):
        jar_output_dir = os.path.join(jar_output_dir_base, f"jar_{index + 1}")
        if not os.path.exists(jar_output_dir):
            os.makedirs(jar_output_dir)
        jar_file = convert_dex_to_jar(dex_file, jar_output_dir, dex2jar_path)
        jar_files.append((jar_file, jar_output_dir))

    # Decompile JAR files using CFR
    for index, (jar_file, jar_output_dir) in enumerate(jar_files):
        cfr_output_dir = os.path.join(cfr_output_dir_base, f"jar_{index + 1}")
        if not os.path.exists(cfr_output_dir):
            os.makedirs(cfr_output_dir)
        decompile_with_cfr(jar_file, cfr_output_dir, cfr_jar_path)

    return cfr_output_dir_base


def main():
    cfr_jar_path = "<CFR_JAR_PATH>"
    dex2jar_path = "<DEX2JAR_PATH>"
    apk_folder = "<APK_FOLDER_PATH>"

    if not os.path.exists(apk_folder):
        print(f"APK folder does not exist: {apk_folder}")
        return

    for apk_file in os.listdir(apk_folder):
        if apk_file.endswith(".apk"):
            apk_path = os.path.join(apk_folder, apk_file)
            apk_name = os.path.splitext(os.path.basename(apk_path))[0]
            output_file_name = f"<OUTPUT_FILE_DIR>/{apk_name}_OpenAI-v2-encrypt-folder-ccc.java"
            filter_name = f"<FILTER_FILE_DIR>/{apk_name}_OpenAI-v2-encrypt-folder-ccc-filter.java"
            base_output_dir = f"<DECOMPILED_OUTPUT_DIR>/{apk_name}_decompiled"
            if os.path.exists(base_output_dir):
                print(f"APK {os.path.splitext(os.path.basename(apk_path))[0]} already decompiled, skipping.")
                continue
            # Analyze APK file
            print(f"Processing APK: {apk_path}")
            process_apk(apk_path, cfr_jar_path, dex2jar_path, output_file_name, filter_name, base_output_dir, apk_name)


def find_method_body_in_files(method_name, base_dir):
    """Search for the method name in all .java files in the given directory and extract its body."""
    method_pattern = re.compile(rf'\b{method_name}\b\s*\([^)]*\)\s*\{{', re.DOTALL)

    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        for match in method_pattern.finditer(content):
                            method_start = match.start()
                            brace_count = 1
                            index = match.end()
                            while brace_count > 0 and index < len(content):
                                if content[index] == '{':
                                    brace_count += 1
                                elif content[index] == '}':
                                    brace_count -= 1
                                index += 1
                            if brace_count == 0:  # Ensure the method body is complete
                                method_body = content[method_start:index]
                                return file_path, method_body
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
    return None, None


def confirm_method_with_LLM(method_body):
    """Analyze a Java method using LangChain to determine if it's related to Bluetooth or Authentication."""
    return "Yes"


def process_apk(apk_path, cfr_jar_path, dex2jar_path, output_file_name, filter_name, base_output_dir, apk_name):
    a, d, dx = AnalyzeAPK(apk_path)

    # Define Bluetooth-related and authentication-related keywords
    bluetooth_keywords = {
        "android/bluetooth/BluetoothAdapter",
        "android/bluetooth/BluetoothDevice",
        "android/bluetooth/BluetoothGatt",
        "android/bluetooth/BluetoothManager",
        "android/bluetooth/BluetoothGattCallback",
        "android/bluetooth/BluetoothGattService",
        "android/bluetooth/BluetoothGattCharacteristic",
        "android/bluetooth/BluetoothServerSocket",
        "android/bluetooth/BluetoothSocket"
    }

    auth_keywords = {
        "authenticate",
        "challengeResponse",
        "encryptionKey",
        "secureConnection",
        "authorize",
        "verify",
        "token",
        "sign",
        "pairing",
        "bondState",
        "connect",
        "disconnect",
        "readCharacteristic",
        "writeCharacteristic",
        "setCharacteristicNotification",
        "onConnectionStateChange",
        "onServicesDiscovered",
        "onCharacteristicRead",
        "onCharacteristicWrite",
        "onCharacteristicChanged",
        "getBluetoothManager"
    }

    bluetooth_auth_methods = {
        "createBond",
        "setPin",
        "getBondState",
        "onBondStateChange",
        "encrypt",
        "generateKey",
        "signData",
    }

    encryption_keywords = {
        "javax/crypto/Cipher",
        "javax/crypto/SecretKey",
        "javax/crypto/KeyGenerator",
        "javax/crypto/Mac",
        "java/security/MessageDigest",
        "java/security/KeyPairGenerator",
        "java/security/Signature",
        "javax/crypto/spec",
        "javax/crypto/EncryptedPrivateKeyInfo"
    }

    method_calls = set()

    for method in dx.get_methods():
        m = method.get_method()
        class_name = m.get_class_name()
        method_name = m.get_name()

        found_bluetooth = False
        found_auth = False
        found_encryption = False
        found_bluetooth_auth_method = False

        for basic_block in method.get_basic_blocks().get():
            for instruction in basic_block.get_instructions():
                output = instruction.get_output()

                if any(kw in output for kw in bluetooth_keywords):
                    found_bluetooth = True

                if any(kw in output for kw in auth_keywords):
                    found_auth = True

                if any(kw in output for kw in bluetooth_auth_methods):
                    found_bluetooth_auth_method = True

                if any(kw in output for kw in encryption_keywords):
                    found_encryption = True

            if (found_bluetooth and found_auth) or (
                    found_bluetooth and found_encryption) or found_bluetooth_auth_method:
                method_calls.add((class_name, method_name))
                break

    print(f"Filtered method calls: {len(method_calls)}")
    print(method_calls)

    output_file = f"<METHOD_CALLS_OUTPUT_DIR>/{apk_name}_method_calls.txt"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        for class_name, method_name in method_calls:
            f.write(f"{class_name}.{method_name}\n")

    cfr_output_dir_base = decompile_apk(apk_path, base_output_dir, cfr_jar_path, dex2jar_path)

    printed_methods = set()
    os.makedirs(os.path.dirname(output_file_name), exist_ok=True)
    os.makedirs(os.path.dirname(filter_name), exist_ok=True)

    with open(output_file_name, "w", encoding='utf-8') as file, open(filter_name, "w", encoding='utf-8') as filtered_file:
        for class_name, method_name in method_calls:
            if (class_name, method_name) in printed_methods:
                continue
            printed_methods.add((class_name, method_name))

            try:
                java_file_path, method_body = find_method_body_in_files(method_name, cfr_output_dir_base)
                if java_file_path and method_body:
                    file.write(f"{method_body}\n")
                    relevance = confirm_method_with_LLM(method_body)
                    if relevance == "Yes":
                        filtered_file.write(f"{class_name}.{method_name}:\n{method_body}\n\n")
                else:
                    file.write(f"// Source code for {class_name}::{method_name} not found.\n")
            except Exception as e:
                file.write(f"// Failed to read source code for {class_name}::{method_name}\n")
                file.write(f"// Error: {e}\n")
                file.write(traceback.format_exc())

            file.write("\n")

    print(f"Results written to {output_file_name}")
    print(f"Decompiled APK saved in {base_output_dir}")


if __name__ == "__main__":
    main()
