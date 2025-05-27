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
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]  # Extract the APK name without extension

    dex_output_dir = os.path.join(base_output_dir, "dex_files")  # Directory to extract DEX files
    jar_output_dir_base = os.path.join(base_output_dir, "jar_files")  # Base directory to store JAR files
    cfr_output_dir_base = os.path.join(base_output_dir, "cfr_files")  # Base output directory for CFR

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
    cfr_jar_path = "/usr/local/bin/software-cfr/cfr.jar"
    dex2jar_path = "/usr/local/bin/dex2jar-2.0/d2j-dex2jar.sh"
    apk_folder = "/home/biwei/Desktop/data2020/Androzoo/Benign/2020/BLE_filter"


    if not os.path.exists(apk_folder):
        print(f"APK folder does not exist: {apk_folder}")
        return

    for apk_file in os.listdir(apk_folder):
        if apk_file.endswith(".apk"):
            apk_path = os.path.join(apk_folder, apk_file)
            apk_name = os.path.splitext(os.path.basename(apk_path))[0]
            output_file_name = f"/home/biwei/Desktop/BLE_LLM/ble_functions/data2020/{apk_name}_OpenAI-v2-encrypt-folder-ccc.java"
            filter_name = f"/home/biwei/Desktop/BLE_LLM/data2020/filter/{apk_name}_OpenAI-v2-encrypt-folder-ccc-filter.java"
            base_output_dir = f"/home/biwei/Desktop/BLE_LLM/decompiled_apk/data2020/{apk_name}_decompiled"
            if os.path.exists(base_output_dir):
                print(f"APK {os.path.splitext(os.path.basename(apk_path))[0]} already decompiled, skipping.")
                # exit()
                continue
            # Analyze APK file
            print(f"Processing APK: {apk_path}")
            process_apk(apk_path, cfr_jar_path, dex2jar_path, output_file_name, filter_name, base_output_dir,apk_name)

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
    # chatmodel = ChatOpenAI(
    #     model="gpt-4o-2024-05-13",
    #     temperature=0,
    #     streaming=True,
    # )
    # prompt = f"If the following function is related to Bluetooth data flow or device authentication, just answer yes, if not, answer no. The following function is as follows:\n\n{method_body}"
    # chain = ChatPromptTemplate.from_template(prompt) | chatmodel | StrOutputParser()
    # result = chain.invoke(method_body)

    # prompt = ChatPromptTemplate.from_template("If the following function is related to Bluetooth data flow or device authentication, just answer yes, if not, answer no. The following function is as follows:{method_body}")
    # model = ChatOpenAI(model="gpt-4")
    # output_parser = StrOutputParser()
    #
    # chain = prompt | model | output_parser
    #
    # result = chain.invoke({"method_body": method_body})

    return "Yes"

def process_apk(apk_path, cfr_jar_path, dex2jar_path, output_file_name, filter_name, base_output_dir,apk_name):

    # prompt = ChatPromptTemplate.from_template("给我讲一个关于 {topic}的笑话")
    # model = ChatOpenAI(model="gpt-4")
    # output_parser = StrOutputParser()
    #
    # chain = prompt | model | output_parser
    #
    # print(chain.invoke({"topic": "冰激凌"}))
    # 分析APK文件

    a, d, dx = AnalyzeAPK(apk_path)

    # 定义与蓝牙数据流相关和身份认证相关的关键词
    # bluetooth_keywords = {
    #     "android/bluetooth/BluetoothAdapter",
    #     "android/bluetooth/BluetoothDevice",
    #     "android/bluetooth/BluetoothGatt",
    #     "android/bluetooth/BluetoothManager",
    #     "android/bluetooth/BluetoothGattCallback",
    #     "android/bluetooth/BluetoothGattService",
    #     "android/bluetooth/BluetoothGattCharacteristic"
    # }
    # auth_keywords = {"authenticate", "login", "verify", "authorization", "auth"}

    # Define Bluetooth-related and authentication-related keywords
    # 关键 API 关键词（蓝牙 + 认证）
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

    # 蓝牙身份认证相关的关键函数
    bluetooth_auth_methods = {
        "createBond",
        "setPin",
        "getBondState",
        "onBondStateChange",
        "encrypt",
        "generateKey",
        "signData",
    }

    # 加密相关关键词（但必须和蓝牙同时出现）
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

    # 记录符合要求的方法
    method_calls = set()

    # 遍历所有方法
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

                # 匹配蓝牙 API
                if any(kw in output for kw in bluetooth_keywords):
                    found_bluetooth = True

                # 匹配身份认证相关 API
                if any(kw in output for kw in auth_keywords):
                    found_auth = True

                # 匹配蓝牙身份认证相关的函数
                if any(kw in output for kw in bluetooth_auth_methods):
                    found_bluetooth_auth_method = True

                # 匹配加密 API
                if any(kw in output for kw in encryption_keywords):
                    found_encryption = True

            # **只记录真正涉及蓝牙和（认证或加密）**的函数
            if (found_bluetooth and found_auth) or (
                    found_bluetooth and found_encryption) or found_bluetooth_auth_method:
                method_calls.add((class_name, method_name))
                break  # 结束当前方法的遍历

    print(f"Filtered method calls: {len(method_calls)}")
    print(method_calls)

    """Save method calls information to a file named after the APK."""
    output_file = f"/home/biwei/Desktop/BLE_LLM/method_calls/2020/{apk_name}_method_calls.txt"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        for class_name, method_name in method_calls:
            f.write(f"{class_name}.{method_name}\n")

    # 反编译APK文件
    cfr_output_dir_base = decompile_apk(apk_path, base_output_dir, cfr_jar_path, dex2jar_path)

    # 记录已经打印的方法体，防止重复
    printed_methods = set()
    os.makedirs(os.path.dirname(output_file_name), exist_ok=True)
    os.makedirs(os.path.dirname(filter_name), exist_ok=True)
    # 打印和记录结果
    with open(output_file_name, "w", encoding='utf-8') as file, open(filter_name, "w",encoding='utf-8') as filtered_file:
        for class_name, method_name in method_calls:
            if (class_name, method_name) in printed_methods:
                continue
            printed_methods.add((class_name, method_name))

            try:
                # 使用方法名在反编译后的文件中查找源代码

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

    # pv_file_path = f"./analysis_results/{os.path.splitext(os.path.basename(apk_path))[0]}_bluetooth_filter.pv"
    #
    # # 定义ProVerif的命令行命令
    # command = ['proverif', pv_file_path]
    #
    # # 调用ProVerif命令
    # result = subprocess.run(command, capture_output=True, text=True)
    #
    # # 打印ProVerif的输出
    # print('标准输出:')
    # print(result.stdout)
    # print('错误输出:')
    # print(result.stderr)

    print(f"Results written to {output_file_name}")

    print(f"Decompiled APK saved in {base_output_dir}")


if __name__ == "__main__":
    main()
