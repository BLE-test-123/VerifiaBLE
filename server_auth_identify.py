import os
import re
import time
import openai
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from langchain_core.output_parsers import StrOutputParser
os.environ.pop("HTTP_PROXY", None)
os.environ.pop("HTTPS_PROXY", None)
os.environ.pop("ALL_PROXY", None)
os.environ.pop("http_proxy", None)
os.environ.pop("https_proxy", None)
os.environ.pop("all_proxy", None)

os.environ["OPENAI_API_KEY"] = "sk-ja7JFi35iaYyMwICC72bB719EeE84aA1A1F2A531524cEf2d"
os.environ["OPENAI_API_BASE"] = "https://ai-yyds.com/v1"

api_base = os.getenv("OPENAI_API_BASE")
api_key = os.getenv("OPENAI_API_KEY")

class Master:
    def __init__(self):
        self.chatmodel = ChatOpenAI(
            model="chatgpt-4o-latest",
            temperature=0,
            streaming=True,
        )

        self.auth_keywords = []
        # self.output_path = 'extracted_methods.txt'

        self.SYSTEMPL = """You are an expert in Bluetooth security, specializing in analyzing Java code to determine whether it involves Bluetooth authentication and encryption in Bluetooth communication."""

        self.prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    self.SYSTEMPL,
                ),
                (
                    "user",
                    "{input}",
                ),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ],
        )

    def extract_functions(self, java_code):
        """提取Java文件中的所有函数"""
        function_pattern = re.compile(r'(\w+)\s*\(')
        # function_pattern = re.compile(r'\w+\s+\w+\(.*\)\s*{')
        functions = []

        lines = java_code.split('\n')
        inside_method = False
        brace_count = 0
        current_method = ""
        current_method_body = []

        for line in lines:
            if not inside_method:
                match = function_pattern.search(line)
                if match:
                    inside_method = True
                    current_method = match.group(1)
                    current_method_body.append(line)
                    brace_count += line.count('{') - line.count('}')
            else:
                current_method_body.append(line)
                brace_count += line.count('{') - line.count('}')
                if brace_count == 0:
                    inside_method = False
                    functions.append((current_method, '\n'.join(current_method_body)))
                    current_method = ""
                    current_method_body = []

        return functions

    def check_authentication_related(self, function_code):
        """通过大模型判断这个函数是否与身份认证相关"""
        prompt = """Task Objective: Determine whether a given Java function is related to Bluetooth authentication protocols and output a simple "yes" or "no".
                    Criteria:
                        1. Device Connection State Changes: If the function initiates the authentication process after a device successfully connects (e.g., calling an authentication function in onConnectionStateChange), it is related to authentication. Output "yes".
                        2. Device Scanning and Pairing: If the function scans for known devices and triggers a pairing or authentication process (e.g., onLeScan calls initiatePairing), it is related to authentication. Output "yes".
                        3. Characteristic Read/Write: If the function reads or writes characteristics related to authentication (e.g., using authentication UUIDs or encrypted data), it is related to authentication. Output "yes".
                        4. Key Exchange and Encryption: If the function involves encryption or key exchange (e.g., encrypting session keys or exchanging authentication data), it is related to authentication. Output "yes".
                        5. Authentication Logic: If the function directly or indirectly participates in authentication (e.g., handling authentication credentials, verifying identities, generating or validating signatures), it is related to authentication. Output "yes".
                        6. Other Actions: If the function only involves connection, scanning, or unrelated operations, without participating in authentication, encryption, or key exchange, output "no".
                    Output Requirement:
                        1. For each Java function, determine if it is related to authentication and simply output "yes" or "no".
                        2. If the function is related to authentication, whether directly or indirectly, always output "yes".
                        3. Let's think step by step, but the final output only returns "yes" or "no".
                    Given Java Function: {function_code}"""


        chain = ChatPromptTemplate.from_template(prompt) | self.chatmodel | StrOutputParser()

        print(function_code)
        result = chain.invoke({"function_code": function_code})
        print(result.strip().lower()+"\n")
        return 'yes' in result.strip().lower()

    def save_relevant_functions(self, functions, input_file_path):
        """保存与身份认证相关的函数及其函数体"""
        # 获取输入文件名并生成输出文件名
        base_filename = os.path.basename(input_file_path)
        filename_without_extension = os.path.splitext(base_filename)[0]

        output_file_path = f"/home/biwei/Desktop/BLE_LLM/case/filter/{filename_without_extension}_auth.java"
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'w', encoding='utf-8') as file:
            for func_name, func_body in functions:
                # file.write(f"Function: {func_name}\n")
                # file.write(f"Function Body:\n{func_body}\n\n")
                file.write(f"{func_body}\n\n")
        print(f"与身份认证相关的函数已保存到文件: {output_file_path}")

    def process_java_file(self, file_path):

        """处理Java文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                java_code = file.read()
            # with open(example_path, 'r', encoding='utf-8') as file:
            #     example_code = file.read()
        except FileNotFoundError:
            print(f"文件未找到: {file_path}")
            return

        functions = self.extract_functions(java_code)
        relevant_functions = []

        for func_name, func_body in functions:
            if self.check_authentication_related(func_body):
                relevant_functions.append((func_name, func_body))
                time.sleep(10)

        if relevant_functions:
            self.save_relevant_functions(relevant_functions, file_path)
        else:
            base_filename = os.path.basename(file_path)
            filename_without_extension = os.path.splitext(base_filename)[0]
            output_file_path = f"/home/biwei/Desktop/BLE_LLM/case/filter/{filename_without_extension}_auth.java"
            os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
            with open(output_file_path, 'w', encoding='utf-8') as file:
                for func_name, func_body in functions:
                    # file.write(f"Function: {func_name}\n")
                    # file.write(f"Function Body:\n{func_body}\n\n")
                    file.write("No authentication related functions found.")

            print("未找到与身份认证相关的函数。")

if __name__ == "__main__":
    master = Master()

    # 设置Java文件路径
    # java_file_path = 'java/BluetoothRevThread.java'  # 修改为你的文件路径
    java_folder_path = '/home/biwei/Desktop/BLE_LLM/case/filterv2'  # 修改为你的文件路径
    """遍历java/文件夹下的所有Java文件，并进行处理"""
    for root, _, files in os.walk(java_folder_path):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
                # 生成输出文件路径
                base_filename = os.path.basename(file_path)
                filename_without_extension = os.path.splitext(base_filename)[0]
                output_file_path = f"/home/biwei/Desktop/BLE_LLM/case/filterv3/{filename_without_extension}_auth.java"

                # **检查文件是否已经存在**
                if os.path.exists(output_file_path):
                    print(f"已存在: {output_file_path}，跳过处理。")
                    continue
                print(f"处理文件: {file_path}")
                master.process_java_file(file_path)

