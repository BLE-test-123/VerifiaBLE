import subprocess
import re

# 定义ProVerif文件路径和命令
pv_file_path = "./pv/smartapplight-0612.pv"
command = ['proverif', pv_file_path]

# 调用ProVerif命令
result = subprocess.run(command, capture_output=True, text=True)

# 合并标准输出和错误输出中的可能的错误信息
output = result.stdout + result.stderr

# 打印原始输出（用于调试）
print("原始输出:")
print(output)

# 检查是否有错误信息
if "Error" in output:
    print('检测到错误输出:')
    print(output)

    # 尝试提取错误行号和字符位置信息
    error_match = re.search(r'line (\d+), character (\d+):\\nError: (.+)', output) or re.search(r'line (\d+), character (\d+):\nError: (.+)', output)
    if not error_match:
        # 如果初步提取失败，尝试直接打印每行内容，帮助分析
        print("未能直接解析错误信息，以下是逐行输出调试信息：")
        for line in output.splitlines():
            print(f"调试行: {line}")
    else:
        line_no = int(error_match.group(1))  # 错误所在行号
        character = int(error_match.group(2))  # 错误所在字符
        error_message = error_match.group(3)  # 错误信息

        print(f"错误位置: 行 {line_no}, 字符 {character}")
        print(f"错误信息: {error_message}")

        # 打开 .pv 文件读取内容
        try:
            with open(pv_file_path, 'r', encoding='utf-8') as file:  # 指定文件编码为 UTF-8
                lines = file.readlines()

            # 打印文件的总行数（调试用）
            print(f"文件总行数: {len(lines)}")

            # 提取错误行及上下文
            start = max(0, line_no - 3)  # 上下文的开始行
            end = min(len(lines), line_no + 2)  # 上下文的结束行

            print("\n错误上下文:")
            for i in range(start, end):
                prefix = '>> ' if i + 1 == line_no else '   '
                print(f"{prefix}{i + 1}: {lines[i].rstrip()}")
        except FileNotFoundError:
            print(f"无法找到文件: {pv_file_path}")
        except UnicodeDecodeError as e:
            print(f"文件编码错误: {str(e)}。尝试使用其他编码格式重新打开文件。")
        except Exception as e:
            print(f"读取文件时发生其他错误: {str(e)}")
else:
    print('标准输出:')
    print(result.stdout)
