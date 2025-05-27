import subprocess
import re

# Define the ProVerif file path and command
pv_file_path = "<PV_FILE_PATH>"
command = ['proverif', pv_file_path]

# Call the ProVerif command
result = subprocess.run(command, capture_output=True, text=True)

# Merge potential error information from stdout and stderr
output = result.stdout + result.stderr

# Print the raw output (for debugging)
print("Raw output:")
print(output)

# Check if there is an error message
if "Error" in output:
    print('Detected error output:')
    print(output)

    # Try to extract error line number and character position
    error_match = re.search(r'line (\d+), character (\d+):\\nError: (.+)', output) or re.search(r'line (\d+), character (\d+):\nError: (.+)', output)
    if not error_match:
        # If initial extraction fails, print each line for further analysis
        print("Failed to parse error information directly. Debug lines below:")
        for line in output.splitlines():
            print(f"Debug line: {line}")
    else:
        line_no = int(error_match.group(1))  # Error line number
        character = int(error_match.group(2))  # Error character position
        error_message = error_match.group(3)  # Error message

        print(f"Error location: line {line_no}, character {character}")
        print(f"Error message: {error_message}")

        # Open the .pv file to read content
        try:
            with open(pv_file_path, 'r', encoding='utf-8') as file:  # Specify UTF-8 encoding
                lines = file.readlines()

            # Print the total number of lines in the file (for debugging)
            print(f"Total number of lines in the file: {len(lines)}")

            # Extract the error line and context
            start = max(0, line_no - 3)  # Start of context
            end = min(len(lines), line_no + 2)  # End of context

            print("\nError context:")
            for i in range(start, end):
                prefix = '>> ' if i + 1 == line_no else '   '
                print(f"{prefix}{i + 1}: {lines[i].rstrip()}")
        except FileNotFoundError:
            print(f"File not found: {pv_file_path}")
        except UnicodeDecodeError as e:
            print(f"File encoding error: {str(e)}. Try opening the file with a different encoding.")
        except Exception as e:
            print(f"An unexpected error occurred while reading the file: {str(e)}")
else:
    print('Standard output:')
    print(result.stdout)
