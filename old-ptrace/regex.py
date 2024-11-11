import re
import os

def count_arguments(function_signature):
    # Removing comments and stripping whitespace
    cleaned_signature = re.sub(r'/\*.*?\*/', '', function_signature)
    cleaned_signature = cleaned_signature.strip()
    # Extracting the argument list
    args = cleaned_signature.split('(')[1].split(')')[0].strip()
    if args == "void":
        return 0
    else:
        # Counting arguments, considering pointer and commas
        return len(re.findall(r'[\w\s*]+(?:,[\w\s*]+)*', args))

def parse_syscalls(source_directory):
    syscall_pattern = re.compile(r'(asmlinkage\s+[\w\s*]+)\s+sys_(\w+)\s*\(([^)]+)\);')
    syscalls = {}

    for subdir, dirs, files in os.walk(source_directory):
        for filename in files:
            if filename.endswith(".h") or filename in ['syscalls.h', 'syscall.h']:
                file_path = os.path.join(subdir, filename)
                try:
                    with open(file_path, 'r') as file:
                        content = file.read()
                    matches = syscall_pattern.findall(content)
                    for match in matches:
                        syscall_name = match[1]
                        function_signature = match[0] + ' ' + match[1] + '(' + match[2] + ');'
                        arg_count = count_arguments(function_signature)
                        syscalls[syscall_name] = arg_count
                except Exception as e:
                    print(f"Failed to read {file_path}: {e}")

    return syscalls

# Path to the directory containing the Linux kernel source
source_directory = '/path/to/linux/kernel/source'
syscalls = parse_syscalls(source_directory)

# Output the result to a text file
with open('syscall_arg_counts.txt', 'w') as f:
    for syscall, arg_count in syscalls.items():
        f.write(f"{syscall} {arg_count}\n")

print("Syscall argument counts have been written to syscall_arg_counts.txt")
