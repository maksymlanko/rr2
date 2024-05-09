import re

# Path to your input file
input_file_path = 'syscallent.h'
# Path to your output file
output_file_path = 'syscall_args.h'

# Regular expression to match the pattern in the file
pattern = re.compile(r'\[\s*\d+\]\s*=\s*\{\s*(\d+),')

# List to store the extracted numbers
first_arguments = []

# Open and read the input file
with open(input_file_path, 'r') as file:
    for line in file:
        # Use regular expression to find matches
        match = pattern.search(line)
        if match:
            # Extract the first number and add it to the list
            first_arguments.append(match.group(1))

# Open and write the numbers to the output file
with open(output_file_path, 'w') as file:
    # Start the list format
    file.write('extern int args_len[];\n')
    file.write('int args_len[] = {')
    # Write each number separated by comma except the last
    file.write(', '.join(first_arguments))
    # Close the list and add a semicolon
    file.write('};\n')

print("Numbers extracted and saved to", output_file_path)
