#!/bin/bash

# Check if a command is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 '<command_to_run>'"
    echo "Note: Enclose the entire command in single quotes if it contains shell operators like ||"
    exit 1
fi

# Function to run the command and extract elapsed time
run_command() {
    TIMEFORMAT='%R'  # Set time format to real time in seconds
    { time bash -c "$1" ; } 2>&1
}

# Function to convert comma to dot in decimal numbers
comma_to_dot() {
    echo "$1" | tr ',' '.'
}

# Initialize variables
total_real_time=0
valid_runs=0
runs=1000
output_file="results.txt"

# Run the command multiple times
for ((i=1; i<=runs; i++))
do
    result=$(run_command "$1")
    
    real_time=$(echo "$result" | tail -n 1)  # Get the last line, which should be the time
    real_time=$(comma_to_dot "$real_time")  # Convert comma to dot if necessary
    
    #echo "Raw output from run $i: real_time=$real_time" >&2  # Print raw output for debugging
    
    # Ensure we're dealing with a number
    if [[ "$real_time" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        total_real_time=$(echo "$total_real_time + $real_time" | bc -l)
        valid_runs=$((valid_runs + 1))
    else
        echo "Error in run $i: Invalid output format. real_time: $real_time" >&2
        continue
    fi
    
    # Update progress
    echo -ne "Executing run $i of $runs (Valid runs: $valid_runs)\r"
done
echo -e "\n" # Move to a new line after the progress indicator

# Calculate average
if [ $valid_runs -gt 0 ]; then
    avg_real_time=$(echo "scale=6; $total_real_time / $valid_runs" | bc -l)

    # Prepare the output
    output="Command executed: $1
Total runs attempted: $runs
Valid runs completed: $valid_runs
Average real time: $avg_real_time seconds"

    # Display the output
    echo "$output"

    # Save the output to a file
    echo "$output" > "$output_file"
    echo "Results saved to $output_file"
else
    echo "No valid runs completed. Unable to calculate average."
fi
