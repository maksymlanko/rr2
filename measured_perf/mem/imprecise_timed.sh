#!/bin/bash

# Check if a command is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 '<command_to_run>'"
    echo "Note: Enclose the entire command in single quotes if it contains shell operators like ||"
    exit 1
fi

# Function to run the command and extract data
run_command() {
    #output=$(/bin/time -v bash -c "$1" 2>&1)
    #output=$(/bin/time -v bash -c "$1")
    output=$( { /bin/time -v bash -c "$1" 1>&3; } 2>&1 3>&2 )
    real_time=$(echo "$output" | grep "Elapsed (wall clock) time" | awk '{print $8}')
    max_resident=$(echo "$output" | grep "Maximum resident set size" | awk '{print $6}')
    echo "$real_time $max_resident"
}

# Function to convert time to seconds
to_seconds() {
    IFS=: read -r m s <<< "$1"
    echo "$m*60 + $s" | bc
}

# Initialize variables
total_real_time=0
total_max_resident=0
runs=1000
output_file="results.txt"

# Run the command multiple times
for ((i=1; i<=runs; i++))
do
    result=$(run_command "$1")
    real_time=$(echo $result | cut -d' ' -f1)
    max_resident=$(echo $result | cut -d' ' -f2)
    
    real_time_seconds=$(to_seconds $real_time)
    total_real_time=$(echo "$total_real_time + $real_time_seconds" | bc)
    total_max_resident=$(echo "$total_max_resident + $max_resident" | bc)

    # Update progress
    echo -ne "Executing run $i of $runs\r"
done

echo -e "\n" # Move to a new line after the progress indicator

# Calculate averages
avg_real_time=$(echo "scale=3; $total_real_time / $runs" | bc)
avg_max_resident=$(echo "scale=0; $total_max_resident / $runs" | bc)

# Prepare the output
output="Command executed: $1
Runs completed: $runs
Average real time: $avg_real_time seconds
Average max resident size: $avg_max_resident KB"

# Display the output
echo "$output"

# Save the output to a file
echo "$output" > "$output_file"
echo "Results saved to $output_file"
