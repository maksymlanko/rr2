import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages

# Data for the times and memory
commands = ['NI binary', 'JVM', 'rec_rec']
average_times_sec = [0.007349, 0.106375, 0.008397]
memory_usage_kb = [12616, 72688, 24773]

# Convert times to milliseconds (ms) and memory to megabytes (MB)
average_times_ms = [t * 1000 for t in average_times_sec]  # seconds to milliseconds
memory_usage_mb = [m / 1024 for m in memory_usage_kb]  # kilobytes to megabytes

# Sort the data in ascending order of average times
sorted_indices = np.argsort(average_times_ms)
sorted_commands = [commands[i] for i in sorted_indices]
sorted_times = [average_times_ms[i] for i in sorted_indices]
sorted_memory = [memory_usage_mb[i] for i in sorted_indices]

# Set up the plot style
plt.style.use('ggplot')

# Function to add labels on the bars
def add_labels(ax, rects, unit):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height:.3f} {unit}' if height < 10 else f'{height:.1f} {unit}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=12)  # Larger font for bar labels

# Color definitions
colors = ['#FF4D4D', '#6D6D6D', '#FFB74D']  # Strong red for NI binary, Gray for JVM, Orange for rec_rec

# Create a PDF to save the figures
with PdfPages('comparison_graphs.pdf') as pdf:
    
    # First figure for average times
    fig1, ax1 = plt.subplots(figsize=(10, 6))
    width = 0.35
    x = np.arange(len(sorted_commands))
    rects1 = ax1.bar(x, sorted_times, width, color=[colors[i] for i in sorted_indices], label='Average Time')

    ax1.set_xlabel('Command', fontsize=14)  # Larger font for x-axis label
    ax1.set_ylabel('Average Time (ms)', fontsize=14)  # Larger font for y-axis label
    ax1.set_xticks(x)
    ax1.set_xticklabels(sorted_commands, fontsize=14)  # Increased font size for tick labels
    add_labels(ax1, rects1, 'ms')
    pdf.savefig(fig1)  # Save the first figure to the PDF
    plt.close(fig1)    # Close the figure to free up memory

    # Second figure for memory usage
    fig2, ax2 = plt.subplots(figsize=(10, 6))
    rects2 = ax2.bar(x, sorted_memory, width, color=[colors[i] for i in sorted_indices], label='Memory Usage')

    ax2.set_xlabel('Command', fontsize=14)  # Larger font for x-axis label
    ax2.set_ylabel('Average Memory Usage (MB)', fontsize=14)  # Larger font for y-axis label
    ax2.set_xticks(x)
    ax2.set_xticklabels(sorted_commands, fontsize=14)  # Increased font size for tick labels
    add_labels(ax2, rects2, 'MB')
    pdf.savefig(fig2)  # Save the second figure to the PDF
    plt.close(fig2)    # Close the figure to free up memory

# Notify user
print("PDF 'comparison_graphs.pdf' created successfully!")

