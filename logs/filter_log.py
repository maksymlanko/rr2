state = "ignore"
# Open the file in read mode
#with open("weird_full2.log", "r") as file, open("filter_full.log", "w") as outfile, open("filter_entry.log", "w") as entry, open("filter_jvm.log", "w") as jvm:
with open("example.log", "r") as file, open("filter_full.log", "w") as outfile, open("filter_entry.log", "w") as entry, open("filter_jvm.log", "w") as jvm:
    # Read each line one by one
    for line in file:
        # Print the line (optional: strip() removes leading/trailing whitespace)
        if state == "ignore":
            if "Entrei" in line:
                state = "record"
                #print(line)
                entry.write(line)
                outfile.write(line)
        elif state == "record":
            entry.write(line)
            outfile.write(line)
            if "Sai" in line:
                #state = "recover"
                state = "ignore"
                entry = jvm # does this work?
                #outfile.write(line)
                outfile.write("\nEND OF RECORD\n\n")
        #if state == "recover":


