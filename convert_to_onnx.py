import csv, sys

csv.field_size_limit(10**9)          # raise field limit

INPUT  = "benign_dataframe_0.csv"
OUTPUT = "output_only_col2.csv"

with open(INPUT, newline="", encoding="utf-8") as src, \
     open(OUTPUT, "w", newline="", encoding="utf-8") as dst:

    reader = csv.reader(src)
    writer = csv.writer(dst)

    for row in reader:
        if len(row) >= 2:            # guard against short lines
            writer.writerow([row[1]])  # keep 2nd column only
