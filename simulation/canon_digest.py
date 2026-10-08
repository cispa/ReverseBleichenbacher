#!/usr/bin/env python3
"""Canonical digest of a December-format experimentalresults.csv.

Rows are collected in completion order, which the process pool does not fix, so
the file's row order varies between runs of identical code. Sorting by the
simulation index `i` and dropping the pandas row label makes two runs
byte-comparable.
"""
import csv
import hashlib
import sys


def digest(path):
    with open(path) as f:
        reader = csv.reader(f)
        header = next(reader)
        # column 0 is the unnamed pandas index, column 1 is `i`
        rows = [r[1:] for r in reader if len(r) > 1]
    rows.sort(key=lambda r: int(r[0]))
    h = hashlib.sha256()
    h.update((",".join(header[1:]) + "\n").encode())
    for r in rows:
        h.update((",".join(r) + "\n").encode())
    return h.hexdigest(), len(rows)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        d, n = digest(p)
        print(f"{d}  {n} rows  {p}")
