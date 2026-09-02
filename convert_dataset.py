#!/usr/bin/env python3
"""
convert_dataset.py — Convert the raw Car-Hacking dataset into a clean normalized CSV.

Input files (in dataset /archive/):
  1. normal_run_data.txt   -> CanLogger format:
        Timestamp: 1479121434.850202  ID: 0350  000  DLC: 8  05 28 84 66 6d 00 00 a2
  2. *_dataset.csv (DoS, Fuzzy, gear, RPM) -> CSV without header:
        Timestamp,CAN_ID,DLC,D0[,D1..Dn],R

Output: normalized/ with one file per type, with header:
    Timestamp, CAN_ID, DLC, B0, B1, B2, B3, B4, B5, B6, B7, Label
- B0..B7 are empty if DLC does not cover that byte.
- CAN_ID is always a hex string with 0x prefix (e.g. 0x0350).
- Label = "normal", "DoS", "fuzzy", "gear", "RPM".

Usage: python convert_dataset.py
"""
import os
import csv
import glob
import time

ARCHIVE = os.path.join(os.path.dirname(__file__), "dataset ", "archive")
OUTDIR = os.path.join(os.path.dirname(__file__), "dataset ", "normalized")

COLS = ["Timestamp", "CAN_ID", "DLC"] + [f"B{i}" for i in range(8)] + ["Label"]


def parse_txt_line(line, label, out):
    """Parse a CanLogger txt line and append it to the CSV writer."""
    # Timestamp: 1479121434.850202  ID: 0350  000  DLC: 8  05 28 ...
    try:
        ts_part = line.split("Timestamp:", 1)[1].strip()
        ts, rest = ts_part.split("  ID:", 1)
        ts = ts.strip()
        id_part, rest = rest.split("DLC:", 1)
        can_id = id_part.strip().split()[0]    # first word after ID (hex)
        dlc_str = rest.strip().split()[0]
        # payload: everything to the end (hex bytes)
        payload = rest.strip().split()[1:]
        dlc = int(dlc_str)
        # multi-line safety check
        if len(payload) != dlc:
            return  # invalid, skip
        row = [ts, "0x" + can_id, dlc] + _pad_payload(payload, dlc) + [label]
        out.writerow(row)
    except Exception:
        pass  # skip problematic line


def parse_csv_line(fields, label, out):
    """Parse a CSV line (Timestamp,CAN_ID,DLC,D0...,R)."""
    if len(fields) < 4:
        return
    ts, can_id, dlc = fields[0], fields[1], fields[2]
    payload = fields[3:]  # from D0 onward, but may include 'R' at end
    # if the last field is just 'R' (marker), remove it
    if payload and payload[-1].strip().lower() == "r":
        payload = payload[:-1]
    dlc = int(dlc)
    if len(payload) != dlc:
        return  # inconsistent, skip
    row = [ts, can_id if can_id.startswith("0x") else "0x" + can_id,
           dlc] + _pad_payload(payload, dlc) + [label]
    out.writerow(row)


def _pad_payload(payload, dlc):
    """Pad payload to 8 bytes; missing bytes left as empty strings."""
    out = list(payload[:dlc])
    while len(out) < 8:
        out.append("")
    return out


def convert_txt(filepath, label, outfile):
    start = time.time()
    n = 0
    with open(outfile, "w", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(COLS)
        with open(filepath) as f:
            for line in f:
                if line.strip():
                    parse_txt_line(line, label, w)
                    n += 1
                    if n % 1_000_000 == 0:
                        print(f"  ...{n:,} lines")
    print(f"  {label}: {n:,} rows ({time.time()-start:.1f}s)")

def convert_csv(filepath, label, outfile):
    start = time.time()
    n = 0
    with open(outfile, "w", newline="") as fo:
        w = csv.writer(fo)
        w.writerow(COLS)
        # read in blocks (large files)
        with open(filepath, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for fields in reader:
                if not any(fld.strip() for fld in fields):
                    continue
                parse_csv_line(fields, label, w)
                n += 1
                if n % 1_000_000 == 0:
                    print(f"  ...{n:,} lines")
    print(f"  {label}: {n:,} rows ({time.time()-start:.1f}s)")


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    total_start = time.time()

    # 1. normal txt
    normal = os.path.join(ARCHIVE, "normal_run_data.txt")
    print(f"[normal] {os.path.basename(normal)}")
    convert_txt(normal, "normal", os.path.join(OUTDIR, "normal.csv"))

    # 2. attack csv
    for name in ["DoS", "Fuzzy", "gear", "RPM"]:
        f = os.path.join(ARCHIVE, f"{name}_dataset.csv")
        if os.path.exists(f):
            print(f"[{name}] {os.path.basename(f)}")
            convert_csv(f, name, os.path.join(OUTDIR, f"{name}.csv"))
        else:
            print(f"[{name}] NOT FOUND {f}")

    print(f"\nDONE. Total {time.time()-total_start:.1f}s")
    print("Normalized files in:", os.path.abspath(OUTDIR))


if __name__ == "__main__":
    main()
