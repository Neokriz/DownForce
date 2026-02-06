# This parser works for the log file formated like the following examples:
# Running Total Compactions: 10, Running L0 Compactions: 1, Running L1 Compactions: 1, Running Ld Compactions: 8
# Running Total Compactions: 9, Running L0 Compactions: 1, Running L1 Compactions: 1, Running Ld Compactions: 7

#!/usr/bin/env python3
import csv
import re
import sys
from pathlib import Path
from typing import Dict, Optional, List
import zipfile

# ----------------------------
# Base columns (your schema + new fields)
# ----------------------------
BASE_COLUMNS: List[str] = [
    # Total L0~L4
    "Total_L0_count","Total_L0_Average","Total_L0_StdDev","Total_L0_p99","Total_L0_P99.9","Total_L0_P99.99",
    "Total_L1_count","Total_L1_Average","Total_L1_StdDev","Total_L1_p99","Total_L1_P99.9","Total_L1_P99.99",
    "Total_L2_count","Total_L2_Average","Total_L2_StdDev","Total_L2_p99","Total_L2_P99.9","Total_L2_P99.99",
    "Total_L3_count","Total_L3_Average","Total_L3_StdDev","Total_L3_p99","Total_L3_P99.9","Total_L3_P99.99",
    "Total_L4_count","Total_L4_Average","Total_L4_StdDev","Total_L4_p99","Total_L4_P99.9","Total_L4_P99.99",

    # Background L0~L4
    "Background_L0_count","Background_L0_Average","Background_L0_StdDev","Background_L0_p99","Background_L0_P99.9","Background_L0_P99.99",
    "Background_L1_count","Background_L1_Average","Background_L1_StdDev","Background_L1_p99","Background_L1_P99.9","Background_L1_P99.99",
    "Background_L2_count","Background_L2_Average","Background_L2_StdDev","Background_L2_p99","Background_L2_P99.9","Background_L2_P99.99",
    "Background_L3_count","Background_L3_Average","Background_L3_StdDev","Background_L3_p99","Background_L3_P99.9","Background_L3_P99.99",
    "Background_L4_count","Background_L4_Average","Background_L4_StdDev","Background_L4_p99","Background_L4_P99.9","Background_L4_P99.99",

    # User L0~L4
    "User_L0_count","User_L0_Average","User_L0_StdDev","User_L0_p99","User_L0_P99.9","User_L0_P99.99",
    "User_L1_count","User_L1_Average","User_L1_StdDev","User_L1_p99","User_L1_P99.9","User_L1_P99.99",
    "User_L2_count","User_L2_Average","User_L2_StdDev","User_L2_p99","User_L2_P99.9","User_L2_P99.99",
    "User_L3_count","User_L3_Average","User_L3_StdDev","User_L3_p99","User_L3_P99.9","User_L3_P99.99",
    "User_L4_count","User_L4_Average","User_L4_StdDev","User_L4_p99","User_L4_P99.9","User_L4_P99.99",

    # Level sizes (MB)
    "L0_size","L1_size","L2_size","L3_size","L4_size","Total_size",

    # Running compactions at interval
    "Total Compactions","L0 Compaction","L1 Compaction","Ld Compaction",

    # NEW: thread throughput (interval + cumulative avg)
    "W_thr0_ops_sec","W_thr0_ops_sec_avg",
    "R_thr1_ops_sec","R_thr1_ops_sec_avg",
]

# ----------------------------
# Validation columns (bucket-sum based)
# ----------------------------
VALID_COLUMNS: List[str] = []
for lv in range(5):
    VALID_COLUMNS += [
        f"V_L{lv}_tot_cnt_from_buckets",
        f"V_L{lv}_usr_cnt_from_buckets",
        f"V_L{lv}_bg_cnt_from_buckets",
        f"V_L{lv}_cnt_delta",
        f"V_L{lv}_cnt_ok",
        f"V_L{lv}_count_matches_buckets",
    ]
VALID_COLUMNS += [
    "V_all_tot_cnt_from_buckets",
    "V_all_usr_cnt_from_buckets",
    "V_all_bg_cnt_from_buckets",
    "V_all_cnt_delta",
    "V_all_cnt_ok",
    "V_all_count_matches_buckets",
]

CSV_COLUMNS: List[str] = BASE_COLUMNS + VALID_COLUMNS

# ----------------------------
# Regex patterns
# ----------------------------
RWW_START_RE = re.compile(r"readwhilewriting", re.IGNORECASE)

HIST_HEADER_RE = re.compile(
    r"^\*\*\s*(?P<kind>File|User File|Background File)\s+Read Latency Histogram By Level\s+\(Interval\)\s+\[default\]\s*\*\*\s*$"
)

LEVEL_HEADER_RE = re.compile(
    r"^\*\*\s*Level\s+(?P<level>\d+)\s+(?:user\s+|background\s+)?read latency histogram\s+\(micros\):\s*$",
    re.IGNORECASE
)

COUNT_LINE_RE = re.compile(
    r"^\s*Count:\s*(?P<count>\d+)\s+Average:\s*(?P<avg>[-+]?\d+(?:\.\d+)?)\s+StdDev:\s*(?P<std>[-+]?\d+(?:\.\d+)?)\s*$"
)

PERCENTILES_RE = re.compile(r"^\s*Percentiles:\s*(?P<rest>.+?)\s*$")

LEVEL_STATS_HEADER_RE = re.compile(r"^\*\*\s*Level Stats at Interval\s*\*\*\s*$")
LEVEL_STATS_ROW_RE = re.compile(r"^\s*(?P<level>\d+)\s+(?P<files>\d+)\s+(?P<size>\d+)\s*$")

BUCKET_RE = re.compile(r"^\(\s*[-+]?\d+(?:\.\d+)?\s*,\s*[-+]?\d+(?:\.\d+)?\s*\]\s+(?P<cnt>\d+)\s+")
STARSTAR_LINE_RE = re.compile(r"^\*\*")

AGG_HIST_RE = re.compile(r"^===\s*Aggregated Interval Histogram", re.IGNORECASE)
RUNNING_COMPACTIONS_RE = re.compile(
    r"^Running Total Compactions:\s*(?P<tot>\d+)(?:\s*\(Jobs:\s*\d+,\s*Sub:\s*\d+\))?\s*,\s*"
    r"Running L0 Compactions:\s*(?P<l0>\d+)\s*,\s*"
    r"Running L1 Compactions:\s*(?P<l1>\d+)\s*,\s*"
    r"Running Ld Compactions:\s*(?P<ld>\d+)\s*$"
)

# NEW: thread performance line (captures both current interval and cumulative avg ops/sec)
THREAD_LINE_RE = re.compile(
    r"^\d{4}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\s+\.{3}\s+thread\s+(?P<tid>\d+):\s+"
    r"\([^)]*\)\s+ops\s+and\s+\((?P<ops_sec>[-+]?\d+(?:\.\d+)?),\s*(?P<ops_sec_avg>[-+]?\d+(?:\.\d+)?)\)\s+ops/second\s+in\s+\([^)]*\)\s+seconds\s*$"
)

# ----------------------------
# Helpers
# ----------------------------
def kind_to_prefix(kind: str) -> str:
    if kind == "File":
        return "Total"
    if kind == "User File":
        return "User"
    if kind == "Background File":
        return "Background"
    raise ValueError(f"Unknown kind: {kind}")

def parse_percentiles(rest: str) -> Dict[str, str]:
    tokens = rest.split()
    out: Dict[str, str] = {}
    i = 0
    while i < len(tokens) - 1:
        key = tokens[i].rstrip()
        val = tokens[i + 1].rstrip()
        if key.endswith(":"):
            k = key[:-1]
            if k in ("P99", "P99.9", "P99.99"):
                out[k] = val
                i += 2
                continue
        i += 1
    return {"p99": out.get("P99",""), "P99.9": out.get("P99.9",""), "P99.99": out.get("P99.99","")}

def empty_row() -> Dict[str, str]:
    return {c: "" for c in CSV_COLUMNS}

def row_has_any_data(row: Dict[str, str]) -> bool:
    return any(row.get(c, "") != "" for c in BASE_COLUMNS)

def interval_complete(seen_total: bool, seen_user: bool, seen_bg: bool, seen_stats: bool) -> bool:
    return seen_total and seen_user and seen_bg and seen_stats

def safe_int(x: str) -> Optional[int]:
    if x is None:
        return None
    x = x.strip()
    if x == "":
        return None
    try:
        return int(x)
    except ValueError:
        return None

# ----------------------------
# Core parser per file
# ----------------------------
def parse_one_log_to_csv(log_path: Path) -> Path:
    out_path = log_path.with_name(f"read-latency_RWW-{log_path.stem}.csv")

    in_rww = False
    current_row = empty_row()

    current_prefix: Optional[str] = None
    current_level: Optional[int] = None

    seen_total = False
    seen_user = False
    seen_bg = False
    seen_stats = False

    lvl_sizes = {0: "", 1: "", 2: "", 3: "", 4: ""}
    in_level_stats = False

    bucket_sums: Dict[str, Dict[int, int]] = {
        "Total": {lv: 0 for lv in range(5)},
        "User": {lv: 0 for lv in range(5)},
        "Background": {lv: 0 for lv in range(5)},
    }

    expect_running_compactions_line = False

    def reset_interval_state() -> None:
        nonlocal current_row, current_prefix, current_level
        nonlocal seen_total, seen_user, seen_bg, seen_stats
        nonlocal lvl_sizes, in_level_stats, bucket_sums
        nonlocal expect_running_compactions_line
        current_row = empty_row()
        current_prefix = None
        current_level = None
        seen_total = seen_user = seen_bg = seen_stats = False
        lvl_sizes = {0: "", 1: "", 2: "", 3: "", 4: ""}
        in_level_stats = False
        bucket_sums = {
            "Total": {lv: 0 for lv in range(5)},
            "User": {lv: 0 for lv in range(5)},
            "Background": {lv: 0 for lv in range(5)},
        }
        expect_running_compactions_line = False

    def fill_validation_columns(row: Dict[str, str]) -> None:
        all_tot = all_usr = all_bg = 0
        all_delta = 0

        for lv in range(5):
            tot_b = bucket_sums["Total"][lv]
            usr_b = bucket_sums["User"][lv]
            bg_b = bucket_sums["Background"][lv]
            delta = tot_b - (usr_b + bg_b)
            ok = 1 if delta == 0 else 0

            row[f"V_L{lv}_tot_cnt_from_buckets"] = str(tot_b)
            row[f"V_L{lv}_usr_cnt_from_buckets"] = str(usr_b)
            row[f"V_L{lv}_bg_cnt_from_buckets"] = str(bg_b)
            row[f"V_L{lv}_cnt_delta"] = str(delta)
            row[f"V_L{lv}_cnt_ok"] = str(ok)

            cnt_val = safe_int(row.get(f"Total_L{lv}_count", ""))
            if cnt_val is None:
                row[f"V_L{lv}_count_matches_buckets"] = ""
            else:
                row[f"V_L{lv}_count_matches_buckets"] = ("1" if cnt_val == tot_b else "0")

            all_tot += tot_b
            all_usr += usr_b
            all_bg += bg_b
            all_delta += delta

        row["V_all_tot_cnt_from_buckets"] = str(all_tot)
        row["V_all_usr_cnt_from_buckets"] = str(all_usr)
        row["V_all_bg_cnt_from_buckets"] = str(all_bg)
        row["V_all_cnt_delta"] = str(all_delta)
        row["V_all_cnt_ok"] = ("1" if all_delta == 0 else "0")

        flags = []
        for lv in range(5):
            v = row.get(f"V_L{lv}_count_matches_buckets", "")
            if v != "":
                flags.append(v == "1")
        row["V_all_count_matches_buckets"] = ("1" if (len(flags) > 0 and all(flags)) else ("0" if len(flags) > 0 else ""))

    def finalize_row() -> Dict[str, str]:
        nonlocal current_row, lvl_sizes
        total_size = 0
        any_size = False
        for lv in range(5):
            s = lvl_sizes.get(lv, "")
            current_row[f"L{lv}_size"] = s
            if s != "":
                any_size = True
                total_size += int(s)
        current_row["Total_size"] = str(total_size) if any_size else ""
        fill_validation_columns(current_row)
        return current_row

    with log_path.open("r", errors="replace") as f, out_path.open("w", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for line in f:
            line = line.rstrip("\n")

            if not in_rww:
                if RWW_START_RE.search(line):
                    in_rww = True
                continue

            # thread performance lines (can appear between intervals)
            mt = THREAD_LINE_RE.match(line)
            if mt:
                tid = int(mt.group("tid"))
                ops_sec = mt.group("ops_sec")
                ops_sec_avg = mt.group("ops_sec_avg")
                if tid == 0:
                    current_row["W_thr0_ops_sec"] = ops_sec
                    current_row["W_thr0_ops_sec_avg"] = ops_sec_avg
                elif tid == 1:
                    current_row["R_thr1_ops_sec"] = ops_sec
                    current_row["R_thr1_ops_sec_avg"] = ops_sec_avg
                continue

            # Aggregated Interval Histogram + running compactions
            if expect_running_compactions_line:
                if line.strip() == "":
                    continue
                mrc = RUNNING_COMPACTIONS_RE.match(line)
                if mrc:
                    current_row["Total Compactions"] = mrc.group("tot")
                    current_row["L0 Compaction"] = mrc.group("l0")
                    current_row["L1 Compaction"] = mrc.group("l1")
                    current_row["Ld Compaction"] = mrc.group("ld")
                expect_running_compactions_line = False
                continue

            if AGG_HIST_RE.match(line):
                expect_running_compactions_line = True
                continue

            # Level stats block
            if in_level_stats:
                if STARSTAR_LINE_RE.match(line) and not LEVEL_STATS_HEADER_RE.match(line):
                    in_level_stats = False
                    seen_stats = True
                    # fallthrough
                else:
                    mrow = LEVEL_STATS_ROW_RE.match(line)
                    if mrow:
                        lv = int(mrow.group("level"))
                        sz = mrow.group("size")
                        if 0 <= lv <= 4:
                            lvl_sizes[lv] = sz
                    continue

            # Histogram group header
            mh = HIST_HEADER_RE.match(line)
            if mh:
                kind = mh.group("kind")
                prefix = kind_to_prefix(kind)

                # interval boundary: new Total header begins next interval
                if prefix == "Total" and seen_total:
                    if interval_complete(seen_total, seen_user, seen_bg, seen_stats) and row_has_any_data(current_row):
                        writer.writerow(finalize_row())
                    reset_interval_state()
                    prefix = "Total"

                current_prefix = prefix
                current_level = None

                if prefix == "Total":
                    seen_total = True
                elif prefix == "User":
                    seen_user = True
                elif prefix == "Background":
                    seen_bg = True
                continue

            # Level Stats header
            if LEVEL_STATS_HEADER_RE.match(line):
                in_level_stats = True
                lvl_sizes = {0: "", 1: "", 2: "", 3: "", 4: ""}
                continue

            # Level header
            mlv = LEVEL_HEADER_RE.match(line)
            if mlv and current_prefix is not None:
                current_level = int(mlv.group("level"))
                continue

            # Bucket lines (validation)
            if current_prefix is not None and current_level is not None and 0 <= current_level <= 4:
                mb = BUCKET_RE.match(line)
                if mb:
                    bucket_sums[current_prefix][current_level] += int(mb.group("cnt"))
                    continue

            # Count / Percentiles
            if current_prefix is not None and current_level is not None and 0 <= current_level <= 4:
                mc = COUNT_LINE_RE.match(line)
                if mc:
                    lv = current_level
                    p = current_prefix
                    current_row[f"{p}_L{lv}_count"] = mc.group("count")
                    current_row[f"{p}_L{lv}_Average"] = mc.group("avg")
                    current_row[f"{p}_L{lv}_StdDev"] = mc.group("std")
                    continue

                mp = PERCENTILES_RE.match(line)
                if mp:
                    lv = current_level
                    p = current_prefix
                    perc = parse_percentiles(mp.group("rest"))
                    current_row[f"{p}_L{lv}_p99"] = perc["p99"]
                    current_row[f"{p}_L{lv}_P99.9"] = perc["P99.9"]
                    current_row[f"{p}_L{lv}_P99.99"] = perc["P99.99"]
                    continue

        # EOF flush (complete only)
        if interval_complete(seen_total, seen_user, seen_bg, seen_stats) and row_has_any_data(current_row):
            writer.writerow(finalize_row())

    return out_path

# ----------------------------
# Main (with ZIP)
# ----------------------------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} ./log_dir", file=sys.stderr)
        sys.exit(2)

    log_dir = Path(sys.argv[1])
    if not log_dir.is_dir():
        print(f"ERROR: not a directory: {log_dir}", file=sys.stderr)
        sys.exit(2)

    log_files = sorted(log_dir.glob("*.log"))
    if not log_files:
        print(f"No .log files in {log_dir}", file=sys.stderr)
        sys.exit(1)

    generated_csvs = []
    for lf in log_files:
        out_csv = parse_one_log_to_csv(lf)
        generated_csvs.append(out_csv)
        print(f"[OK] {lf.name} -> {out_csv.name}")

    if generated_csvs:
        zip_path = log_dir / "read-latency_results.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for csv_file in generated_csvs:
                zipf.write(csv_file, csv_file.name)
        print(f"\n[DONE] All CSVs zipped into: {zip_path.name}")

if __name__ == "__main__":
    main()
