#!/usr/bin/env python3
import csv
import re
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional

# ----------------------------
# CSV Columns Definition
# ----------------------------
CSV_COLUMNS: List[str] = [
    "Interval", "Device", "Req", "Iss", "End", "Miss", "Inflight",
    "READ_cnt", "READ_wait_avg", "READ_wait_p50", "READ_wait_p95", "READ_wait_p99", "READ_wait_p99.9",
    "READ_dev_avg", "READ_dev_p50", "READ_dev_p95", "READ_dev_p99", "READ_dev_p99.9",
    "WRITE_cnt", "WRITE_wait_avg", "WRITE_wait_p50", "WRITE_wait_p95", "WRITE_wait_p99", "WRITE_wait_p99.9",
    "WRITE_dev_avg", "WRITE_dev_p50", "WRITE_dev_p95", "WRITE_dev_p99", "WRITE_dev_p99.9"
]

# ----------------------------
# Regex Patterns
# ----------------------------
# Header: --- [/dev/nvme1n1] Stats (Req=9676, Iss=9676, End=9689, Miss=14) | Current Inflight: 1 ---
HEADER_RE = re.compile(
    r"^---\s+\[(?P<dev>.+?)\]\s+Stats\s+\(Req=(?P<req>\d+),\s+Iss=(?P<iss>\d+),\s+End=(?P<end>\d+),\s+Miss=(?P<miss>\d+)\)\s+\|\s+Current\s+Inflight:\s+(?P<inflight>\d+)\s+---"
)

# Stats Line: READ   (cnt=9043    ): wait [avg=     1.5] [     1.1      1.1     17.0     31.0] dev [avg=   133.2] [    84.0    152.0   1728.0   2176.0]
STATS_RE = re.compile(
    r"^(?P<type>READ|WRITE)\s+\(cnt=(?P<cnt>\d+)\s*\):\s+"
    r"wait\s+\[avg=\s*(?P<wait_avg>[\d.]+)\]\s+\[\s*(?P<wait_vals>.+?)\s*\]\s+"
    r"dev\s+\[avg=\s*(?P<dev_avg>[\d.]+)\]\s+\[\s*(?P<dev_vals>.+?)\s*\]"
)

def parse_vals(vals_str: str) -> List[str]:
    """Helper to split space-separated values in brackets."""
    return re.split(r"\s+", vals_str.strip())

def parse_one_log(log_path: Path) -> Optional[Path]:
    out_path = log_path.with_suffix(".csv")
    
    rows = []
    current_row = {}
    interval_count = 0
    
    with log_path.open("r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # Match header
            m_header = HEADER_RE.match(line)
            if m_header:
                # Save previous row if it exists and has data
                if current_row and current_row.get("READ_cnt"):
                    rows.append(current_row)
                
                interval_count += 1
                current_row = {col: "" for col in CSV_COLUMNS}
                current_row["Interval"] = str(interval_count)
                current_row["Device"] = m_header.group("dev")
                current_row["Req"] = m_header.group("req")
                current_row["Iss"] = m_header.group("iss")
                current_row["End"] = m_header.group("end")
                current_row["Miss"] = m_header.group("miss")
                current_row["Inflight"] = m_header.group("inflight")
                continue
            
            # Match READ/WRITE stats
            m_stats = STATS_RE.match(line)
            if m_stats:
                stype = m_stats.group("type")
                prefix = f"{stype}_"
                
                current_row[f"{prefix}cnt"] = m_stats.group("cnt")
                current_row[f"{prefix}wait_avg"] = m_stats.group("wait_avg")
                
                wait_vals = parse_vals(m_stats.group("wait_vals"))
                if len(wait_vals) >= 4:
                    current_row[f"{prefix}wait_p50"] = wait_vals[0]
                    current_row[f"{prefix}wait_p95"] = wait_vals[1]
                    current_row[f"{prefix}wait_p99"] = wait_vals[2]
                    current_row[f"{prefix}wait_p99.9"] = wait_vals[3]
                
                current_row[f"{prefix}dev_avg"] = m_stats.group("dev_avg")
                dev_vals = parse_vals(m_stats.group("dev_vals"))
                if len(dev_vals) >= 4:
                    current_row[f"{prefix}dev_p50"] = dev_vals[0]
                    current_row[f"{prefix}dev_p95"] = dev_vals[1]
                    current_row[f"{prefix}dev_p99"] = dev_vals[2]
                    current_row[f"{prefix}dev_p99.9"] = dev_vals[3]
                continue
        
        # Save last row
        if current_row and current_row.get("READ_cnt"):
            rows.append(current_row)

    if not rows:
        print(f"No valid data found in {log_path.name}")
        return None

    with out_path.open("w", newline="") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"[OK] {log_path.name} -> {out_path.name} ({len(rows)} intervals)")
    return out_path

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <log_file_or_dir>")
        sys.exit(1)
        
    generated_csvs = []
    log_dir: Optional[Path] = None

    for arg in sys.argv[1:]:
        p = Path(arg)
        if p.is_file():
            res = parse_one_log(p)
            if res:
                generated_csvs.append(res)
            log_dir = p.parent
        elif p.is_dir():
            log_dir = p
            for log_file in sorted(p.glob("*.lat")):
                res = parse_one_log(log_file)
                if res:
                    generated_csvs.append(res)
            for log_file in sorted(p.glob("*.log")):
                res = parse_one_log(log_file)
                if res:
                    generated_csvs.append(res)

    if generated_csvs and log_dir:
        zip_path = log_dir / "io_lat_results.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for csv_file in generated_csvs:
                zipf.write(csv_file, csv_file.name)
        print(f"\n[DONE] All CSVs zipped into: {zip_path.name}")

if __name__ == "__main__":
    main()
