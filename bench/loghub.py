"""Measure false positives on real logs from Loghub (github.com/logpai/loghub).

Loghub is a research collection of logs from 16 systems: SSH, Apache, Hadoop, Spark,
Android, macOS, Windows and more. Almost none of it should contain personal data or
secrets, so nearly every hit is a false positive worth reading.

    uv run python bench/loghub.py            # summary
    uv run python bench/loghub.py --hits     # every hit, with context

The logs are downloaded to bench/.cache/ (gitignored), about 5 MB.
"""

from __future__ import annotations

import argparse
import urllib.request
from collections import Counter
from pathlib import Path

from log_leak.detectors import detect

SYSTEMS = [
    "Android", "Apache", "BGL", "HDFS", "HPC", "Hadoop", "HealthApp", "Linux",
    "Mac", "OpenSSH", "OpenStack", "Proxifier", "Spark", "Thunderbird", "Windows", "Zookeeper",
]  # fmt: skip
URL = "https://raw.githubusercontent.com/logpai/loghub/master/{0}/{0}_2k.log"
CACHE = Path(__file__).parent / ".cache"


def fetch(system: str) -> Path:
    path = CACHE / f"{system}_2k.log"
    if not path.exists():
        CACHE.mkdir(exist_ok=True)
        urllib.request.urlretrieve(URL.format(system), path)
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hits", action="store_true", help="print every hit with context")
    args = parser.parse_args()

    lines = 0
    per_detector: Counter[str] = Counter()
    distinct: set[tuple[str, str]] = set()
    for system in SYSTEMS:
        for line in fetch(system).read_text(errors="replace").splitlines():
            lines += 1
            for h in detect(line):
                value = line[h.start : h.end]
                per_detector[h.detector.id] += 1
                distinct.add((h.detector.id, value))
                if args.hits:
                    print(f"{system:<12} {h.detector.id}  ...{line[max(0, h.start - 50) : h.end + 30]}")

    print(f"{lines} lines from {len(SYSTEMS)} systems")
    print(f"{sum(per_detector.values())} hits, {len(distinct)} distinct values")
    for detector_id, n in sorted(per_detector.items()):
        print(f"  {detector_id}: {n}")


if __name__ == "__main__":
    main()
