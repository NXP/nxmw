# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

import json
import sys
from pathlib import Path

def convert_device_ids(json_file_path):
    json_path = Path(json_file_path)

    if not json_path.exists():
        print(f"Error: File not found -> {json_path}")
        sys.exit(1)

    # Load the JSON file
    with json_path.open("r") as f:
        data = json.load(f)

    # Convert deviceId from decimal to hexadecimal string format with leading zeros
    for entry in data.get("content", []):
        if "deviceId" in entry:
            try:
                decimal_id = int(entry["deviceId"])
                # Determine if it's a 7-byte or 10-byte UID
                if decimal_id <= 0xFFFFFFFFFFFFFF:  # 7-byte max
                    entry["deviceId"] = f"0x{decimal_id:014X}"  # 14 hex digits
                else:  # Assume 10-byte UID
                    entry["deviceId"] = f"0x{decimal_id:020X}"  # 20 hex digits
            except ValueError:
                print(f"Invalid deviceId format: {entry['deviceId']}")

    # Save the modified JSON back to the same file
    with json_path.open("w") as f:
        json.dump(data, f, indent=4)

    print(f"Conversion complete. Updated file: {json_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python convert_deviceid_json.py <path_to_json_file>")
        sys.exit(1)

    convert_device_ids(sys.argv[1])