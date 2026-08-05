"""MITRE ATT&CK Enterprise STIX 번들을 다운로드한다."""
from __future__ import annotations

import argparse
import pathlib
import urllib.request

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEST_PATH = pathlib.Path("data/stix/enterprise-attack.json")


def download(dest: pathlib.Path = DEST_PATH, force: bool = False) -> pathlib.Path:
    if dest.exists() and not force:
        print(f"이미 존재함, 다운로드 스킵: {dest} (--force로 재다운로드)")
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"다운로드 중: {STIX_URL}")
    with urllib.request.urlopen(STIX_URL) as response:
        data = response.read()

    dest.write_bytes(data)
    print(f"저장 완료: {dest} ({len(data):,} bytes)")
    return dest


def main() -> None:
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Enterprise STIX 번들 다운로드")
    parser.add_argument(
        "--force", action="store_true", help="이미 파일이 있어도 강제로 재다운로드한다"
    )
    args = parser.parse_args()
    download(force=args.force)


if __name__ == "__main__":
    main()
