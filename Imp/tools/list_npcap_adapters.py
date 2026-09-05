import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.npcap import list_adapters

if __name__ == "__main__":
    adapters = list_adapters()
    if not adapters:
        print("No Npcap adapters found.")
        raise SystemExit(1)

    for i, (name, description) in enumerate(adapters, 1):
        print(f"[{i}] {name}")
        print(f"    {description or '(no description)'}")
