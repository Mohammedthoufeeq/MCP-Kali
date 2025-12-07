from dataclasses import dataclass
from typing import Dict, List


@dataclass
class ScanProfile:
    name: str
    description: str
    nmap_args: List[str]


SCAN_PROFILES: Dict[str, ScanProfile] = {
    "fast": ScanProfile(
        name="fast",
        description="Top 100 ports, minimal scripts.",
        nmap_args=["-T4", "--top-ports", "100", "-sV", "-oX"],
    ),
    "balanced": ScanProfile(
        name="balanced",
        description="Top 1000 ports, version detection, default scripts.",
        nmap_args=["-T3", "--top-ports", "1000", "-sV", "-sC", "-oX"],
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        description="Full TCP scan with version detection and more scripts (CTF/lab).",
        nmap_args=["-T4", "-p-", "-sV", "-sC", "-A", "-oX"],
    ),
    "low-noise": ScanProfile(
        name="low-noise",
        description="Reduced ports and conservative timing (lower intensity).",
        nmap_args=["-T2", "--top-ports", "200", "-sV", "-oX"],
    ),
}


def get_scan_profile(mode: str) -> ScanProfile:
    if mode not in SCAN_PROFILES:
        raise ValueError(f"Unknown scan mode: {mode}")
    return SCAN_PROFILES[mode]
