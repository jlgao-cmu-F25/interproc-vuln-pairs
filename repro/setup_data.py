"""Fetch the authors' replication package at the pinned commit.

    python -m repro.setup_data
"""
import subprocess
import sys

from .paths import SWVULN_COMMIT, SWVULN_DIR, SWVULN_URL


def run(*cmd):
    print("$", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main():
    if not (SWVULN_DIR / ".git").exists():
        SWVULN_DIR.parent.mkdir(parents=True, exist_ok=True)
        run("git", "clone", "--filter=blob:none", SWVULN_URL, str(SWVULN_DIR))
    run("git", "-C", str(SWVULN_DIR), "fetch", "--quiet", "origin", SWVULN_COMMIT)
    run("git", "-C", str(SWVULN_DIR), "checkout", "--quiet", SWVULN_COMMIT)
    head = subprocess.check_output(["git", "-C", str(SWVULN_DIR), "rev-parse", "HEAD"], text=True).strip()
    if head != SWVULN_COMMIT:
        sys.exit(f"expected {SWVULN_COMMIT}, got {head}")
    print(f"sw-vuln ready at {SWVULN_DIR} ({head[:7]})")


if __name__ == "__main__":
    main()
