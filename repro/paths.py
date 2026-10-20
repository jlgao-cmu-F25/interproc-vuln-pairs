"""Locations of the authors' replication package and of our own outputs."""
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Authors' replication package (github.com/kevinwsbr/sw-vuln), pinned so that
# every number we report is computed from the same shipped files.
SWVULN_URL = "https://github.com/kevinwsbr/sw-vuln.git"
SWVULN_COMMIT = "46796d168daf865331b1ca15d763d2e6746bf5a5"

SWVULN_DIR = Path(os.environ.get("SWVULN_DIR", REPO_ROOT / "third_party" / "sw-vuln"))
SWVULN_DATA = SWVULN_DIR / "data"
SHIPPED_OUTPUTS = SWVULN_DATA / "outputs"
PROMPTS_DIR = SWVULN_DATA / "prompts"

RESULTS_DIR = REPO_ROOT / "results"
