"""Run the authors' own McNemar script unchanged, with only its paths repointed.

    python -m repro.run_authors_scripts

src/utilities/mcnemar_analysis.py reads `<script dir>/dashboard/results`, which
does not exist in the reorganised repo (the files live in data/outputs/). We
import the module, override RESULTS_DIR / OUTPUT_FILE and call its entry point,
so the published code itself is what produces results/authors_mcnemar_report.md.
"""
import contextlib
import importlib.util
import io
import sys

from .paths import RESULTS_DIR, SHIPPED_OUTPUTS, SWVULN_DIR


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    sys.stdout.reconfigure(encoding="utf-8")  # the report is in Portuguese; Windows consoles default to a legacy codepage
    RESULTS_DIR.mkdir(exist_ok=True)
    mod = load(SWVULN_DIR / "src" / "utilities" / "mcnemar_analysis.py", "authors_mcnemar")
    mod.RESULTS_DIR = SHIPPED_OUTPUTS
    mod.OUTPUT_FILE = RESULTS_DIR / "authors_mcnemar_report.md"
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        mod.run_analysis()
    (RESULTS_DIR / "authors_mcnemar_stdout.txt").write_text(log.getvalue(), encoding="utf-8")
    summary = mod.OUTPUT_FILE.read_text(encoding="utf-8").split("## Tabela Resumo", 1)[1]
    print("Authors' McNemar summary table (their script, their output file):")
    print(summary.split("## Principais Achados")[0].strip())


if __name__ == "__main__":
    main()
