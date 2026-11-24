"""Audit the fixed side of every C pair against the upstream fix commit.

For each CVE in the paired C set this checks, using the commit patch stored in
the pinned raw_cves record:

* direction: lines the patch adds appear in the fixed functions, lines it
  removes appear in the vulnerable functions (and not the other way round);
* coverage: how much of the patch's code change falls inside the functions the
  model is shown, versus other functions, headers or files;
* recovery: whether every target function has recovered fixed code;
* prompt: the CO fixed prompt really contains the fixed functions and none of
  the removed lines that the vulnerable prompt contains.

Run from the repo root: python tools/audit_fixed_functions.py
Writes results/final/fixed_function_audit.csv and prints a summary.
"""
import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from repro.pairs import _load_raw, _function_rows, PAIRED_PROMPTS  # noqa: E402

CODE_EXT = (".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".y", ".l", ".inc")
TEST_HINT = re.compile(r"(^|/)(tests?|testsuite|fuzz|regress)(/|$)|_test\.|test_", re.I)


def norm(line):
    return re.sub(r"\s+", " ", line).strip()


def substantive(line):
    n = norm(line)
    if len(n) < 4:
        return False
    if n.startswith(("//", "/*", "*", "*/")):
        return False
    return n not in {"} else {", "else {", "break;", "return;", "#endif", "#else", "default:"}


def patch_lines(patch):
    added, removed = [], []
    for raw in (patch or "").splitlines():
        if raw.startswith(("+++", "---", "@@")):
            continue
        if raw.startswith("+") and substantive(raw[1:]):
            added.append(norm(raw[1:]))
        elif raw.startswith("-") and substantive(raw[1:]):
            removed.append(norm(raw[1:]))
    return added, removed


def lines_of(code):
    return {norm(l) for l in code.splitlines() if norm(l)}


def main():
    records = _load_raw()
    root = PAIRED_PROMPTS / "c"
    out = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        cve = folder.name
        rec = records[cve]
        fns = list(_function_rows(rec))
        vuln_lines = set().union(*(lines_of(v) for _, v, _ in fns)) if fns else set()
        fixed_lines = set().union(*(lines_of(f if fn.get("fixed_code_found") and f else v) for fn, v, f in fns)) if fns else set()
        unrecovered = sum(1 for fn, _, f in fns if not (fn.get("fixed_code_found") and f))
        add_in = add_out = rem_in = rem_out = reversed_lines = test_lines = 0
        outside_examples = []
        for fe in rec.get("files", []):
            name = fe.get("file_name", "")
            if not name.lower().endswith(CODE_EXT):
                continue
            added, removed = patch_lines(fe.get("patch"))
            if TEST_HINT.search(name):
                test_lines += len(added) + len(removed)
                continue
            for l in added:
                if l in fixed_lines:
                    add_in += 1
                    if l in vuln_lines - fixed_lines:
                        reversed_lines += 1
                else:
                    add_out += 1
                    if l in vuln_lines:
                        reversed_lines += 1
                    elif len(outside_examples) < 3:
                        outside_examples.append(f"{name}: +{l[:70]}")
            for l in removed:
                if l in vuln_lines:
                    rem_in += 1
                    if l in fixed_lines - vuln_lines:
                        reversed_lines += 1
                else:
                    rem_out += 1
                    if l in fixed_lines:
                        reversed_lines += 1
                    elif len(outside_examples) < 3:
                        outside_examples.append(f"{name}: -{l[:70]}")
        total = add_in + add_out + rem_in + rem_out
        coverage = (add_in + rem_in) / total if total else None

        co_v = (folder / "CO_vulnerable.txt").read_text(encoding="utf-8")
        co_f = (folder / "CO_fixed.txt").read_text(encoding="utf-8")
        nv, nf = norm(co_v), norm(co_f)
        fixed_prompt_lines = lines_of(co_f)
        fixed_in_prompt = all(norm(f if fn.get("fixed_code_found") and f else v) in nf for fn, v, f in fns)
        vuln_in_prompt = all(norm(v) in nv for _, v, _ in fns)
        removed_still_in_fixed_prompt = 0
        for fe in rec.get("files", []):
            if fe.get("file_name", "").lower().endswith(CODE_EXT) and not TEST_HINT.search(fe.get("file_name", "")):
                _, removed = patch_lines(fe.get("patch"))
                removed_still_in_fixed_prompt += sum(1 for l in removed if l in vuln_lines and l not in fixed_lines and l in fixed_prompt_lines)

        if not fixed_in_prompt or not vuln_in_prompt:
            status = "prompt mismatch"
        elif reversed_lines and reversed_lines >= max(1, (add_in + rem_in) // 2):
            status = "possibly reversed"
        elif unrecovered:
            status = "some fixed code not recovered"
        elif coverage is None:
            status = "no code lines in patch"
        elif coverage >= 0.9:
            status = "complete"
        elif coverage >= 0.5:
            status = "mostly inside shown functions"
        else:
            status = "fix mostly outside shown functions"
        out.append({
            "cve": cve, "status": status, "target_functions": len(fns), "unrecovered": unrecovered,
            "patch_lines_in_shown_functions": add_in + rem_in, "patch_lines_elsewhere": add_out + rem_out,
            "coverage": "" if coverage is None else round(coverage, 3), "reversed_lines": reversed_lines,
            "test_file_lines": test_lines, "fixed_prompt_has_fixed_code": fixed_in_prompt,
            "vuln_prompt_has_vuln_code": vuln_in_prompt,
            "removed_lines_left_in_fixed_prompt": removed_still_in_fixed_prompt,
            "outside_examples": " | ".join(outside_examples), "fix_commit_url": rec.get("fix_commit_url", ""),
        })
    dest = ROOT / "results" / "final" / "fixed_function_audit.csv"
    with dest.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(out)
    from collections import Counter
    print(len(out), "CVEs")
    for k, v in Counter(r["status"] for r in out).most_common():
        print(f"  {k}: {v}")
    print("removed lines left in a fixed prompt:", sum(r["removed_lines_left_in_fixed_prompt"] for r in out))
    print("wrote", dest.relative_to(ROOT))


if __name__ == "__main__":
    main()
