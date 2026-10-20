"""Load the model outputs and CVE languages shipped in the authors' package."""
import json

from .paths import PROMPTS_DIR, SHIPPED_OUTPUTS

MODEL_FILES = {
    "Claude Haiku 4.5": "haiku_4_5.json",
    "Gemini 3 Flash": "gemini_3_0_flash.json",
    "GPT-5 Mini": "gpt_5_mini.json",
    "GPT-4.1 Mini": "gpt_4_1_mini.json",
}

# Output-file field for each context level.
CONTEXT_FIELDS = {"CO": "code", "CC": "code_callees", "CK": "code_callers"}

# Folder name under data/prompts/ -> language name used in the paper.
LANGUAGE_DIRS = {"c": "C", "cpp": "C++", "python": "Python"}


def load_outputs(model):
    """{cve_id: {"CO": 0/1/None, "CC": ..., "CK": ...}} for one model.

    None means the context was not generated for that CVE or the model's answer
    had no parsable CLASSIFICATION line; the paper drops both from N.
    """
    with open(SHIPPED_OUTPUTS / MODEL_FILES[model], encoding="utf-8") as f:
        raw = json.load(f)
    return {cve: {ctx: rec.get(field) for ctx, field in CONTEXT_FIELDS.items()} for cve, rec in raw.items()}


def load_all_outputs():
    return {m: load_outputs(m) for m in MODEL_FILES}


def load_explanations(model, context="CO"):
    with open(SHIPPED_OUTPUTS / MODEL_FILES[model], encoding="utf-8") as f:
        raw = json.load(f)
    key = CONTEXT_FIELDS[context] + "_explanation"
    return {cve: rec.get(key) for cve, rec in raw.items()}


def cve_languages():
    """Language of each CVE, taken from the prompt folder it was generated into."""
    langs = {}
    for folder, lang in LANGUAGE_DIRS.items():
        for d in (PROMPTS_DIR / folder).iterdir():
            if d.is_dir() and d.name.startswith("CVE-"):
                langs[d.name] = lang
    return langs


def shipped_language_map():
    with open(SHIPPED_OUTPUTS / "cve_languages.json", encoding="utf-8") as f:
        return json.load(f)
