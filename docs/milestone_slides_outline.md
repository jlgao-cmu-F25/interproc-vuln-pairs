# Milestone slides + video: outline (draft)

The video follows the proposal's demo plan: **load shipped outputs → recompute Tables 4–7 → compare to the paper → live re-run on 50 C functions.** Screen-record `notebooks/milestone_reproduction.ipynb` while it runs.

1. **Title + recap (15 s).** We add the fixed version of each CVE to Lira et al.'s benchmark so false positives can be measured. Today's goal is the reproduction.
2. **Step 1: code running.**
   - Pinned the authors' repo at `46796d1`.
   - Their McNemar script ran once two path constants were repointed (D4).
   - There was no requirements.txt and the prompt-folder paths were broken, so we wrote our own loader.
3. **Step 2: Tables 4–7.**
   - 48/48 rows match exactly: N, TP, accuracy, F1, χ², p, Holm α, φ.
   - Show the headline CO F1 table (paper vs. ours, all "yes").
4. **Discrepancy log (the interesting slide).**
   - D2: answers without a label are dropped from N. Gemini 3 Flash has 43/451 CO and about 30% CC/CK unparsed; counted as misses, CO accuracy goes 0.985 → 0.891. This is the reason our paired study counts "no label after a retry" as wrong.
   - D3: GPT-5 Mini ran at temperature 1, not 0.
   - D1: 509 vs. 451 CVEs (Java prompts were never run).
   - D6: C++ minimum N is 2, not 1 (wording only).
5. **Step 3: live re-run.**
   - GPT-4.1 Mini, 50 C, CO, seed 795.
   - Shipped accuracy 0.76 vs. ours ___. Agreement ___%. Cost $___.
6. **Next.** Pair builder (429 pairs) → paired evaluation (RQ1/RQ2) → false-alarm analysis. Due Nov 27.
