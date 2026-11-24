# Final presentation script

15-minute slot. Spoken time about 14:25 at ~125 words per minute. Timings are also in each slide's speaker notes.

## Slide 1: Title

*0:55 (0:00–0:55)*

Hi, we're Justun, Siwei and Mengchao. Our project asks: do LLMs really find interprocedural vulnerabilities? We start from a 2026 EASE paper by Lira et al. that reported near-perfect F1 scores for LLM vulnerability detectors. We asked one extra question: what happens if you also show each model the fixed version of the same code? The three numbers on the right are the short answer. Gemini 3 Flash and Claude Haiku 4.5 still flag 97 percent of patched functions. Precision drops from 1.0 to about 0.5 for every model. And adding callers or callees reduced false alarms for only one of the three models we could test pair by pair: GPT-5 Mini.

## Slide 2: Goals: Scores Without False Positives

*1:15 (0:55–2:10)*

Here's the problem. In code review or static-analysis triage, most functions you look at are safe. So a useful detector has to stay quiet on safe code, not just catch bugs. The baseline study can't measure that. Its 451 CVEs are all vulnerable samples. Look at the matrix on the right: with only vulnerable inputs, you can only get true positives and false negatives. False positives and true negatives are never measured. That means precision is 1 by construction, and F1 depends only on recall: 2R over 1 plus R. That's how Claude Haiku 4.5 gets an F1 of 0.988 from a recall of 0.976. The authors acknowledge this in their own limitations section. Our fix is simple: ask about the patched code too. In CVE-2011-1078 in the Linux kernel, for example, the fix adds a single memset line. A detector that really understands the bug should flag the first version and clear the second.

## Slide 3: Goals: Research Questions and Final Scope

*1:10 (2:10–3:20)*

We kept the research questions from our proposal. RQ1: once the fixed versions are added, what are precision, false-alarm rate, MCC and pair accuracy for each model and context? Our hypothesis H1 was that these fall far below the reported F1. RQ2: the paper found that adding callers and callees barely changed recall. We ask whether context helps in a different way, by reducing false alarms. H2 says it should, at least for the stronger models. Since the milestone we added a third question, an error analysis: when a model flags patched code, is it pointing at the patch, at some other code, or reciting a memorised CVE? We narrowed the scope to C, because C++ had only 18 CVEs and Python had too few pairs for statistics. That gives 343 CVEs, 718 vulnerable/fixed pairs across the three context levels, four models and 5,744 model answers.

## Slide 4: System: Paired Evaluation Pipeline

*1:25 (3:20–4:45)*

This is our system. Grey boxes are reused from the authors' replication package; the blue boxes marked NEW are ours. Step 1 is the authors' CVE records, which store the vulnerable and fixed code of each function, plus its callers and callees. Step 2, our pair builder, swaps every target function for its fixed version. Some CVEs have duplicate records, so we pick one deterministically, and we flag pairs where a function was renamed or doesn't line up. Step 3 uses the authors' prompt template unchanged, in three contexts: code only, with callees, and with callers. Our vulnerable prompts are byte-identical to theirs, so any difference comes only from the fixed side. Step 4 is a new runner for OpenAI, Anthropic and Google with the authors' settings, budget caps, checkpoints so a run can resume, and one retry when an answer has no label. Step 5 computes the metrics with bootstrap confidence intervals, McNemar tests with Holm correction, and the false-alarm labels. Everything after step 4 runs offline from saved responses, so our notebook's analysis reruns without API keys.

## Slide 5: System: What We Replicated and What We Changed

*1:30 (4:45–6:15)*

Before trusting new numbers, we checked the reproduction. At the milestone we recomputed all 48 rows of the paper's Tables 4 to 7 exactly from the authors' saved outputs. In our fresh runs the vulnerable side also reproduces: Haiku's vulnerable-only F1 is 0.985, against 0.990 in the paper. Three settings could not be matched, and the table lists them. Anthropic's API no longer accepts a temperature for Haiku 4.5, so it ran at the default. Gemini's default thinking used up the 4,096-token budget before giving a label in 5 of 7 pilot answers, so we used low thinking. And GPT-4.1 Mini ran on an Azure deployment: on the same CVEs its recall was 0.66, against 0.76 in the authors' outputs, so take its numbers with some caution. The other question is whether a fixed function is really safe. Our 30-pair spot check found 28 valid, one valid with a caveat and one misaligned. 17 CVEs pair functions with different names, but excluding them moves no false-alarm rate by more than 1.4 points, and scoring unparsed answers differently moves none by more than 1.9. The runs cost 34 dollars of our 45-dollar budget.

## Slide 6: RQ1: Near-Perfect F1, Yet Patched Code Is Flagged

*1:20 (6:15–7:35)*

Now RQ1: with the fixed code added, what are each model's precision, false-alarm rate, MCC and pair accuracy? Blue is the F1 the paper reports on vulnerable code only. Orange is the share of fixed functions each model still flags. Green is the share of CVEs where the model gets both versions right. For Haiku and Gemini, orange is almost as tall as blue: they flag 96.5 and 97.4 percent of patched functions, and only 2.6 and 1.5 percent of CVEs are right on both sides. GPT-5 Mini is somewhat better, at 87 percent false alarms and 9 percent both right. The ranking flips: GPT-4.1 Mini, the weakest model in the paper, has the fewest false alarms, 56 percent, and the most pairs right, 19 percent. One caution: our GPT-4.1 run said 'vulnerable' less often than the authors' run, which helps both of those numbers. Still, H1 holds for every model. A high vulnerable-only F1 mostly measures a tendency to say 'vulnerable'.

## Slide 7: RQ1: Corrected Table 5 (C, Code-Only)

*1:20 (7:35–8:55)*

Still on RQ1, this is the corrected Table 5 for C, code-only context. Every fixed function a model flags counts as a false positive. Look at the FP column: Haiku flags 331 of 343 fixed functions, Gemini 334 and GPT-5 Mini 299. Precision lands at about 0.5 for every model, so half of all alerts are on patched code, and paired F1 falls to about 0.65. But compare that with a trivial baseline. A model that answers 'vulnerable' to everything gets recall 1, precision 0.5 and F1 0.667. Three of the four models sit right at that baseline. GPT-4.1 Mini has the lowest F1, 0.593, even though it flags the fewest fixed functions, because it misses 118 real bugs. So on paired data, F1 can't tell these models apart. The chart on the right shows what happens to each pair. Orange, both versions flagged, is about 94 percent for Haiku and Gemini, 80 for GPT-5 Mini and 47 for GPT-4.1 Mini. Blue, both right, is small for everyone.

## Slide 8: RQ2: More Context Barely Reduces False Alarms

*1:20 (8:55–10:15)*

RQ2 asks whether giving the model more context, meaning the functions that call the target or the functions it calls, reduces false alarms on fixed code. Each group of bars is one model, and the three bars are code only, plus callees, and plus callers. Lower is better. For Claude Haiku and Gemini, the bars barely move: with or without context, they flag about 95 percent of fixed code. GPT-5 Mini is the one model that changes. On the 179 CVEs that have callers, adding them cuts its false alarms from 85 to 70 percent, and that drop is statistically significant. But there's a catch. On the same CVEs it also catches fewer real bugs, 88 percent down to 80. So the context didn't help it recognise the fix; it just made it answer 'not vulnerable' more often across the board. GPT-4.1 Mini also goes down, from 56 to 45 percent, but we only have its summary numbers, so we couldn't test it. So the answer to RQ2 is: mostly no.

## Slide 9: Why Do Models Flag Code That Is Already Fixed?

*1:50 (10:15–12:05)*

So why do models flag code that's already fixed? We checked all 946 code-only false alarms from the three models we ran, and looked at which code each explanation points at, compared with the lines the patch changed. Two patterns show up. The first is quoting the fix itself and still calling it vulnerable. That's about 28 percent of false alarms. In CVE-2018-8786, the fix widens a counter from 16 to 32 bits; Haiku quotes that exact new line and still calls it an integer overflow. The second, and by far the most common, at about 71 percent, is pointing at unchanged code instead. In CVE-2013-6412, the fix corrects a file-permission calculation; GPT-5 Mini accepts that line, then reports a different problem elsewhere that we couldn't confirm. The table shows the split per model: GPT-5 Mini points at unchanged code most often, Gemini quotes the fix most often. Almost every false alarm cites specific code, so these aren't vague guesses. One caution: this labelling is automatic and agreed with our hand labels 17 times out of 24, so treat the percentages as approximate. Finally, a likely amplifier we inherited is the authors' prompt, whose instructions say 'explain where the vulnerability is located'. We kept it to stay faithful to the paper, so its effect is untested. And it isn't memorisation: the models rarely name the CVE.

## Slide 10: Recommended Future Work

*1:25 (12:05–13:30)*

If we had more time and resources, here is what we would do, roughly in order of cost. One: make the patch visible. Show the model both versions or the diff, and ask whether this specific flaw is still reachable. That's about 100 dollars of API calls and two weeks. Two: verify before alerting. An agent must back each alert with evidence, such as a static-analysis query, a sanitizer run or a proof-of-concept input. That needs containerised builds of around 300 projects, about one engineer-month. Three: calibrate the threshold. Instead of a yes or no, score with log-probabilities or self-consistency and choose an operating point on paired data, using open-weight models on one or two GPUs. Four, the big one: a human-validated paired benchmark covering all languages, PrimeVul and JitVul pairs, and CVEs published after the models' training cutoff, with two security experts per pair. That's about two annotators for six weeks for a thousand pairs. Five: train on pairs, with contrastive fine-tuning of an open code model on vulnerable and fixed versions, about three days on eight A100s.

## Slide 11: Justification for Future Work

*0:55 (13:30–14:25)*

Each of these steps answers a failure we measured. Both-flagged rates of 94 percent, and models quoting the fix itself as the bug, motivate diff-aware prompting. The 71 percent of false alarms that point at unchanged code with unverified claims motivate verification. GPT-5 Mini's context effect was a threshold shift, which motivates calibration. Misaligned pairs, single-reviewer labels and Gemini naming the right CVE motivate a human-validated benchmark with post-cutoff CVEs. And with every MCC near zero, prompting alone barely separates the two versions, which motivates training on pairs. To sum up: once you show the fixed code, today's LLM detectors flag almost everything, and near-perfect F1 on vulnerable-only benchmarks overstates what they can do. Thank you; we're happy to take questions.
