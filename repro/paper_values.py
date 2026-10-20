"""Numbers transcribed from Lira et al., arXiv:2604.08417v1 (EASE 2026), Tables 4-7.

Accuracy tables: (model, context) -> (N, TP, accuracy, F1)
McNemar table:   (model, comparison) -> dict
"""

MODELS = ["Claude Haiku 4.5", "Gemini 3 Flash", "GPT-5 Mini", "GPT-4.1 Mini"]
CONTEXTS = ["CO", "CC", "CK"]
COMPARISONS = [("CO", "CC"), ("CO", "CK"), ("CC", "CK")]

# Table 5: all languages
TABLE5 = {
    ("Claude Haiku 4.5", "CO"): (451, 440, 0.9756, 0.9877),
    ("Claude Haiku 4.5", "CC"): (237, 232, 0.9789, 0.9893),
    ("Claude Haiku 4.5", "CK"): (221, 216, 0.9774, 0.9886),
    ("Gemini 3 Flash", "CO"): (408, 402, 0.9853, 0.9926),
    ("Gemini 3 Flash", "CC"): (170, 162, 0.9529, 0.9759),
    ("Gemini 3 Flash", "CK"): (149, 143, 0.9597, 0.9795),
    ("GPT-5 Mini", "CO"): (442, 401, 0.9072, 0.9514),
    ("GPT-5 Mini", "CC"): (230, 192, 0.8348, 0.9100),
    ("GPT-5 Mini", "CK"): (217, 168, 0.7742, 0.8727),
    ("GPT-4.1 Mini", "CO"): (451, 341, 0.7561, 0.8611),
    ("GPT-4.1 Mini", "CC"): (237, 128, 0.5401, 0.7014),
    ("GPT-4.1 Mini", "CK"): (221, 153, 0.6923, 0.8182),
}

# Table 6: C only
TABLE6 = {
    ("Claude Haiku 4.5", "CO"): (356, 349, 0.9803, 0.9901),
    ("Claude Haiku 4.5", "CC"): (204, 200, 0.9804, 0.9901),
    ("Claude Haiku 4.5", "CK"): (189, 185, 0.9788, 0.9893),
    ("Gemini 3 Flash", "CO"): (316, 314, 0.9937, 0.9968),
    ("Gemini 3 Flash", "CC"): (142, 136, 0.9577, 0.9784),
    ("Gemini 3 Flash", "CK"): (125, 121, 0.9680, 0.9837),
    ("GPT-5 Mini", "CO"): (348, 315, 0.9052, 0.9502),
    ("GPT-5 Mini", "CC"): (197, 166, 0.8426, 0.9146),
    ("GPT-5 Mini", "CK"): (185, 147, 0.7946, 0.8855),
    ("GPT-4.1 Mini", "CO"): (356, 269, 0.7556, 0.8608),
    ("GPT-4.1 Mini", "CC"): (204, 104, 0.5098, 0.6753),
    ("GPT-4.1 Mini", "CK"): (189, 130, 0.6878, 0.8150),
}

# Table 7: Python only
TABLE7 = {
    ("Claude Haiku 4.5", "CO"): (77, 73, 0.9481, 0.9733),
    ("Claude Haiku 4.5", "CC"): (27, 26, 0.9630, 0.9811),
    ("Claude Haiku 4.5", "CK"): (27, 26, 0.9630, 0.9811),
    ("Gemini 3 Flash", "CO"): (75, 71, 0.9467, 0.9726),
    ("Gemini 3 Flash", "CC"): (24, 22, 0.9167, 0.9565),
    ("Gemini 3 Flash", "CK"): (22, 21, 0.9545, 0.9767),
    ("GPT-5 Mini", "CO"): (77, 69, 0.8961, 0.9452),
    ("GPT-5 Mini", "CC"): (27, 21, 0.7778, 0.8750),
    ("GPT-5 Mini", "CK"): (27, 18, 0.6667, 0.8000),
    ("GPT-4.1 Mini", "CO"): (77, 56, 0.7273, 0.8421),
    ("GPT-4.1 Mini", "CC"): (27, 20, 0.7407, 0.8511),
    ("GPT-4.1 Mini", "CK"): (27, 19, 0.7037, 0.8261),
}

ACCURACY_TABLES = {"Table 5 (all)": (TABLE5, None), "Table 6 (C)": (TABLE6, "C"), "Table 7 (Python)": (TABLE7, "Python")}


def _m(n, chi2, p, alpha, sig, acc1, acc2, phi, effect):
    return dict(n=n, chi2=chi2, p=p, alpha=alpha, sig=sig, acc1=acc1, acc2=acc2, phi=phi, effect=effect)


# Table 4: McNemar, all languages, Holm-Bonferroni over all 12 comparisons
TABLE4 = {
    ("Claude Haiku 4.5", "CO-CC"): _m(237, 0.571, 0.4497, 0.0100, False, 0.9916, 0.9789, 0.074, "Small"),
    ("Claude Haiku 4.5", "CO-CK"): _m(221, 0.083, 0.7728, 0.0250, False, 0.9683, 0.9774, -0.039, "Small"),
    ("Claude Haiku 4.5", "CC-CK"): _m(129, 0.000, 1.0000, 0.0500, False, 0.9690, 0.9767, -0.039, "Small"),
    ("Gemini 3 Flash", "CO-CC"): _m(157, 5.143, 0.0233, 0.0056, False, 1.0000, 0.9554, 0.211, "Medium"),
    ("Gemini 3 Flash", "CO-CK"): _m(140, 1.500, 0.2207, 0.0083, False, 0.9929, 0.9643, 0.138, "Medium"),
    ("Gemini 3 Flash", "CC-CK"): _m(68, 0.500, 0.4795, 0.0125, False, 0.9559, 0.9265, 0.171, "Medium"),
    ("GPT-4.1 Mini", "CO-CC"): _m(237, 37.123, 0.0000, 0.0042, True, 0.7384, 0.5401, 0.404, "Large"),
    ("GPT-4.1 Mini", "CO-CK"): _m(221, 0.103, 0.7488, 0.0167, False, 0.7059, 0.6923, 0.032, "Small"),
    ("GPT-4.1 Mini", "CC-CK"): _m(129, 22.781, 0.0000, 0.0045, True, 0.4651, 0.6822, -0.436, "Large"),
    ("GPT-5 Mini", "CO-CC"): _m(222, 4.654, 0.0310, 0.0063, False, 0.8964, 0.8423, 0.158, "Medium"),
    ("GPT-5 Mini", "CO-CK"): _m(213, 13.081, 0.0003, 0.0050, True, 0.8779, 0.7700, 0.259, "Medium"),
    ("GPT-5 Mini", "CC-CK"): _m(122, 1.895, 0.1687, 0.0071, False, 0.8361, 0.7787, 0.145, "Medium"),
}
