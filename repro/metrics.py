"""Metrics as defined in Sec. 3.3-3.4 of the paper, reimplemented independently.

Every evaluated function is vulnerable (target = 1), so TN = FP = 0,
precision = 1, accuracy = recall = TP / N and F1 = 2R / (1 + R).
"""
import math
from dataclasses import dataclass

from scipy import stats

ALPHA = 0.05


@dataclass
class Accuracy:
    n: int
    tp: int

    @property
    def accuracy(self):
        return self.tp / self.n if self.n else float("nan")

    @property
    def f1(self):
        r = self.accuracy
        return 2 * r / (1 + r) if self.n else float("nan")


def accuracy(labels):
    """labels: iterable of 0/1/None predictions on vulnerable functions."""
    kept = [int(x) for x in labels if x is not None]
    return Accuracy(n=len(kept), tp=sum(kept))


@dataclass
class McNemar:
    n: int
    a: int  # both correct
    b: int  # only first correct
    c: int  # only second correct
    d: int  # both wrong
    chi2: float
    p: float
    phi: float
    acc1: float
    acc2: float
    alpha: float = float("nan")
    sig: bool = False

    @property
    def effect(self):
        x = abs(self.phi)
        return "Small" if x < 0.1 else "Medium" if x < 0.3 else "Large"


def mcnemar(pairs):
    """pairs: list of (pred1, pred2) on vulnerable functions, both not None.

    Continuity-corrected chi-square, phi = (b - c) / sqrt((b + c) * n).
    """
    n = len(pairs)
    a = sum(1 for x, y in pairs if x == 1 and y == 1)
    b = sum(1 for x, y in pairs if x == 1 and y != 1)
    c = sum(1 for x, y in pairs if x != 1 and y == 1)
    d = n - a - b - c
    if b + c == 0:
        chi2, p, phi = 0.0, 1.0, 0.0
    else:
        chi2 = (abs(b - c) - 1) ** 2 / (b + c)
        p = float(stats.chi2.sf(chi2, df=1))
        phi = (b - c) / math.sqrt((b + c) * n)
    acc1 = (a + b) / n if n else float("nan")
    acc2 = (a + c) / n if n else float("nan")
    return McNemar(n, a, b, c, d, chi2, p, phi, acc1, acc2)


def holm(results, alpha=ALPHA):
    """Holm-Bonferroni in place: rank by p, the k-th smallest gets alpha / (m - k + 1).

    Like the authors' script, each test is judged against its own threshold
    (no step-down stop), which gives the alphas printed in Table 4.
    """
    m = len(results)
    for rank, r in enumerate(sorted(results, key=lambda r: r.p), start=1):
        r.alpha = alpha / (m - rank + 1)
        r.sig = r.p < r.alpha
    return results
