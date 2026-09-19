"""
bench.harness — measurement that reports its own uncertainty.

A benchmark that prints a mean is close to useless: the mean hides the tail, and
the tail is what an operator is paged for. Everything here reports p50/p95/p99
and the sample count, so a reader can tell whether a number is trustworthy.

Two rules this harness enforces:

  · **warm up before measuring.** The first calls pay import, JIT-free bytecode
    caching and allocator warmup, and including them makes a fast thing look
    slow for reasons that will not recur in production.
  · **always measure a baseline.** "The gateway adds 1.2 ms" is a claim about a
    difference, and a difference needs two measurements. Absolute numbers on one
    machine tell you almost nothing.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class Sample:
    name: str
    unit: str
    n: int
    p50: float
    p95: float
    p99: float
    mean: float
    stdev: float
    minimum: float
    maximum: float
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "unit": self.unit, "n": self.n,
                "p50": round(self.p50, 4), "p95": round(self.p95, 4),
                "p99": round(self.p99, 4), "mean": round(self.mean, 4),
                "stdev": round(self.stdev, 4), "min": round(self.minimum, 4),
                "max": round(self.maximum, 4), "note": self.note}

    def line(self) -> str:
        return (f"  {self.name:<38}{self.p50:>9.3f}{self.p95:>9.3f}"
                f"{self.p99:>9.3f}{self.maximum:>9.3f}  {self.unit}")


def _pct(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    k = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[k]


def measure(name: str, fn: Callable[[], Any], *, n: int = 1000,
            warmup: int = 50, unit: str = "µs", note: str = "") -> Sample:
    """Time `fn` n times after a warmup, in microseconds by default."""
    for _ in range(warmup):
        fn()
    scale = 1e6 if unit == "µs" else 1e3
    xs: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * scale)
    return Sample(name=name, unit=unit, n=n, p50=_pct(xs, 0.50),
                  p95=_pct(xs, 0.95), p99=_pct(xs, 0.99),
                  mean=statistics.fmean(xs),
                  stdev=statistics.pstdev(xs) if len(xs) > 1 else 0.0,
                  minimum=min(xs), maximum=max(xs), note=note)


@dataclass
class Comparison:
    """A measurement against a baseline. The delta is the only honest claim."""
    baseline: Sample
    treatment: Sample

    @property
    def overhead_p50(self) -> float:
        return self.treatment.p50 - self.baseline.p50

    @property
    def overhead_p95(self) -> float:
        return self.treatment.p95 - self.baseline.p95

    @property
    def ratio_p50(self) -> float:
        return (self.treatment.p50 / self.baseline.p50) if self.baseline.p50 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"baseline": self.baseline.to_dict(),
                "treatment": self.treatment.to_dict(),
                "overheadP50": round(self.overhead_p50, 4),
                "overheadP95": round(self.overhead_p95, 4),
                "ratioP50": round(self.ratio_p50, 3),
                "unit": self.treatment.unit}

    def line(self) -> str:
        return (f"  {self.treatment.name:<38}"
                f"{self.overhead_p50:>+9.3f}{self.overhead_p95:>+9.3f}"
                f"{self.ratio_p50:>8.2f}x  {self.treatment.unit} over baseline")


def table(samples: list[Sample], title: str) -> str:
    head = (f"\n{title}\n" + "-" * len(title) + "\n"
            f"  {'':<38}{'p50':>9}{'p95':>9}{'p99':>9}{'max':>9}")
    return head + "\n" + "\n".join(s.line() for s in samples)


def comparison_table(cs: list[Comparison], title: str) -> str:
    head = (f"\n{title}\n" + "-" * len(title) + "\n"
            f"  {'':<38}{'Δp50':>9}{'Δp95':>9}{'ratio':>9}")
    return head + "\n" + "\n".join(c.line() for c in cs)


ENVIRONMENT_CAVEAT = """
These numbers come from a containerised CI-class machine over loopback, using
the Python reference implementation. Read them as orders of magnitude, not as a
specification:

  · Loopback removes network latency, which makes the trust layer's RELATIVE
    overhead look larger than it will in production. A call crossing a real
    network pays 1-50 ms of RTT that dwarfs everything measured here.
  · Python is the reference, not the fast path. A Go or Rust gateway would move
    the CPU-bound numbers substantially; the protocol's inherent cost is lower
    than what is measured.
  · Single machine, no contention, no GC pressure from a real workload.

What the numbers are good for: comparing components against each other, and
sizing the per-call overhead against a network RTT budget.
"""
