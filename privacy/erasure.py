"""
privacy.erasure — handle a subject's request, honestly.

An erasure response has to say three things, and most implementations manage
only the first: what was erased, what was **not**, and on what lawful basis it
was kept and when that lapses. "No" without a basis and an end date is not a
defensible answer to a data subject, and neither is a silent partial deletion
that leaves them believing more was removed than actually was.

    report = erase(ring, subject="sub_ab12", held=[...])
    report.erased        # classes actually shredded
    report.retained      # classes kept, each with a reason and an expiry date
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .retention import CLASSES, classify, erasable, RetentionError
from .shredding import KeyRing, ShredError


@dataclass
class Retained:
    data_class: str
    reason: str
    basis: str
    erased_automatically_at: int

    def to_dict(self) -> dict[str, Any]:
        return {"dataClass": self.data_class, "reason": self.reason,
                "basis": self.basis,
                "erasedAutomaticallyAt": self.erased_automatically_at,
                "erasedAutomaticallyOn": time.strftime(
                    "%Y-%m-%d", time.gmtime(self.erased_automatically_at))}


@dataclass
class ErasureReport:
    subject: str
    requested_at: int
    erased: list[str] = field(default_factory=list)
    retained: list[Retained] = field(default_factory=list)
    key_destroyed: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True only when nothing at all was held back."""
        return not self.retained

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "requestedAt": self.requested_at,
                "erased": sorted(self.erased),
                "retained": [r.to_dict() for r in self.retained],
                "keyDestroyed": self.key_destroyed,
                "complete": self.complete, "notes": self.notes}

    def human_summary(self) -> str:
        lines = [f"Erasure request for {self.subject}",
                 f"  requested: {time.strftime('%Y-%m-%d', time.gmtime(self.requested_at))}",
                 ""]
        if self.erased:
            lines.append("  Erased:")
            lines += [f"    - {c}: {CLASSES[c].description}" for c in sorted(self.erased)
                      if c in CLASSES]
        if self.retained:
            lines += ["", "  Retained, and why:"]
            for r in self.retained:
                lines.append(f"    - {r.data_class} ({r.basis}) until "
                             f"{r.to_dict()['erasedAutomaticallyOn']}")
                lines.append(f"      {r.reason}")
        if self.key_destroyed:
            lines += ["", "  The subject's encryption key was destroyed. Content "
                          "encrypted under it is unrecoverable, including by us."]
        if not self.complete:
            lines += ["", "  This erasure is PARTIAL. The retained classes above "
                          "are kept under a lawful basis and are erased "
                          "automatically when it lapses."]
        return "\n".join(lines)


def erase(ring: KeyRing, subject: str,
          held: Optional[list[tuple[str, int]]] = None,
          now: Optional[int] = None) -> ErasureReport:
    """
    Process a request.

    `held` is the (data_class, created_at) inventory this node holds for the
    subject. Anything whose class permits erasure is shredded by destroying the
    key; anything retained is reported with its basis and the date it goes.
    """
    now = now or int(time.time())
    rep = ErasureReport(subject=subject, requested_at=now)
    inventory = held if held is not None else [
        (cid, now) for cid, c in CLASSES.items() if c.contains_personal_data]

    must_keep = False
    for class_id, created in inventory:
        try:
            c = classify(class_id)
        except RetentionError:
            rep.notes.append(f"unknown class {class_id!r} — erased rather than kept")
            rep.erased.append(class_id)
            continue
        if not c.contains_personal_data:
            continue
        ok, reason = erasable(class_id)
        if ok:
            rep.erased.append(class_id)
        else:
            must_keep = True
            rep.retained.append(Retained(
                data_class=class_id, reason=reason, basis=c.basis.value,
                erased_automatically_at=created + c.retention_seconds))

    # The key is only destroyed when nothing encrypted under it must be kept.
    # Destroying it while a retained class still needs reading would make the
    # operator unable to meet the obligation they cited as the reason to keep it.
    if not must_keep:
        rep.key_destroyed = ring.destroy(subject, now=now)
        rep.notes.append("subject key destroyed; encrypted content is now "
                         "unreadable, and every chain containing it still verifies")
    else:
        rep.notes.append("subject key RETAINED because a class above must remain "
                         "readable under a legal obligation; it is destroyed when "
                         "the last such class expires")
    return rep


def pending_expiry(held: list[tuple[str, int]],
                   now: Optional[int] = None) -> list[dict[str, Any]]:
    """
    What is now past its retention and should be deleted on the next sweep. A
    retention policy nobody runs is a liability, not a control.
    """
    from .retention import due_for_expiry
    out = []
    for class_id, created in due_for_expiry(held, now):
        c = CLASSES.get(class_id)
        out.append({"dataClass": class_id, "createdAt": created,
                    "retentionDays": c.retention_days if c else 0,
                    "action": "delete"})
    return out


__all__ = ["erase", "ErasureReport", "Retained", "pending_expiry"]
