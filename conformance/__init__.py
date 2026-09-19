"""
conformance — prove an implementation speaks XCP.

    from conformance import run, format_report, Profile
    print(format_report(run("https://gateway.example", [Profile.CORE])))

Black-box over HTTP: imports nothing from the implementation under test, so a
Go, Rust or TypeScript gateway gets the same verdict as this one.
"""
from .suite import (run, format_report, Report, Result, Profile, Level,
                    Outcome, CHECKS, SUITE_VERSION)

__all__ = ["run", "format_report", "Report", "Result", "Profile", "Level",
           "Outcome", "CHECKS", "SUITE_VERSION"]
