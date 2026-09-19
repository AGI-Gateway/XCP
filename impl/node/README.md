# A second implementation

The conformance suite exists to certify implementations other than the
reference. Until now nothing had ever run against it but the Python gateway,
which means the suite proved only that the reference agreed with itself.

This is an independent XCP gateway in TypeScript/Node, written against the
specification and the conformance clauses rather than by porting the Python. It
implements the `core` and `security` profiles.

```bash
node server.mjs                       # listens on 8080
xcp conform http://127.0.0.1:8080 --profile core,security
```

## What it proved

Writing it surfaced spec ambiguities that a single implementation cannot reveal,
recorded in `FINDINGS.md`. That is the point of the exercise: a specification is
only as good as its second reader.

## What it is not

Not production software. No federation, no receipts, no settlement — those
profiles are unimplemented and the suite is told so rather than being given a
stub that appears to pass.
