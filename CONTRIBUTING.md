# Contributing

## Setup

Give this repository its own virtual environment. Do not reuse a venv from
another project — a shared venv hides missing dependencies until CI catches
them on a fresh install.

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS/Linux
pip install -r requirements.txt
```

The only dependency is `dnspython`.

## Running the tests

There is no `tests/` directory. `check.py --selftest` is the test suite for
this repository — it runs the parser and scoring checks offline, with no DNS
traffic, and it is what CI runs on every push.

```bash
python -m compileall -q .
python check.py --selftest
```

CI runs both commands on Python 3.10 and 3.12.

## Adding a check or fixing a bug

This repository follows a failing-test-first rule, adapted to having no
`tests/` directory:

1. Add a failing case to the `selftest()` function in `check.py` — extend an
   existing `check(...)` call or add a new one — that demonstrates the bug or
   the new behavior.
2. Confirm it fails: `python check.py --selftest`.
3. Implement the fix or the check.
4. Confirm `python check.py --selftest` passes, with the new case counted.

## Commit style

Short, descriptive sentences, occasionally `type: description`. Examples from
this repository's history, copied verbatim:

```
Run the tests in CI on every push
email-deliverability-check: SPF/DKIM/DMARC audit from DNS, with the lookup-limit and wildcard traps handled
```

## Pull requests

- Keep changes scoped to one check or one fix.
- CI must pass: byte-compile plus `--selftest` on Python 3.10 and 3.12.
- Do not commit real domain or DNS data that reveals sensitive infrastructure
  details. Only the files under `samples/` are tracked as example input — add
  new examples there rather than dropping domain lists elsewhere in the repo.
