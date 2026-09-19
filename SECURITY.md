# Security Policy

## Supported Versions

There are no tagged releases yet. Only the latest commit on `main` is
supported — apply fixes by updating to the current `main`.

## Reporting a Vulnerability

Report privately using GitHub's Private Vulnerability Reporting: open this
repository's Security tab and select "Report a vulnerability". If that option
is not available to you, email hello@dkautomation.dev instead.

Do not open a public issue for a suspected vulnerability.

You will get a first response within 3 business days.

A good report includes:

- Steps to reproduce
- The affected file (usually `check.py`)
- The impact: what an attacker can do with it, and who is affected

## Scope

check.py resolves DNS records (SPF, DKIM, DMARC, MX, MTA-STS, BIMI) for a
domain you give it and prints or writes what it finds. It reads DNS only: it
never connects to the mail servers or hosts named in the records it reads, and
it stores nothing beyond the `--csv` file you asked for.

### Treated as a vulnerability here

- check.py being made to direct its DNS queries at internal, private, or
  link-local network addresses instead of the intended public target —
  for example through a crafted domain, a crafted SPF `include:`/`redirect=`
  chain followed by `spf_lookup_count`, or a programmatic call to
  `_resolver()` / `query()` with an attacker-supplied nameserver list — in a
  way that probes or exposes internal infrastructure the operator did not
  intend to reach. This applies even though no command-line flag exposes a
  custom nameserver today.
- DNS answers or lookup results for a domain (the `Result.facts` /
  `Result.findings` produced by `check_domain()`, or the rows `write_csv()`
  writes) being exposed to, logged for, or made reachable by anyone other
  than the person who ran the check.
- Any change that makes check.py open a network connection that is not a DNS
  query — the tool is DNS-only by design.

### Not treated as a vulnerability here

- check.py resolving whatever public domain you point it at, including a
  third party's domain — that is its normal, intended job.
- A checked domain's own missing or weak SPF, DKIM, DMARC, MTA-STS, or BIMI
  configuration. That is the finding the tool exists to report, not a bug in
  the tool.
- DNS queries falling back to the public resolvers 1.1.1.1/1.0.0.1 or
  8.8.8.8/8.8.4.4 (`FALLBACK_RESOLVERS`) when the local resolver does not
  answer — documented, intentional behavior.
