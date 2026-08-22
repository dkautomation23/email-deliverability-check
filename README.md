# email-deliverability-check

Reads a domain's DNS and tells you why its mail is landing in spam — or is
about to. SPF, DKIM, DMARC, MX, MTA-STS, BIMI, in about five seconds, with no
access to the domain and nothing sent.

```bash
python check.py example.com
python check.py --batch domains.txt --csv results.csv
```

## Why

Gmail, Yahoo and Microsoft now enforce what used to be advice: authenticate
your mail or it does not arrive. The failures are quiet — nobody gets an error,
the sender sees "delivered", and the reply rate just drops.

Two of them are almost impossible to notice by hand:

- **SPF has a hard limit of 10 DNS lookups.** Every `include:` costs one. A
  company adds a newsletter tool, then a CRM, then a scheduling app — and the
  eleventh include silently invalidates the whole record. GitHub is sitting on
  exactly 10 right now.
- **DMARC at `p=none`** looks configured and does nothing. It is the single most
  common finding: the record exists, so the box is ticked, but spoofed mail is
  still delivered and nobody is reading the reports.

## What it checks

| Check | What it catches |
| --- | --- |
| SPF | missing, duplicated (a permanent error), `+all`, `?all`, and the lookup count with includes followed recursively |
| DKIM | 22 selectors used by Google, Microsoft, Mailchimp, SendGrid, Zoho, Postmark, SES, HubSpot, Brevo and others |
| DKIM edge cases | revoked keys (`p=` with nothing after it) and wildcard zones that answer every selector |
| DMARC | missing, `p=none`, no `rua`, partial `pct` |
| MX | absent (send-only domain that still needs anti-spoof records), null MX |
| MTA-STS | inbound TLS can be stripped without it |
| BIMI | reported when present |

The DKIM canary is worth a sentence: before probing selectors, it asks for one
that cannot exist. Some zones answer everything with a wildcard, which would
otherwise "find" all 22 selectors and report nonsense.

Likewise, a DNS timeout is never reported as a missing record. If the local
resolver is unreachable the tool falls back to public ones and, if those fail
too, it says it could not check rather than inventing a verdict.

## Sample output

```console
$ python check.py github.com

github.com   80/100
  [~] SPF is at 10 of 10 DNS lookups
      One more tool and authentication breaks.
      fix: Remove includes for services you no longer use.
  [~] No MTA-STS record
  [+] DKIM found (6 selector(s))
      google - Google Workspace, selector1 - Microsoft 365, k1 - Mailchimp, s1, s2, k2
  [+] DMARC policy is p=quarantine
      v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@github.com; ...
```

```console
$ python check.py example.com

example.com   70/100
  [~] DKIM cannot be determined - the zone uses a wildcard
      Every _domainkey lookup returns a record, including one that cannot exist.
  [~] DMARC has no rua address
  [+] Null MX (domain does not receive mail)
  [+] DMARC policy is p=reject
```

## Checking a list

```bash
python check.py --batch domains.txt --csv results.csv
```

```csv
domain,score,worst,spf,spf_lookups,dmarc_policy,dkim_selectors,issues
github.com,80,warning,~all,10,quarantine,google;selector1;k1;k2;s1;s2,SPF is at 10 of 10 DNS lookups | No MTA-STS record
stripe.com,90,warning,~all,7,reject,google;s1;s2;mandrill,No MTA-STS record
```

Handy for an agency auditing a client list, or before a migration: run it, sort
by score, and start with the reds.

## Install

```bash
git clone https://github.com/dkautomation23/email-deliverability-check.git
cd email-deliverability-check
pip install -r requirements.txt
python check.py --selftest      # 17 checks, offline
```

Python 3.10+, one dependency (dnspython). Exit code `1` when something critical
is found, `2` when DNS itself was unreachable — so a cron job can tell "this
domain is broken" apart from "I could not look".

## Honest limits

DNS is only half of deliverability. This tool reads the half that is public and
objective; the rest needs access or paid data:

- **No inbox placement test.** Whether a specific message lands in Primary,
  Promotions or Spam needs seed accounts at each provider and a real send.
- **No reputation or blacklist data.** Sending IP and domain reputation live in
  Google Postmaster, Microsoft SNDS and commercial RBL feeds.
- **No content analysis.** Spam-triggering copy, image ratio, link shorteners,
  broken unsubscribe headers — not covered.
- **DKIM by common selectors only.** A custom selector will be missed; the tool
  says so instead of claiming DKIM is absent.
- **Nothing is fixed.** Every finding comes with the change to make, but the
  records have to be published in whoever's DNS panel this domain lives in.

If the score is low, the DNS work is usually an hour. Confirming the mail
actually reaches inboxes afterwards is a separate exercise with seed lists and
a week of sending.

## License

MIT
