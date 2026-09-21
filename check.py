"""Audit a domain's e-mail authentication before the mail starts bouncing.

    python check.py example.com
    python check.py example.com --verbose
    python check.py --batch domains.txt --csv results.csv
    python check.py --selftest

Reads DNS only: SPF, DKIM, DMARC, MX, MTA-STS, BIMI. Nothing is sent, nothing
is stored, and the domain owner never has to give you access.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import dns.resolver
import dns.exception

TIMEOUT = 5.0

# Selectors used by the mail platforms small companies actually run on.
# Cheap to probe, and a hit tells you who sends their mail.
KNOWN_SELECTORS = {
    "google": "Google Workspace",
    "selector1": "Microsoft 365",
    "selector2": "Microsoft 365",
    "k1": "Mailchimp / Mandrill",
    "k2": "Mailchimp",
    "s1": "SendGrid / generic",
    "s2": "SendGrid / generic",
    "mail": "generic",
    "dkim": "generic",
    "default": "generic",
    "zoho": "Zoho Mail",
    "protonmail": "Proton Mail",
    "pm": "Postmark",
    "mte1": "Mailerlite",
    "mandrill": "Mandrill",
    "sm": "SparkPost",
    "sig1": "iCloud / other",
    "hs1": "HubSpot",
    "hs2": "HubSpot",
    "amazonses": "Amazon SES",
    "mailjet": "Mailjet",
    "brevo": "Brevo",
}

# Every mechanism that costs a DNS lookup. Ten is the hard limit in RFC 7208;
# past it receivers return permerror and the SPF result is discarded.
LOOKUP_MECHANISMS = ("include:", "a:", "mx:", "ptr", "exists:", "redirect=")


@dataclass
class Result:
    domain: str
    findings: list[dict] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def add(self, level: str, title: str, detail: str = "", fix: str = "") -> None:
        self.findings.append({"level": level, "title": title, "detail": detail, "fix": fix})

    @property
    def score(self) -> int:
        penalty = sum({"critical": 30, "warning": 10}.get(item["level"], 0) for item in self.findings)
        return max(0, 100 - penalty)

    @property
    def worst(self) -> str:
        for level in ("critical", "warning"):
            if any(item["level"] == level for item in self.findings):
                return level
        return "ok"


# ---------------------------------------------------------------- dns

class DnsUnavailable(RuntimeError):
    """No resolver answered. Reporting "no SPF record" here would be a lie."""


# Public resolvers to fall back on: hotel wifi, phone tethering and corporate
# DNS all like to swallow TXT queries, and a silent timeout must never be
# reported as a missing record.
FALLBACK_RESOLVERS = (["1.1.1.1", "1.0.0.1"], ["8.8.8.8", "8.8.4.4"])
_working_servers: list[str] | None = None


def _resolver(servers: list[str] | None) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    if servers:
        resolver.nameservers = servers
    resolver.lifetime = resolver.timeout = TIMEOUT
    return resolver


def query(name: str, record: str) -> list[str]:
    """Return record strings, [] when the record genuinely does not exist.

    Raises DnsUnavailable when no resolver could be reached at all.
    """
    global _working_servers
    candidates = [_working_servers] if _working_servers else [None, *FALLBACK_RESOLVERS]

    answers = None
    last_error: Exception | None = None
    for servers in candidates:
        try:
            answers = _resolver(servers).resolve(name, record)
            _working_servers = servers or _resolver(None).nameservers
            break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            _working_servers = servers or _resolver(None).nameservers
            return []                       # the resolver answered: nothing there
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            last_error = exc
            continue                        # this resolver is not usable, try the next

    if answers is None:
        raise DnsUnavailable(f"no resolver answered for {name} {record}: {last_error}")
    values = []
    for answer in answers:
        if record == "TXT":
            values.append("".join(part.decode() for part in answer.strings))
        elif record == "MX":
            values.append(f"{answer.preference} {answer.exchange.to_text().rstrip('.')}")
        else:
            values.append(answer.to_text().strip('"'))
    return values


# ---------------------------------------------------------------- parsers

def spf_lookup_count(record: str, depth: int = 0, seen: set | None = None) -> int:
    """Count the DNS lookups an SPF record costs, following includes.

    This is the check almost nobody runs by hand, and the one that silently
    breaks authentication when a company adds its fifth marketing tool.
    """
    seen = seen if seen is not None else set()
    count = 0
    for token in record.split():
        lowered = token.lower()
        if not lowered.startswith(LOOKUP_MECHANISMS) and lowered not in {"a", "mx", "ptr"}:
            continue
        count += 1
        target = ""
        if lowered.startswith("include:"):
            target = token.split(":", 1)[1]
        elif lowered.startswith("redirect="):
            target = token.split("=", 1)[1]
        if target and depth < 3 and target not in seen:
            seen.add(target)
            nested = [r for r in query(target, "TXT") if r.lower().startswith("v=spf1")]
            if nested:
                count += spf_lookup_count(nested[0], depth + 1, seen)
    return count


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, _, value = part.strip().partition("=")
            tags[key.strip().lower()] = value.strip()
    return tags


def spf_policy(record: str) -> str:
    """The qualifier on 'all': -all reject, ~all softfail, ?all neutral, +all open."""
    match = re.search(r"([-~?+])all\b", record.lower())
    return match.group(0) if match else "missing"


# ---------------------------------------------------------------- checks

def check_domain(domain: str, verbose: bool = False) -> Result:
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    result = Result(domain=domain)

    mx = query(domain, "MX")
    result.facts["mx"] = mx
    if not mx:
        result.add("warning", "No MX records",
                   "This domain cannot receive mail.",
                   "Fine for a send-only or parked domain - but then publish 'v=spf1 -all' "
                   "and a reject DMARC policy so nobody can spoof it.")
    elif any(entry.split(" ", 1)[-1] in {"", "."} for entry in mx):
        result.add("ok", "Null MX (domain does not receive mail)", ", ".join(mx))

    # --- SPF -------------------------------------------------------------
    txt = query(domain, "TXT")
    spf_records = [record for record in txt if record.lower().startswith("v=spf1")]
    result.facts["spf"] = spf_records

    if not spf_records:
        result.add("critical", "No SPF record",
                   "Receivers cannot tell which servers may send as this domain.",
                   "Publish a TXT record starting with v=spf1 listing your mail providers, ending in -all.")
    else:
        if len(spf_records) > 1:
            result.add("critical", f"{len(spf_records)} SPF records",
                       "More than one v=spf1 record is a permanent error - authentication fails outright.",
                       "Merge them into a single record.")
        record = spf_records[0]
        policy = spf_policy(record)
        lookups = spf_lookup_count(record)
        result.facts["spf_lookups"] = lookups
        result.facts["spf_policy"] = policy

        if lookups > 10:
            result.add("critical", f"SPF needs {lookups} DNS lookups (limit is 10)",
                       "Receivers stop evaluating and treat SPF as failed.",
                       "Flatten or drop unused includes - each marketing tool you added costs one.")
        elif lookups >= 8:
            result.add("warning", f"SPF is at {lookups} of 10 DNS lookups",
                       "One more tool and authentication breaks.",
                       "Remove includes for services you no longer use.")
        if policy == "+all":
            result.add("critical", "SPF ends in +all",
                       "This authorises the entire internet to send as your domain.",
                       "Change it to -all.")
        elif policy == "missing":
            result.add("warning", "SPF has no 'all' mechanism",
                       "Behaviour for unlisted senders is undefined.", "End the record with -all.")
        elif policy == "?all":
            result.add("warning", "SPF ends in ?all (neutral)",
                       "Neutral tells receivers to ignore the result.", "Move to ~all, then -all.")

    # --- DKIM ------------------------------------------------------------
    # Canary first: some zones answer every *._domainkey lookup with a wildcard,
    # which would otherwise "find" all 22 selectors and mean nothing.
    canary = query(f"zz-no-such-selector-9x._domainkey.{domain}", "TXT")
    wildcard = any("v=dkim1" in record.lower() for record in canary)
    result.facts["dkim_wildcard"] = wildcard

    found_selectors = {}
    revoked = []
    if not wildcard:
        for selector, platform in KNOWN_SELECTORS.items():
            records = query(f"{selector}._domainkey.{domain}", "TXT")
            for record in records:
                if "p=" not in record:
                    continue
                # "p=" with nothing after it is a revoked key, not a working one.
                key = record.split("p=", 1)[1].strip().strip('";')
                if key:
                    found_selectors[selector] = platform
                else:
                    revoked.append(selector)
                break
    result.facts["dkim_selectors"] = found_selectors

    if wildcard:
        result.add("warning", "DKIM cannot be determined - the zone uses a wildcard",
                   "Every _domainkey lookup returns a record, including one that cannot exist.",
                   "Check the actual selector in your mail platform; wildcard TXT records also "
                   "make life easy for anyone trying to spoof you.")
    elif revoked and not found_selectors:
        result.add("critical", f"DKIM key is revoked ({', '.join(revoked)})",
                   "The selector exists but publishes an empty key - signatures will not verify.",
                   "Re-publish the public key from your mail provider.")
    elif not found_selectors:
        result.add("warning", "No DKIM key found on the common selectors",
                   f"Tried {len(KNOWN_SELECTORS)} selectors used by the usual providers.",
                   "DKIM may still exist on a custom selector - confirm in your mail platform. "
                   "If it does not, enable signing: Gmail and Outlook require it from bulk senders.")
    else:
        result.add("ok", f"DKIM found ({len(found_selectors)} selector(s))",
                   ", ".join(f"{selector} - {platform}" for selector, platform in found_selectors.items()))

    # --- DMARC -----------------------------------------------------------
    dmarc_records = [r for r in query(f"_dmarc.{domain}", "TXT") if r.lower().startswith("v=dmarc1")]
    result.facts["dmarc"] = dmarc_records

    if not dmarc_records:
        result.add("critical", "No DMARC record",
                   "Nothing tells receivers what to do with mail that fails checks, and you get no reports.",
                   "Start with p=none plus a rua address, read the reports, then tighten to quarantine.")
    else:
        tags = parse_dmarc(dmarc_records[0])
        policy = tags.get("p", "none").lower()
        result.facts["dmarc_policy"] = policy
        if policy == "none":
            result.add("warning", "DMARC policy is p=none",
                       "Monitoring only - spoofed mail is still delivered.",
                       "Once your reports are clean, move to p=quarantine, then p=reject.")
        elif policy in {"quarantine", "reject"}:
            result.add("ok", f"DMARC policy is p={policy}", dmarc_records[0][:120])
        if not tags.get("rua"):
            result.add("warning", "DMARC has no rua address",
                       "You are not receiving aggregate reports, so failures are invisible.",
                       "Add rua=mailto:dmarc@yourdomain (or a reporting service).")
        pct = tags.get("pct")
        if pct and pct.isdigit() and int(pct) < 100:
            result.add("warning", f"DMARC applies to only {pct}% of mail",
                       "A partial rollout left in place.", "Raise pct to 100 when you are confident.")

    # --- modern extras ----------------------------------------------------
    mta_sts = [r for r in query(f"_mta-sts.{domain}", "TXT") if r.lower().startswith("v=stsv1")]
    result.facts["mta_sts"] = bool(mta_sts)
    if mx and not mta_sts:
        result.add("warning", "No MTA-STS record",
                   "Inbound mail can be downgraded to plaintext by an attacker on the path.",
                   "Publish _mta-sts TXT plus the policy file - a 20-minute job, one-off.")

    bimi = [r for r in query(f"default._bimi.{domain}", "TXT") if r.lower().startswith("v=bimi1")]
    result.facts["bimi"] = bool(bimi)
    if bimi:
        result.add("ok", "BIMI published", bimi[0][:100])

    if verbose:
        for key, value in result.facts.items():
            print(f"    {key}: {value}")
    return result


# ---------------------------------------------------------------- output

def print_result(result: Result) -> None:
    mark = {"critical": "[!]", "warning": "[~]", "ok": "[+]"}
    print(f"\n{result.domain}   {result.score}/100")
    order = {"critical": 0, "warning": 1, "ok": 2}
    for finding in sorted(result.findings, key=lambda item: order[item["level"]]):
        print(f"  {mark[finding['level']]} {finding['title']}")
        if finding["detail"]:
            print(f"      {finding['detail']}")
        if finding["fix"] and finding["level"] != "ok":
            print(f"      fix: {finding['fix']}")


def write_csv(results: list[Result], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["domain", "score", "worst", "spf", "spf_lookups", "dmarc_policy",
                         "dkim_selectors", "issues"])
        for result in results:
            writer.writerow([
                result.domain,
                result.score,
                result.worst,
                result.facts.get("spf_policy", "none"),
                result.facts.get("spf_lookups", ""),
                result.facts.get("dmarc_policy", "none"),
                ";".join(result.facts.get("dkim_selectors", {})),
                " | ".join(f["title"] for f in result.findings if f["level"] != "ok"),
            ])
    print(f"\n{len(results)} domain(s) -> {path}")


# ---------------------------------------------------------------- selftest

def selftest() -> int:
    """Parsers only - no DNS, so this passes on a plane."""
    checks, failures = 0, []

    def check(label, condition):
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(label)

    check("hard fail detected", spf_policy("v=spf1 include:_spf.google.com -all") == "-all")
    check("softfail detected", spf_policy("v=spf1 ~all") == "~all")
    check("open relay detected", spf_policy("v=spf1 +all") == "+all")
    check("neutral detected", spf_policy("v=spf1 ?all") == "?all")
    check("missing all detected", spf_policy("v=spf1 ip4:1.2.3.4") == "missing")

    # Counted without touching the network: ip4 is free, includes are not.
    flat = "v=spf1 ip4:1.2.3.4 ip6:::1 -all"
    check("ip mechanisms cost nothing", spf_lookup_count(flat) == 0)
    check("a and mx each cost one", spf_lookup_count("v=spf1 a mx -all") == 2)
    check("ptr costs one", spf_lookup_count("v=spf1 ptr -all") == 1)

    dmarc = parse_dmarc("v=DMARC1; p=quarantine; rua=mailto:d@example.com; pct=50; sp=none")
    check("dmarc policy parsed", dmarc["p"] == "quarantine")
    check("dmarc rua parsed", dmarc["rua"] == "mailto:d@example.com")
    check("dmarc pct parsed", dmarc["pct"] == "50")
    check("dmarc subdomain policy parsed", dmarc["sp"] == "none")
    check("dmarc tolerates spacing", parse_dmarc("v=DMARC1;   p=reject ;")["p"] == "reject")

    result = Result("x.com")
    result.add("critical", "a")
    result.add("warning", "b")
    check("score subtracts by severity", result.score == 60)
    check("worst level reported", result.worst == "critical")
    check("clean domain scores 100", Result("y.com").score == 100)
    ok_only = Result("z.com")
    ok_only.add("ok", "fine")
    check("ok findings cost nothing", ok_only.score == 100 and ok_only.worst == "ok")

    print(f"selftest: {checks - len(failures)}/{checks} passed")
    for failure in failures:
        print("  FAILED:", failure)
    return 1 if failures else 0


# ---------------------------------------------------------------- cli

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check SPF, DKIM and DMARC for a domain.")
    parser.add_argument("domain", nargs="?", help="domain to check, e.g. example.com")
    parser.add_argument("--batch", type=Path, help="file with one domain per line")
    parser.add_argument("--csv", type=Path, help="write results to CSV (works with --batch)")
    parser.add_argument("--verbose", action="store_true", help="print the raw records")
    parser.add_argument("--selftest", action="store_true", help="run the parser checks and exit")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()

    domains = []
    if args.batch:
        domains = [line.strip() for line in args.batch.read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.startswith("#")]
    elif args.domain:
        domains = [args.domain]
    else:
        parser.error("give me a domain, --batch a file, or --selftest")

    results = []
    for domain in domains:
        try:
            result = check_domain(domain, args.verbose)
        except DnsUnavailable as exc:
            print(f"\n{domain}: cannot check - {exc}")
            print("  DNS is not reachable from here. Nothing is reported as missing, because "
                  "a timeout is not an answer. Try again on another network, or pass a resolver "
                  "your machine can reach.")
            return 2
        results.append(result)
        print_result(result)

    if args.csv:
        write_csv(results, args.csv)

    if len(results) > 1:
        criticals = sum(1 for r in results if r.worst == "critical")
        print(f"\n{len(results)} domain(s) checked, {criticals} with a critical problem")

    return 1 if any(result.worst == "critical" for result in results) else 0


if __name__ == "__main__":
    sys.exit(main())
