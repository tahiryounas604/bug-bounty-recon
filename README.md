# bug-bounty-recon

One-command recon for authorized bug-bounty targets: enumerate subdomains,
probe live hosts, check common ports, optionally run nuclei, and write a
Markdown + JSON report.

## Features

- **Subdomain enumeration** via the [crt.sh](https://crt.sh) certificate-transparency
  JSON API (wildcard stripping, de-duplication, in-scope filtering).
- **DNS wordlist probe** — 142 common subdomain labels, resolved concurrently
  with the standard library (`recon/wordlist.txt`, bring your own with `--wordlist`).
- **Wildcard DNS detection** — random labels are resolved first; if they
  answer, the report warns that DNS-probe hits are unreliable (wildcards
  and some egress proxies resolve everything).
- **Port checks** — TCP connect checks for ports 80/443/8080/8443 by default
  (configurable with `--ports`).
- **nuclei integration** — runs nuclei against live hosts *if* the binary is
  on your PATH; otherwise skips with a clear note (nuclei is not bundled).
- **Reports** — `report.md` (human-readable) + `report.json` (machine-readable)
  in the output directory.

## Install

Python 3.9+ only. No third-party dependencies — standard library only.

```bash
git clone https://github.com/tahiryounas604/bug-bounty-recon.git
cd bug-bounty-recon
# optional: install as a command
pip install --break-system-packages .
```

## Usage

```bash
# Full run (nuclei runs too, if installed)
python3 recon.py example.com

# Skip nuclei, custom output directory
python3 recon.py example.com --no-nuclei --output-dir ./out

# Skip crt.sh, use a custom wordlist, check extra ports
python3 recon.py example.com --no-crtsh --wordlist ./my-words.txt --ports 80,443,8000,9000

# Faster / slower probes
python3 recon.py example.com --timeout 5 --workers 30
```

Output:

```
recon-example.com/
├── report.md            # human-readable report
├── report.json          # machine-readable results
└── live-hosts.txt       # nuclei targets (only when nuclei runs)
└── nuclei-findings.txt  # nuclei output (only when nuclei runs)
```

## Tests

```bash
python3 -m pytest -q
```

27 tests, covering: crt.sh parsing from a canned response, DNS probing
with a mocked resolver, live probing against a real local `http.server`
fixture, port checks, report generation, nuclei skip/run behaviour, and
the CLI pipeline end to end.

## Known limits

- **Pure Python v0.1 — no Go helper.** Go was not available in the build
  environment, so the concurrent DNS/HTTP probe is Python
  (`concurrent.futures`). A Go helper may be added in a later version.
- **crt.sh needs network access** to `crt.sh`. If it is unreachable the
  tool logs the failure and continues with the DNS probe only.
- **DNS probe only finds what the wordlist contains** (142 labels) plus
  what crt.sh knows. It is not a replacement for a full brute-force or
  for passive sources such as Shodan, VirusTotal or SecurityTrails.
- **Live probe is HTTP-level only** — no JavaScript rendering, no
  screenshot, no login handling. A host that needs JS or auth may report
  a title/status that does not reflect the real application.
- **nuclei is optional and external.** Findings quality depends entirely
  on the nuclei version and templates installed on your machine.
- **No rate limiting / politeness controls yet.** Against large subdomain
  lists the default 20 workers can be aggressive; lower `--workers` on
  sensitive targets.
- **Not tested against a live bug-bounty program** in v0.1 — only against
  `example.com` (smoke test) and local fixtures. Live-program validation
  is planned before any v0.2 claim.

## Legal / ethical use

**Scan only targets you are authorized to test.** This tool is for
authorized security research — your own assets, or programs where you
have explicit permission (bug bounty scope, client engagement, CTF).
Unauthorized scanning may be illegal. You are responsible for staying
inside the scope you were given.

## License

GPL-3.0 — see [LICENSE](LICENSE).

Built by Tahir Younas — Penetration Tester & Application Security Engineer — https://www.linkedin.com/in/tahiryounas604 | Tytechlabs
