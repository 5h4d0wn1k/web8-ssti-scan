> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# WEB8 — SSTI Scanner

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub Stars](https://img.shields.io/github/stars/5h4d0wn1k/web8-ssti-scan)
![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/web8-ssti-scan)
![GitHub Issues](https://img.shields.io/github/issues/5h4d0wn1k/web8-ssti-scan)

> **Server-Side Template Injection scanner** — math-evaluation detection,
> template-engine fingerprinting, per-engine RCE/file-read payloads, and
> multi-target fuzzing for Jinja2, Twig, Mako, ERB, and more, for web security
> education and authorized testing.

## Why

Server-Side Template Injection turns a small rendering flaw into full remote
code execution — one of the highest-impact web vulnerabilities to miss. WEB8
teaches detection the way a pentester performs it: inject arithmetic probes
(`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) and look for evaluated output, then identify
the engine from error pages and response differences, and finally generate
engine-specific RCE and file-read payloads for Jinja2, Twig, Mako, ERB,
FreeMarker, Velocity, and Smarty. A fully offline demo spins up a vulnerable and
a hardened control renderer on loopback, so every detection signal can be
verified with zero network exposure before any authorized engagement.

## Features

- **Math-evaluation detection** — `{{7*7}}` → `49` style probes.
- **Engine fingerprinting** — identify Jinja2 / Twig / Mako / ERB / FreeMarker /
  Velocity / Smarty from error and response signals.
- **Engine-specific payloads** — RCE and file-read payload generation
  (`--payloads --engine jinja2`).
- **Parameter fuzzing** — `--fuzz URL --param name,q,input` sweeps common paths
  and parameters with worker threads.
- **Offline demo** — vulnerable + clean control simulators on loopback.
- **Stdlib-only** — Python 3.8+, no external dependencies.

## Quickstart

```bash
# Offline demo (vulnerable + clean control simulators, no network)
python3 ssti_scanner.py --demo

# Detection against a target you own
python3 ssti_scanner.py --url "http://target/search?q=" --param q

# Show payloads for an engine
python3 ssti_scanner.py --payloads --engine jinja2

# Fuzz common paths and parameters
python3 ssti_scanner.py --fuzz http://target --param name,q,input

# Offline test suite
python3 -m unittest discover -s tests
```

## Project structure

```
ssti_scanner.py     # CLI + detection engine (stdlib)
tests/              # deterministic offline tests
ETHICS.md           # ethics/authorized-use policy (read first)
SCOPE.md            # defined assessment scope
```

## Documentation

- [ETHICS.md](ETHICS.md) — ethical-use policy, read first
- [SCOPE.md](SCOPE.md) — authorized-scope definition
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## Contributing

New engines, payload sets, and detection heuristics are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md); keep the offline demo green.

## License

MIT — see [LICENSE](LICENSE).