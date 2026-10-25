# watchfire-feed

The feed behind [Watchfire](https://fresh-reads.lovable.app/): what developers
should know about, and what to do. Rebuilt every two hours by a GitHub Action
and published at <https://nexlabz.github.io/watchfire-feed/>:

- `news.json` — every item from the last 30 days, newest first
- `feed.xml` — the same as RSS; `feeds/<topic>.xml` per topic
  (`npm`, `pypi`, `rust`, `go`, `ai-tools`, `ci-cd`, `vulns`, `snare`)

Sources are advisory databases (GitHub Advisories, CISA KEV), the researchers
who find supply-chain malware (Socket, Aikido, StepSecurity, ReversingLabs,
Datadog Security Labs, Wiz, and others), and security press. Each item links
its source and says whether it is **confirmed** (an advisory or the
researchers who found it) or **reported** (press). Malware advisories arrive
by the dozen each day, nearly all throwaway fakes, so they are one daily
digest; a malicious package with real usage gets its own alert.

With the `ANTHROPIC_API_KEY` repository secret set, Claude writes each
summary and its "what to do" line and drops off-topic posts. Without it the
feed still builds, on rules. The model never supplies a link.

Sources: `bot/sources.json`. Run locally: `python3 -I bot/build.py site`.
