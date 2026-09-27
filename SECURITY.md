# Security Policy

## Supported versions

Security fixes go into the latest release line (currently `v0.21.0`) and the `main` branch. Older releases are not patched; please upgrade.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: **Security → Advisories → "Report a vulnerability"** on this repository (<https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/security/advisories/new>).
If you cannot use GitHub, open a public issue that says only that you have a security report and asks for a private contact. Do not include any details in that issue.

Please include:

- the version or commit, and a minimal Sigma rule, pipeline or command that reproduces the problem, with the observed and expected output;
- the impact you see (see the scope below) and, if you have one, a proposed fix.

## What we treat as a vulnerability

These validators check Sigma rules, including rules submitted by third parties to the SigmaHQ rule repository, against SigmaHQ conventions. The following are in scope:

- **Denial of service:** a small crafted rule that makes a validator consume excessive CPU or memory (for example pathological regular expressions or YAML structures).
- **Code execution or file access:** validating a rule that leads to code execution, unsafe deserialisation, or file access outside the intended location.
- **Release and supply chain:** weaknesses in this repository's CI or release workflows that could let an outsider publish or alter a released package or the bundled data files.

**Out of scope (report publicly as bugs):**

- A validator that accepts or rejects a rule incorrectly. Validators enforce style and quality conventions; they are not a security boundary.

Report problems whose root cause is in pySigma itself (rule parsing, modifiers, processing pipeline machinery, conversion base classes) to [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma). Report problems specific to this repository here.

## Our process

| Step                                                                          | Target                                        |
| ----------------------------------------------------------------------------- | --------------------------------------------- |
| Acknowledge the report                                                        | within 5 working days                         |
| Initial assessment and severity (CVSS 3.1)                                    | within 14 days                                |
| Fix developed in the advisory's temporary private fork                        | as soon as practical, normally within 90 days |
| Coordinated release, then GitHub Security Advisory published (CVE via GitHub) | at the fix release                            |

- We credit reporters in the advisory unless they ask not to be credited.
- When a fix affects other SigmaHQ projects, we may coordinate their releases.
- We ask reporters to keep details private until the advisory is published or 90 days have passed, whichever comes first, unless agreed otherwise.
