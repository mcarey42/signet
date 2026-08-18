# Security policy

## Reporting a vulnerability

Report privately, not in a public issue:

- **GitHub:** [private vulnerability reporting](https://github.com/mcarey42/signet/security/advisories/new)
- **Email:** mcarey@solcore.net

Include what you did, what happened, and what you expected. A runnable
reproduction is worth more than a description, and is what we hold ourselves
to as well.

You will get an acknowledgement within 72 hours. We will tell you what we
think the severity is and why, and if we disagree with your assessment we will
say so plainly rather than quietly downgrade it.

There is no bounty. This is an unfunded project.

## ⚠️ Before you send us a trace or a log

`signet serve -trace-file` produces a diagnostic trace. **Read it before you
send it.** It is plain text, one JSON object per line, and skimming it is the
point.

**A trace does NOT contain** secret values, tokens, private keys, or the
contents of anything sealed. Bearer credentials appear only as a salted digest
(`r:...`) which is useless outside that one file — the salt is random per
process.

**A trace DOES contain**, and this is the part to think about:

| In the file | Why it matters to you |
|---|---|
| Resource paths, e.g. `/secrets/prod/acme-corp/db` | The path is not the secret — but it says a secret by that name exists, and paths often carry **customer, project, or hostname**. |
| Principal, binding and activation identifiers | Reveals the shape of who has access to what. |
| Role and scope names | Reveals your authorization structure. |
| Route patterns, status codes, timings | Low sensitivity, but reveals traffic shape. |

**If your paths name customers, redact them before sending.** We would rather
have a trace with `/secrets/prod/CUSTOMER-A/db` in it than not have one — the
structure is what makes it diagnostic, not the literal name.

And if you would rather not send one at all, that is a completely reasonable
answer. Say so and we will work from a description. Nobody should have to
choose between getting help and disclosing their deployment.

The same applies to `signet audit` output and to anything from `/metrics`
(which uses route *patterns*, never concrete paths, precisely so it can be
scraped safely).

## Supported versions

Signet is **pre-1.0 and not yet recommended for production**. Security fixes
land on `main` and in the most recent tag. There is no long-term support
branch and there will not be one before 1.0.

## What we already know is wrong

`docs/pentest/REGISTER.md` lists every finding from an adversarial review,
fixed and open, by ID and severity.

**Reproduction detail for open findings is deliberately withheld** and
published per finding once it is fixed. That is ordinary coordinated
disclosure, applied to ourselves: a write-up is a working attack guide, and
publishing one against a version people are running helps the wrong people
first.

If you are running Signet and need to assess exposure to a specific open ID
before it is fixed, email us and say which — we will share the detail with
someone who has a deployment to protect.

## Threat model

`docs/01-threat-model.md` is the full STRIDE pass. The short version of what
Signet does **not** currently defend against:

- **An attacker who owns a node** can forge everything after the last witnessed
  audit checkpoint. Witnessing proves a history is an append-only continuation
  of what a peer saw before; it does not prove that history is complete or
  honest. `docs/11-operations.md` states this limit precisely.
- **A parent domain** can always mint into a subordinate child's namespace.
  This is inherent to a PKI hierarchy, is stated rather than papered over
  (`docs/02-trust-topology.md`), and is why sovereign domains exist.
- **A node that stops seeking witnessing** hides indefinitely. Absence of
  conflict is not evidence of integrity. There is no cadence enforcement yet
  (finding F5).
