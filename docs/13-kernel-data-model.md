# 13 — Kernel data model

**Status: Draft** (designed in session 2026-08-16; pending Fable cold-read
and first-vertical-slice validation)

The kernel is what every dialect serializes over and every property test
asserts against — so it is specified here concretely, not hand-waved.

## Four graphs, not one (the AD lesson)

Active Directory conflates four distinct structures into one replicated
directory with automatic transitive trust — which is precisely why a *forest*,
not a *domain*, becomes AD's security boundary. Signet keeps them separate so
the **domain** stays the blast-radius boundary (charter / E-01):

1. **Resource tree** — the hierarchical namespace (`/clusters/svc/apps/eso`)
   where roles bind and scope is defined.
2. **Principal set** — the identities that can hold credentials.
3. **Authorization set** — role definitions + bindings of
   *(subject, role, scope, conditions)*.
4. **Trust graph** — which domains trust which, and how (parent/child chains,
   peer federations).

## Entities

```
Principal   { id: path            # e.g. /people/mcarey, /clusters/svc/apps/eso
              kind                 # human | service | machine | workload | group | domain
              home_domain
              credential_refs      # attestation anchors / keys that authenticate it
              attributes }         # free-form, non-authoritative metadata

Group       # a Principal of kind=group; others are MEMBERS of it
            { members: [ { principal_ref, not_before?, not_after? } ] }  # membership may be time-bound

Role        { name                 # bare label, the narrow-waist RP-facing claim
              domain               # roles are namespaced to a domain
              description }         # FLAT — no role nesting (audit-preserving)

Binding     { subject_ref          # a Principal or Group (may be a cross-domain reference)
              role
              scope: path          # binds here, inherits DOWNWARD
              conditions           # tier (06), required amr/freshness, etc.
              grantor              # who created it (must satisfy delegation-narrows)
              not_before?, not_after?      # time-bound => JIT grant
              activation_required? }       # true => eligible-not-active (PAM/sudo)

MappingRule { verifier             # which attestation verifier (04)
              evidence_matcher     # (issuer, subject, claims…) pattern
              produces: principal_ref
              constraints }        # scoped to the author's subtree (E-01 K-1)

TrustLink   { kind                 # parent | child | peer
              target_domain
              mode                 # subordinate | sovereign (02)
              anchors / cross_cert }
```

## Scope & path semantics (E-01 K-4)

- Paths are **canonicalized**; comparison is **component-wise prefix**, never
  substring — `/clusters/lab` does **not** match `/clusters/lab-2`.
- A binding at scope S applies at S and everything below it; **delegation only
  narrows** — a grantor authorized at S may only create bindings/rules/mappings
  producing subjects and grants **at or below S**, enforced at write time and
  re-checked at issuance.
- Grants are **additive only**; no first-class deny (preserves local reasoning).

## Cross-domain references: explicit, signed — never transitive (Decided)

"Child inherits the parent's graph" (AD-forest ergonomics) is offered **only in
subordinate mode**, and only as **reference, not replication or automatic
transitive trust**:

- The child stores only its own subtree. A binding at the child may reference a
  **parent** principal/role/group; that reference resolves against a
  **cached, signed slice of the parent's graph** the parent periodically
  exports — so resolution is offline-capable.
- The child **imports** what it chooses to honor; trust flows only the
  direction configured. A compromised `aws` child therefore cannot assert
  rights up at `home` or sideways at `gcp`. This is the AD *ergonomics* without
  the AD *blast radius*.
- **Sovereign** children (their own root) import nothing implicitly; they
  federate as peers (02).

## JIT / PAM fall out of the model — no new machinery

Both mechanisms are just fields the role-ticket lifecycle (06) already honors,
because every ~15-min renewal re-evaluates policy:

- **JIT / time-bounded access** — a `not_after` on a Binding **or** on a Group
  membership (both supported). The grant simply stops being minted after T; no
  revocation sweep, no cleanup job. Used for temporary group provisioning and
  short-lived privileged bindings.
- **Role-sudo / PAM (eligible-vs-active)** — `activation_required: true` makes
  a principal *eligible* for a role without *holding* it. Activation is a
  **runtime request** (not a config commit) that the kernel grants only with
  step-up (tier-4 WebAuthn) + optional approval, minting a short-TTL credential
  carrying the role, fully logged. This is the Azure-PIM eligible/active split.

**Narrow waist preserved:** group membership and eligibility resolve
**server-side into the flat role-claim set at issuance** — the RP still sees
only `groups: [infra-admin]`, never nesting. The issuance log records the
resolved set **and the why** (which binding / activation / approval), so audit
stays tractable.

## Desired-state vs runtime-state (load-bearing for PAM)

- **Desired state** (declarative, git/reconciled — doc 14): principals, groups,
  roles, bindings, mapping rules, trust links — *who is eligible for what*.
- **Runtime state** (dynamic, never in git): live sessions, minted credentials,
  **JIT activations**. You *declare eligibility*; you *activate at runtime*
  through an API. `sudo` must never require a git push (too slow, too
  permanent, and it puts elevation in version control).

## Secrets in the same keyspace

KV secrets (v1: static KV v2 only; dynamic/leased secrets explicitly deferred)
live in the same bbolt FSM keyspace (03) as versioned entries. The Vault-compat
dialect (E-06) serializes over them. Version history is a **kernel storage
requirement**, not dialect state.

## Open / for cold-read (E-13)

- Attribute model: how far do non-authoritative principal attributes go before
  they tempt ABAC creep? (Keep policy = data, not code.)
- Group-of-groups: members are principals; a group can contain a group, but
  resolution stays flat at issuance — confirm no cycles / bounded depth.
- Exact cached-parent-slice format + staleness policy (ties to E-12 bundles).
- Whether roles ever carry structured attributes or stay pure labels (05).
