# 18 — Hardware seal verification

**Status: SoftHSM2 verified 2026-08-18. Real hardware pending (Pico2HSM).**

## What was wrong

`PKCS11Seal.Wrap` passed a **NULL IV** to `CKM_AES_GCM` and read one back out of
the mechanism parameters, assuming the token had generated it.

`CK_GCM_PARAMS` is an *input* structure in PKCS#11 v2.40. Who generates the IV
is underspecified, implementations disagree, and v3.0 added a separate
message-based interface precisely because of that ambiguity.

Measured against SoftHSM2: **it wrote nothing back.** Every `Blob` carried an
empty nonce and every wrap ran under the same IV.

That is keystream reuse, and it was proven rather than inferred — two wraps of
known plaintext gave

```
C1 ^ C2 = 0303...03
P1 ^ P2 = 0303...03
```

exactly equal, which is the signature of AES-GCM degenerating to CTR mode with a
repeated keystream. **Anyone holding two wrapped blobs could recover the XOR of
the two secrets.** Under this seal that means the root key and every DEK.

## The fix

Signet generates the IV itself (12 random bytes) and stores the one it chose,
rather than reading one back. This removes the question instead of answering it,
and it is the portable choice: a token that would have generated its own IV
accepts a supplied one, while a token that expects a supplied IV cannot work any
other way.

`Unwrap` refuses a blob whose nonce is not 12 bytes, and says what it means:
material wrapped before the fix was all encrypted under one IV and should be
treated as compromised and re-wrapped.

## The tests, and why these ones

`internal/seal/pkcs11_gcm_test.go`, run by `make test-hsm`.

| Test | What it settles |
|---|---|
| `WrapUsesAFreshIVEachTime` | The decisive one: identical plaintext twice. Identical ciphertext means a fixed IV. Also rejects an empty or all-zero IV. |
| `IVsDoNotRepeatOverManyWraps` | 64 wraps, no repeat. One comparison can pass by luck; this catches a small counter or a per-session reseed. |
| `UnwrapDependsOnTheStoredIV` | Corrupt the stored IV and unwrapping must fail. If it succeeds, the stored IV is decorative and the real one lives inside the token. |
| `AADBinds` | Wrapped material cannot be moved to a different purpose. |
| `CiphertextIsAuthenticated` | One flipped bit anywhere fails — what distinguishes GCM from raw CTR. |
| `TagLength` | Overhead is exactly 16 bytes, so the token is not silently using a shorter tag. |

The general principle: **for a token, measure rather than read the
specification.** Every claim here is about observed behaviour of a specific
implementation, because that is the only thing that turned out to be true.

## Fixed alongside: key identity across a rotation

`KeyID()` was `token/label` — a location, not an identity. A key regenerated
under the same label reported the *same* ID as its predecessor, and
`RewrapRootKey` treats a matching KeyID as "already moved". So rotating to a
same-label successor **skipped every blob**: `seal status` showed a clean
rotation while the material was still wrapped by the key the operator believed
retired. That is the worst shape a rotation bug can take, because it looks like
success.

The fingerprint now comes from the key object. Measured on SoftHSM2, deleting
the key and regenerating it under the identical label:

```
before   signet/signet-seal/kcv:4470aa
after    signet/signet-seal/kcv:8328cd
```

`PKCS11Seal.Unwrap` also now refuses a blob wrapped by a different key, which
`FileSeal` had always done — previously the wrong key was simply tried and the
failure surfaced as an opaque decrypt error.

The skip test is deliberately strict: unknown means *not* the same key.
Re-wrapping something already wrapped correctly is harmless; skipping a rewrap
that was needed is not.

## Still to verify on real hardware

SoftHSM2 is a software simulator. It exercises the same code path, which is why
it is worth having, but its GCM handling is not evidence about a real token.

Target: **Pico2HSM**. Two things to establish before any hardware-seal guidance
ships:

1. **Does it implement `CKM_AES_GCM` at all?** The Pico HSM descends from
   SmartCard-HSM, whose mechanism list is narrower than SoftHSM's. If GCM is
   absent, that is a finding rather than a failure — it means the seal needs a
   fallback (`CKM_AES_KEY_WRAP_PAD`, or wrapping a software DEK) and the
   hardware-seal story needs rewriting for that class of device.
2. **Do all six tests above pass unmodified?** Point `SIGNET_TEST_PKCS11` at the
   token and run `make test-hsm`. Any difference from SoftHSM is exactly the
   kind of divergence this file exists to catch.

Worth checking at the same time, because they are cheap once a token is in hand:

- Non-extractability: `pkcs11_signer_test.go` asserts the token refuses to
  export a key marked `CKA_SENSITIVE`/`CKA_EXTRACTABLE=false`. A device that
  quietly allows it defeats the whole point of hardware custody.
- Whether the key fingerprint works on that device. `KeyID()` is now
  `token/label/<fingerprint>`, where the fingerprint is `CKA_CHECK_VALUE` if the
  token provides one and `CKA_ID` otherwise. SoftHSM2 provides the check value;
  a device offering **neither** reports `unidentified`, and rotation then never
  skips — safe, but it means `seal status` cannot confirm a rotation is
  complete. `TestHSMKeyIDDistinguishesASuccessorKey` skips with that
  explanation rather than passing vacuously, so the skip is the signal.
- PIN handling and lockout behaviour on repeated failures, which differs
  sharply between simulators and real devices.
