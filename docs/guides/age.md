# `age` encryption + secretspec

Encrypt files — and a project's secrets — to a key that only opens with the
device in your hand. Two layers, and this page is in that order: `age` on its
own, then [secretspec](https://github.com/cachix/secretspec) on top of it.

RS-Key drives both over **FIDO2, not the smart card**. The plugin asks for the
CTAP `hmac-secret` extension over CTAPHID, so nothing here wants PKCS#11,
OpenSC, or a particular reader name, and the stock build works as shipped.
[PIV](piv.md) is the other route to `age` and buys something different — the
trade-off is at the [end of this page](#which-route).

> **What you are trusting.** `hmac-secret` unwraps an `age` identity **into host
> memory**. Whoever lifts it from there decrypts your past and future files with
> no token at all. The device gates access; it is not a wall the key never
> crosses. On the [PIV route](piv.md) the private key does stay on the card.
> [threat-model.md](../threat-model.md) draws that line, and this page sits on
> the permissive side of it.

## What the token actually does

FIDO2 has no asymmetric decryption to offer, so nothing here is "decrypted by
the key". `hmac-secret` returns 32 deterministic bytes for a given (credential,
salt) pair; the plugin uses them to unwrap an `age` identity it stored in the
recipient, or in the encrypted file's own stanza.

What it costs on the device: nothing persistent. The credential is
**non-discoverable**, so it takes no slot in the credential store and shows up
in no passkey list. Its relying party is `age-encryption.org`, and the same
token mints as many independent recipients as you care to ask for.

## Install

```sh
nix shell nixpkgs#age nixpkgs#age-plugin-fido2-hmac
```

Or from source — it is Go plus `libfido2`:

```sh
go install github.com/olastor/age-plugin-fido2-hmac/cmd/age-plugin-fido2-hmac@latest
```

`age` finds the plugin by name on `PATH`; there is nothing to configure. On
Linux you need the FIDO udev rules, same as for [SSH keys](ssh.md) — see
[linux.md](../linux.md). The plugin is pre-1.0 and ships no Windows build.

## Create an identity

```sh
age-plugin-fido2-hmac -g > identity.txt
```

It walks you through, in this order:

1. finds the token (it waits up to 50 s, so plug in whenever),
2. asks for the **FIDO PIN**, but only if one is set on the device,
3. asks for a **touch**, and mints the credential,
4. asks whether to **require the PIN for decryption** — again only if a PIN is
   set, otherwise decryption is touch-only,
5. asks whether you want a **separate identity**. Yes gives you a file to keep;
   no is "data-less", where the credential id travels inside every encrypted
   file and anyone holding one can read it.

Its yes/no questions want a **digit, not a letter** — `1` for yes, `2` for no —
and it reads them straight from `/dev/tty`, so the prompts survive redirecting
stdout to a file but a pipe on stdin will not answer them.

`-g` writes the recipients into the file as comment lines. Pull **one** out and
encrypt to it:

```sh
grep '^# public key:' identity.txt | sed 's/^.*: //' > recipient.txt
echo 'secret' | age -R recipient.txt -o secret.age
age -d -i identity.txt secret.age          # with an identity file
age -d -j fido2-hmac secret.age            # data-less
```

An ordinary run prints **two** of them — a plain `age1…` X25519 recipient and,
because deriving it is nearly free, an `age1pq…` post-quantum hybrid on a
`# public key (pq safe):` line. Take one or the other, never both: `age` refuses
a roster that mixes post-quantum and classic recipients. The grep above anchors
on the colon so it picks the classic one; swap the pattern to
`'^# public key (pq safe):'` for the hybrid.

Do not pattern-match on `age1fido2-hmac1` — that prefix appears only in the
symmetric mode. To recover a recipient from an identity later,
`age-plugin-fido2-hmac -y identity.txt` derives it, but that one needs the token.

**Encryption needs no token.** The recipient carries an X25519 public key, so
`age -R` runs on a machine that has never seen the device. Only decryption
touches it. (`-s`/`--symmetric` is the exception: it re-salts every encryption
and wants the token both ways.)

### Algorithms RS-Key accepts

`-a` picks the credential's signature algorithm. It never signs anything here —
`hmac-secret` is the whole point — but the device still has to accept it at
enrollment:

| `-a` | COSE | On RS-Key |
|---|---|---|
| `es256` | −7 | the default, works |
| `eddsa` | −8 | works on every shipped build |
| `rs256` | −257 | **refused.** RS-Key advertises ES256, ES384, ES512 and EdDSA — no RSA |

If you pick `rs256` the enrollment fails with an unsupported-algorithm error
before anything is written. Nothing is left behind; just rerun with `es256`.

## PIN and touch

| Action | FIDO PIN | Touch |
|---|---|---|
| `-g` enrollment, no PIN on the device | — | once |
| `-g` enrollment, PIN set | once | once |
| Encrypt (`age -R`) | — | — |
| Decrypt, require-PIN answered *no* | — | once |
| Decrypt, require-PIN answered *yes* | once | once |

> **On an `always-uv` build, answer *yes*.** The shipped image leaves `alwaysUv`
> off, so the touch-only path above is the default. Build with
> `--features always-uv` (or flip it with `ykman fido config toggle-always-uv`)
> and a `makeCredential` carrying no PIN token is refused whatever else it asks
> for — see [`tests/16_always_uv_gate.py`](https://github.com/TheMaxMur/RS-Key/blob/main/tests/16_always_uv_gate.py).
> So set a FIDO PIN first, then answer *yes* to the require-PIN question.

RS-Key packs the whole credential into the credential id, because a
non-discoverable credential has nowhere else to live. That id rides inside the
identity string, and inside each encrypted file's stanza when you go data-less,
so both run long. The recipient does not carry it — an ordinary run hands you a
plain X25519 `age1…`, the same length as any other.

## secretspec on top

[secretspec](https://github.com/cachix/secretspec) separates *which* secrets a
project needs from *where* they live. The declaration goes in `secretspec.toml`
and gets committed; the values go to a provider. Its `age` provider keeps them
in one `age`-encrypted blob, which is exactly the file the plugin above can
lock.

```toml
[project]
name = "my-app"
revision = "1.0"

[providers]
vault = "age://secrets.age?identity=identity.txt&recipients-file=recipient.txt"

[profiles.default]
DATABASE_URL = { description = "PostgreSQL connection string", providers = ["vault"] }
```

```sh
secretspec set DATABASE_URL          # no token — writes to the recipient
secretspec get DATABASE_URL          # touch (and PIN, if required)
secretspec run -- ./my-app           # same, secrets exported as env vars
```

The asymmetry is the useful part: **writing a secret never needs the key**, so
CI and colleagues can add values against the committed recipient file, and only
reading asks for the token. Commit `secrets.age` and `recipient.txt`; keep
`identity.txt` off the repo, or drop it entirely and let the stanza carry the
credential id.

Two things that will bite you:

- **secretspec can ask for a `--reason`.** Its `require_reason` policy defaults
  to `"agents"`, and every command above is refused in an environment it reads
  as one until you pass `--reason "<why>"` or set `SECRETSPEC_REASON`. Put
  `require_reason = false` in `[project]` to switch it off.
- **Everyone on the roster reads the whole blob.** `age` recipients decrypt the
  file, not individual keys. Split anything with a narrower audience into its
  own blob with its own recipients file.

## Which route

Both end at `age`; they differ in where the key is when it is used.

| | FIDO2 `hmac-secret` (this page) | [PIV](piv.md) + `age-plugin-yubikey` |
|---|---|---|
| Transport | CTAPHID | CCID / PKCS#11 |
| Stock build | works | wants the `VIDPID=Yubikey5` build, or `opensc-pkcs11.so` — the plugin matches on the reader name |
| Key at decryption | identity in host RAM | private key stays on the card |
| Device state | none — non-discoverable credential | occupies a PIV slot |
| Recipients per token | unlimited | one per slot |

Pick `hmac-secret` for convenience on a stock key and for secrets you would
otherwise leave in a `.env`. Pick PIV when "the key never leaves the card" is
the property you actually need.

## What was measured

The CTAP exchange below is the plugin's own, taken from its source at `c490421`
and replayed call for call.

**On a board.** RS-Key's `getInfo` advertises `hmac-secret` (and
`hmac-secret-mc`), so the plugin's device filter accepts it. With `alwaysUv`
turned on and a PIN set, the plugin's `makeCredential` carrying no PIN token is
refused `PUAT_REQUIRED` — the warning above, on hardware — while `rs256` is
refused `UNSUPPORTED_ALGORITHM` first, so the algorithm check runs ahead of the
UV gate. An `authenticatorReset` brings the shipped image back with `alwaysUv`
**off**, which is the state the touch-only path assumes.

**On the software emulator** (`tools/emu`, see [testing.md](../testing.md)):

- `makeCredential` (relying party `age-encryption.org`, non-discoverable,
  `hmac-secret`) is served for `es256` and `eddsa` and refused for `rs256`.
  Credential ids came back at 131 and 135 bytes.
- `getAssertion` returns a 32-byte `hmac-secret` output, identical across calls
  for one salt and different for another — the contract the plugin checks before
  it will unwrap anything. [`tests/24_extensions.py`](https://github.com/TheMaxMur/RS-Key/blob/main/tests/24_extensions.py)
  asserts the same thing as part of the suite.
- secretspec's `age` provider round-trips `set` / `get` / `run` / `check` with a
  plain identity and the provider declared in `secretspec.toml` as above, and it
  spawns `age-plugin-fido2-hmac --age-plugin=identity-v1` when the identity is a
  plugin one — so plugin identities are wired through it.

**Still unmeasured: a full round trip driven by the plugin itself** — enroll,
encrypt, decrypt — and the same through secretspec. Every step of it needs a
physical touch, so it takes someone at the device; nothing in the exchange is
in doubt, only the end-to-end run.
