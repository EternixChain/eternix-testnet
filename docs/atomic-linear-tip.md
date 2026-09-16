# Atomic Linear-Tip Application

The node rejects a stale active slot before execution, then stages locally produced slot results
against a clone of in-memory protocol state. The current local builder selects and executes its
body on that overlay. The completed candidate is canonically encoded and decoded, checked for
commitments, required to extend the current canonical tip by exactly one slot, recorded, and
processed through boundary transitions before the staged state is installed. If staged execution or
the persistence boundary fails, the candidate is discarded without installing balances, validator
state, mempool removals, block indexes, history, rewards, or accounting changes. Locally produced
blocks are broadcast only after successful installation.

This is an in-memory atomicity boundary only. The prototype has no durable state database yet; the
fallible persistence boundary exists so a storage backend can preserve the same install-or-discard
property. It must not be interpreted as crash-safe persistence.

## Intentionally Disabled Paths

- All remote `BLOCK` messages are decoded and then rejected. Transaction-bearing remote blocks are
  not executed, remote validator blocks are not accepted because blocks have no authentication, and
  remote protocol blocks are not applied because miss and collision authorization remain undefined.
- Late block replacement is not part of the staged linear-tip path. The existing legacy correction
  helpers remain outside it and have no active P2P ingress.
- The staged path does not add transaction signature verification, nonce rules, fee validation,
  raw-Ethereum replay, semantics for undefined transaction kinds, miss penalties, collision rules,
  state roots, receipts, or block signatures.

The V1 canonical transaction and block serialization, block hashes, and reserved roots are unchanged.
