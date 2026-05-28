# Forge Standard Library (`std.*`)

The Forge standard library is a set of built-in modules provided by the compiler.
Import any module with `use std.<name>` — no files to download, no external dependencies.

---

## Quick Reference

| Module | Import | Contents |
|--------|--------|----------|
| `math` | `use std.math` | Arithmetic, sqrt, compound interest |
| `access` | `use std.access` | Role-based access control |
| `crypto` | `use std.crypto` | Hashing, signature verification, Merkle proofs |
| `tokens` | `use std.tokens` | ERC20-equivalent token operations |
| `governance` | `use std.governance` | Proposal creation, voting, execution |
| `oracle` | `use std.oracle` | Price feed reading |
| `strings` | `use std.strings` | String manipulation utilities |
| `arrays` | `use std.arrays` | Collection utilities (sort, reverse) |

---

## `std.math` — Arithmetic & Fixed-Point Math

```zeph
use std.math
```

### `math.sqrt(value)`

Compute the integer square root.

| Param | Type | Description |
|-------|------|-------------|
| `value` | `u256` | The value to take the square root of |

**Returns:** `u256`

**Example:**
```zeph
pure compute_sqrt(x is u256) gives u256:
    give back math.sqrt(x)
```

**Uniswap-style sqrt price:**
```zeph
pure sqrt_price(reserve_a is u256, reserve_b is u256) gives price18:
    give back math.sqrt(reserve_a times PRECISION divided by reserve_b)
```

---

### `math.compound(principal, rate, periods)`

Compute compound interest: `principal × (1 + rate)^periods`.

| Param | Type | Description |
|-------|------|-------------|
| `principal` | `u256` | Starting amount |
| `rate` | `percent` | Interest rate per period (e.g. `5.0` = 5%) |
| `periods` | `u64` | Number of compounding periods |

**Returns:** `u256`

**Example:**
```zeph
pure calculate_compound_interest(
    principal is u256,
    rate is percent,
    periods is u64
) gives u256:
    give back math.compound(principal, rate, periods)
```

---

### `math.pow(base, exponent)`

Raise `base` to the power of `exponent`.

| Param | Type | Description |
|-------|------|-------------|
| `base` | `u256` | The base value |
| `exponent` | `u256` | The exponent |

**Returns:** `u256`

**Example:**
```zeph
pure power(x is u256, exp is u256) gives u256:
    give back math.pow(x, exp)
```

---

### `math.min(a, b)` / `math.max(a, b)`

Return the smaller/larger of two values.

| Param | Type | Description |
|-------|------|-------------|
| `a` | `u256` | First value |
| `b` | `u256` | Second value |

**Returns:** `u256`

**Example:**
```zeph
pure clamp(val is u256, lo is u256, hi is u256) gives u256:
    give back math.min(math.max(val, lo), hi)
```

---

### `math.abs(value)`

Compute the absolute value.

| Param | Type | Description |
|-------|------|-------------|
| `value` | `i256` | The signed integer value |

**Returns:** `i256`

**Example:**
```zeph
pure abs_delta(a is i256, b is i256) gives i256:
    give back math.abs(a minus b)
```

---

## `std.access` — Role-Based Access Control

```zeph
use std.access
```

### `access.grant(role, account)`

Grant a role to an account.

| Param | Type | Description |
|-------|------|-------------|
| `role` | `ShortStr` | The role name (e.g. `"OPERATOR"`, `"ADMIN"`) |
| `account` | `Account` | The account receiving the role |

**Returns:** `void`

---

### `access.revoke(role, account)`

Revoke a role from an account.

| Param | Type | Description |
|-------|------|-------------|
| `role` | `ShortStr` | The role name |
| `account` | `Account` | The account losing the role |

**Returns:** `void`

---

### `access.has_role(role, account)`

Check whether an account holds a role.

| Param | Type | Description |
|-------|------|-------------|
| `role` | `ShortStr` | The role name |
| `account` | `Account` | The account to check |

**Returns:** `bool`

**Example — full RBAC pattern:**
```zeph
use std.access

contract RBACExample:
    has:
        roles is Map[ShortStr → Set[Account]]

    action grant_role(role is ShortStr, account is Account):
        only admin_authority
        access.grant(role, account)

    action revoke_role(role is ShortStr, account is Account):
        only admin_authority
        access.revoke(role, account)

    guard only_role(role is ShortStr):
        need access.has_role(role, caller) else panic "unauthorized"

    action restricted_operation():
        guard only_role("OPERATOR")
        // Only OPERATOR role holders can execute this
```

---

## `std.crypto` — Cryptography Primitives

```zeph
use std.crypto
```

### `crypto.keccak(a, b)`

Compute the Keccak-256 hash of two concatenated hashes.

| Param | Type | Description |
|-------|------|-------------|
| `a` | `Hash` | First 32-byte hash |
| `b` | `Hash` | Second 32-byte hash |

**Returns:** `Hash`

**Example:**
```zeph
pure hash_pair(a is Hash, b is Hash) gives Hash:
    give back crypto.keccak(a, b)
```

---

### `crypto.bls_verify(message, signature, pubkey)`

Verify a BLS12-381 signature.

| Param | Type | Description |
|-------|------|-------------|
| `message` | `Hash` | The 32-byte signed message hash |
| `signature` | `Signature` | The 96-byte BLS signature |
| `pubkey` | `PublicKey` | The 48-byte BLS public key |

**Returns:** `bool`

**Example:**
```zeph
view verify_sig(message is Hash, sig is Signature, key is PublicKey) gives bool:
    give back crypto.bls_verify(message, sig, key)
```

---

### `crypto.merkle_verify(leaf, proof, root)`

Verify a Merkle proof against a root hash.

| Param | Type | Description |
|-------|------|-------------|
| `leaf` | `Hash` | The leaf hash being proven |
| `proof` | `Hash` | A sibling hash from the proof path |
| `root` | `Hash` | The Merkle root hash |

**Returns:** `bool`

**Example:**
```zeph
view verify_merkle_proof(leaf is Hash, proof is Array[Hash, 16], root is Hash) gives bool:
    give back crypto.merkle_verify(leaf, proof[0], root)
```

---

### `crypto.sha256(data)`

Compute the SHA-256 hash of arbitrary bytes.

| Param | Type | Description |
|-------|------|-------------|
| `data` | `Bytes` | The input data |

**Returns:** `Bytes32`

**Example:**
```zeph
pure compute_hash(data is Bytes) gives Bytes32:
    give back crypto.sha256(data)
```

---

## `std.tokens` — Token Operations (ERC20-equivalent)

```zeph
use std.tokens
```

### `tokens.transfer(from, to, amount)`

Transfer tokens from one account to another (caller must be the `from` account or have an allowance).

| Param | Type | Description |
|-------|------|-------------|
| `from` | `Account` | The sender |
| `to` | `Account` | The recipient |
| `amount` | `u256` | The amount to transfer |

**Returns:** `void`

---

### `tokens.transfer_from(sender, from, to, amount)`

Transfer tokens on behalf of another account (caller must have an allowance from `from`).

| Param | Type | Description |
|-------|------|-------------|
| `sender` | `Account` | The caller (allowance holder) |
| `from` | `Account` | The source account |
| `to` | `Account` | The destination account |
| `amount` | `u256` | The amount to transfer |

**Returns:** `void`

---

### `tokens.approve(spender, amount)`

Approve an account to spend tokens on your behalf.

| Param | Type | Description |
|-------|------|-------------|
| `spender` | `Account` | The account being approved |
| `amount` | `u256` | The allowance amount |

**Returns:** `void`

---

### `tokens.balance_of(account)`

Get the token balance of an account.

| Param | Type | Description |
|-------|------|-------------|
| `account` | `Account` | The account to check |

**Returns:** `u256`

---

### `tokens.allowance(owner, spender)`

Get the remaining allowance that `spender` can spend from `owner`.

| Param | Type | Description |
|-------|------|-------------|
| `owner` | `Account` | The token owner |
| `spender` | `Account` | The approved spender |

**Returns:** `u256`

---

## `std.governance` — Voting & Governance

```zeph
use std.governance
```

### `governance.create_proposal(target, calldata, description)`

Create a new governance proposal.

| Param | Type | Description |
|-------|------|-------------|
| `target` | `Program` | The contract to execute |
| `calldata` | `Bytes` | Encoded function call data |
| `description` | `String` | Human-readable proposal description |

**Returns:** `u64` (proposal ID)

---

### `governance.cast_vote(proposal_id, in_favor, votes)`

Cast votes on an active proposal.

| Param | Type | Description |
|-------|------|-------------|
| `proposal_id` | `u64` | The proposal to vote on |
| `in_favor` | `bool` | `yes` for, `no` against |
| `votes` | `u256` | Number of votes to cast |

**Returns:** `void`

---

### `governance.execute_proposal(proposal_id)`

Execute an approved proposal.

| Param | Type | Description |
|-------|------|-------------|
| `proposal_id` | `u64` | The proposal to execute |

**Returns:** `void`

---

### `governance.get_vote_count(proposal_id)`

Get the total votes on a proposal.

| Param | Type | Description |
|-------|------|-------------|
| `proposal_id` | `u64` | The proposal to query |

**Returns:** `u256`

**Example:**
```zeph
use std.governance

contract GovExample:
    has:
        proposals is Map[u64 → Proposal]
        next_id is u64

    setup():
        next_id = 1

    action propose(target is Program, data is Bytes, desc is String):
        only governance_authority
        let pid = governance.create_proposal(target, data, desc)
        mine.proposals[pid] = Proposal{
            id = pid, target = target, description = desc,
        }

    action vote(pid is u64, support is bool):
        let voter_weight = compute_voting_power(caller)
        governance.cast_vote(pid, support, voter_weight)

    action execute(pid is u64):
        only governance_authority
        governance.execute_proposal(pid)
```

---

## `std.oracle` — Price Feed Helpers

```zeph
use std.oracle
```

### `oracle.get_price(feed)`

Get the current price from an oracle feed.

| Param | Type | Description |
|-------|------|-------------|
| `feed` | `Account` | The oracle feed account |

**Returns:** `price18`

---

### `oracle.get_price_at(feed, timestamp)`

Get the price at a specific past timestamp from an oracle feed.

| Param | Type | Description |
|-------|------|-------------|
| `feed` | `Account` | The oracle feed account |
| `timestamp` | `Timestamp` | The point in time to query |

**Returns:** `maybe price18` (returns `nothing` if no data at that time)

---

### `oracle.is_stale(feed)`

Check whether an oracle feed's data is stale.

| Param | Type | Description |
|-------|------|-------------|
| `feed` | `Account` | The oracle feed account |

**Returns:** `bool`

**Example:**
```zeph
use std.oracle

contract PriceConsumer:
    accounts:
        zeph_usd is Oracle[price18] at known.ZephUsdOracle readonly

    view get_price() gives price18:
        need not oracle.is_stale(zeph_usd) else "stale price"
        give back oracle.get_price(zeph_usd)

    view get_historical_price(at is Timestamp) gives maybe price18:
        give back oracle.get_price_at(zeph_usd, at)
```

---

## `std.strings` — String Utilities

```zeph
use std.strings
```

### `strings.concat(a, b)`

Concatenate two strings.

| Param | Type | Description |
|-------|------|-------------|
| `a` | `String` | First string |
| `b` | `String` | Second string |

**Returns:** `String`

---

### `strings.substring(s, start, end)`

Extract a substring.

| Param | Type | Description |
|-------|------|-------------|
| `s` | `String` | The source string |
| `start` | `u64` | Starting index (0-based) |
| `end` | `u64` | Ending index (exclusive) |

**Returns:** `String`

---

### `strings.contains(s, substr)`

Check if a string contains a substring.

| Param | Type | Description |
|-------|------|-------------|
| `s` | `String` | The source string |
| `substr` | `String` | The substring to search for |

**Returns:** `bool`

---

### `strings.to_upper(s)` / `strings.to_lower(s)`

Convert a string to upper/lower case.

| Param | Type | Description |
|-------|------|-------------|
| `s` | `String` | The source string |

**Returns:** `String`

**Example:**
```zeph
use std.strings

action process_name(name is String):
    let normalized = strings.to_lower(name)
    need strings.contains(normalized, "token") else "not a token name"
    let prefix = strings.substring(normalized, 0, 5)
    let full = strings.concat("prefix_", name)
```

---

## `std.arrays` — Collection Utilities

```zeph
use std.arrays
```

### `arrays.sort(arr)`

Sort a list in place.

| Param | Type | Description |
|-------|------|-------------|
| `arr` | `List` | The list to sort |

**Returns:** `void`

---

### `arrays.reverse(arr)`

Reverse a list in place.

| Param | Type | Description |
|-------|------|-------------|
| `arr` | `List` | The list to reverse |

**Returns:** `void`

**Example:**
```zeph
use std.arrays

action process_leaderboard(entries is List[Account]):
    arrays.sort(entries)
    arrays.reverse(entries)  // highest first
```

---

## Import Rules

- `use std.<name>` imports a built-in module. No file path needed.
- Module functions are called with the module prefix: `math.sqrt(x)`.
- Module names become accessible identifiers in scope.
- Unknown modules produce a no-op (no error, no registration).

## Type Compatibility

When calling stdlib functions, the compiler validates argument types against the
declared signatures. Type mismatches produce a compile-time error:

```zeph
use std.math
pure bad() gives u256:
    give back math.sqrt("hello")  // COMPILE ERROR: type mismatch
```
