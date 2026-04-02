# Exfer: A Peer-to-Peer Settlement Protocol for Autonomous Machines

Version 1.0.0

---

## Overview

Currency, contracts, and enforcement make it possible for human beings to work collectively — achieving outcomes no single human can reach alone. The same applies to autonomous machines. Exfer provides all three, native to autonomous machines, with finality. The protocol is the minimum infrastructure that turns independent agents into an economy.

Exfer is a permissionless proof-of-work blockchain for autonomous machine-to-machine commerce. It combines Argon2id memory-hard mining, an extended UTXO model, and Exfer Script — a total functional combinator language — for transaction conditions. Miners solve proof-of-work puzzles to produce blocks; transactions transfer value under conditions expressed as combinator programs that are statically typed, guaranteed to terminate, and have costs computable before execution.

All scripts terminate. Costs are statically computable before execution. The UTXO model eliminates global state and reentrancy. An autonomous agent can construct a transaction, compute its exact cost, and know with certainty that it will validate — without simulating execution, competing in a fee auction, or reasoning about concurrent state changes. There is no gas estimation. There is no mempool priority auction. Scripts are Merkleized — commit to the full program when locking funds, reveal only the executed path when spending.

This is operational context. It affects how an agent plans transactions: knowing costs are deterministic means precomputing fees, knowing scripts terminate means no timeout logic for validation, knowing there is no state contention means transactions can be constructed independently.

---

# Part I: Protocol Specification

## 1. Notation and Conventions

**Byte order.** All multi-byte integers are serialized in **little-endian** byte order unless stated otherwise. The sole exception: 256-bit values used in difficulty target comparisons and cumulative work are compared as **big-endian** unsigned integers (their byte-level representation is the numeric big-endian form).

**Integer types.** `u8`, `u16`, `u32`, `u64` denote unsigned integers of the stated bit width. `u128` is used as an intermediate type for overflow-safe arithmetic; it never appears on the wire.

**Hash256.** A 32-byte SHA-256 digest, stored and transmitted as a raw 32-byte sequence.

**VarBytes.** A variable-length byte string: `length(u16 LE) || data[length]`. Maximum data length: 65,535 bytes (u16 range).

**ceil_div(a, b).** Ceiling division. Computed as `(a + b - 1) / b` using u128 intermediate to prevent overflow of `a + b - 1`.

**Pseudocode.** All pseudocode is language-agnostic. `||` denotes byte concatenation. `[n]` denotes an array of `n` bytes. Indices are zero-based.

---

## 2. Data Types and Encoding

| Type | Wire size | Encoding |
|------|-----------|----------|
| u8 | 1 byte | unsigned integer |
| u16 | 2 bytes | little-endian |
| u32 | 4 bytes | little-endian |
| u64 | 8 bytes | little-endian |
| Hash256 | 32 bytes | raw bytes (big-endian as a 256-bit number) |
| VarBytes | 2 + length bytes | u16 LE length prefix, then data |
| Bool flag | 1 byte | 0x00 = absent/false, 0x01 = present/true |

---

## 3. Domain-Separated Hashing

All hash computations use domain-separated SHA-256. The construction is prefix-free:

```
domain_hash(separator, data) = SHA-256(len(separator) || separator || data)
```

where `len(separator)` is a single byte encoding the separator length (0–255). This ensures no domain separator is a prefix of another's encoding.

**Raw SHA-256** (without domain separation) is used only for:
- Block ID computation: `SHA-256(header_bytes)`
- SMT internal nodes: `SHA-256(left || right)`
- SMT leaf values: `SHA-256(output_bytes || height_u64_le || is_coinbase_u8)`
- Datum hashing: `SHA-256(datum_bytes)`

PoW password and salt derivation use `domain_hash` (i.e., `SHA-256(len_byte || separator || header_bytes)`), not raw SHA-256.

The complete domain separator catalog is in Appendix B.

---

## 4. Block Structure

### 4.1 Block Header

Fixed 156 bytes. All integers little-endian. Hash fields are raw 32-byte sequences.

| Offset | Size | Field | Type | Description |
|--------|------|-------|------|-------------|
| 0 | 4 | version | u32 | Protocol version. Must be 1. |
| 4 | 8 | height | u64 | Block height. Genesis = 0. |
| 12 | 32 | prev_block_id | Hash256 | Parent block's ID. Genesis = all zeros. |
| 44 | 8 | timestamp | u64 | Unix timestamp (seconds since epoch). |
| 52 | 32 | difficulty_target | Hash256 | Full 256-bit PoW target. |
| 84 | 8 | nonce | u64 | Miner-chosen value for PoW search. |
| 92 | 32 | tx_root | Hash256 | Merkle root of transaction hashes. |
| 124 | 32 | state_root | Hash256 | Sparse Merkle tree root of UTXO set. |

Total: **156 bytes**.

### 4.2 Block ID

```
block_id = SHA-256(header_bytes)
```

Input is the 156-byte serialized header. This is raw SHA-256 (no domain separator). Block ID is NOT the Argon2id hash.

### 4.3 Block Body

Serialized immediately after the header:

```
tx_count(u32 LE) || transaction[0] || transaction[1] || ... || transaction[tx_count-1]
```

- Transaction 0 must be the coinbase transaction.
- No other transaction may have the coinbase sentinel outpoint.
- Maximum block size: 4,194,304 bytes (4 MiB), measured on the full serialized block.

### 4.4 Transaction Merkle Root

The `tx_root` is a Merkle tree over **witness-committed transaction hashes** (WtxId), not TxId. This prevents block malleability by committing to all witness data.

**Leaf values:** For each transaction, compute `WtxId = domain_hash("EXFER-WTXID", full_serialization)`.

**Tree construction:**
1. If zero transactions: root = all-zero Hash256.
2. If one transaction: root = that transaction's WtxId.
3. If odd count: duplicate the last hash.
4. Pair adjacent hashes and compute parent: `domain_hash("EXFER-TXROOT", left || right)`.
5. Repeat until one hash remains.

### 4.5 State Root (Sparse Merkle Tree)

The state root commits to the complete UTXO set via a sparse Merkle tree of depth 256.

**Leaf key:**
```
leaf_key = domain_hash("EXFER-STATE", tx_id || output_index_le32)
```

**Leaf value:**
```
leaf_value = SHA-256(canonical_output_bytes || height_u64_le || is_coinbase_u8)
```

where `canonical_output_bytes` is the serialized TxOutput (Section 5.4), `height_u64_le` is the u64 LE block height at which the UTXO was created, and `is_coinbase_u8` is 0x01 if the UTXO came from a coinbase transaction, 0x00 otherwise.

**Empty subtree hashes:**
```
empty_hash[0] = [0x00; 32]
empty_hash[d] = SHA-256(empty_hash[d-1] || empty_hash[d-1])   for d = 1..256
```

**Internal nodes:**
```
node_hash = SHA-256(left_child_hash || right_child_hash)
```

**Path:** The 256 bits of the leaf key determine the path from root to leaf. Bit 0 (MSB of byte 0) selects left (0) or right (1) at depth 0. Bit 255 (LSB of byte 31) selects at depth 255.

**Empty UTXO set root:** `empty_hash[256]`.

---

## 5. Transactions

### 5.1 Transaction Structure

A transaction consists of three sections serialized in order:

```
tx_header || tx_body || tx_witnesses
```

**tx_header** (4 bytes):
```
input_count(u16 LE) || output_count(u16 LE)
```

**tx_body** (variable):
```
input[0] || ... || input[input_count-1] || output[0] || ... || output[output_count-1]
```

Each **input** (36 bytes):
```
prev_tx_id(Hash256) || output_index(u32 LE)
```

Each **output** (variable): see Section 5.4.

**tx_witnesses** (variable):
```
witness[0] || ... || witness[input_count-1]
```

The witness count equals the input count. Each **witness**:
```
VarBytes(witness_data) || has_redeemer(u8) || [VarBytes(redeemer) if has_redeemer=1]
```

### 5.2 Transaction ID (TxId)

```
TxId = domain_hash("EXFER-TX", tx_header || tx_body)
```

Witnesses are **excluded** from TxId computation. This prevents witness malleability from changing transaction identity.

### 5.3 Witness-Committed Transaction ID (WtxId)

```
WtxId = domain_hash("EXFER-WTXID", tx_header || tx_body || tx_witnesses)
```

Includes the full serialization. Used in the block's tx_root Merkle tree.

### 5.4 Output Serialization

Each output is serialized as:

```
value(u64 LE)
|| VarBytes(script)
|| has_datum(u8) || [VarBytes(datum) if has_datum=1]
|| has_datum_hash(u8) || [Hash256(datum_hash) if has_datum_hash=1]
```

**Flags:** `has_datum` and `has_datum_hash` are single bytes. Value 0x00 = absent, 0x01 = present. Any other value is non-canonical and must be rejected.

**Constraints:**
- Datum size: at most 4,096 bytes.
- If both datum and datum_hash are present, `SHA-256(datum)` must equal datum_hash.

---

## 6. Exfer Script

Exfer Script is a total functional combinator language. Programs are directed acyclic graphs (DAGs) of combinator nodes. All programs terminate. Costs are statically computable.

### 6.1 Type System

```
Type ::= Unit
       | Sum(Type, Type)
       | Product(Type, Type)
       | List(Type)
       | Bound(k)           -- bounded natural: values 0..k-1
```

**Derived types:**
- `Bool = Sum(Unit, Unit)` — Left = false, Right = true
- `Option(A) = Sum(Unit, A)` — Left(Unit) = None, Right(a) = Some(a)
- `Bytes = List(Bound(256))` — variable-length byte string
- `Hash256 = Bound(0)` — sentinel for 256-bit hash (opaque to type system, handled by jets)
- `U64 = Bound(u64_max)` — 64-bit unsigned integer
- `U256` — 256-bit unsigned integer, a nominal type with a dedicated `Type::U256` variant. U256 is **not** an alias for `Product(U64, U64)`: it is a distinct type that prevents type confusion. A U256 value produced by 256-bit arithmetic jets (Add256, Mul256, etc.) cannot be consumed by product projections (Take/Drop) or 64-bit jets (Eq64), and vice versa. The wire format is unchanged (tag 0x07, 32 bytes big-endian).

### 6.2 Combinators

| Combinator | Notation | Type Rule |
|------------|----------|-----------|
| Iden | `A → A` | Identity function |
| Unit | `A → Unit` | Discard input, return unit |
| Comp(f, g) | `A → C` | `f: A→B, g: B→C` — composition |
| Pair(f, g) | `A → Product(B, C)` | `f: A→B, g: A→C` — both on same input |
| Take(f) | `Product(A, B) → C` | `f: A→C` — project first |
| Drop(f) | `Product(A, B) → C` | `f: B→C` — project second |
| InjL(f) | `A → Sum(B, C)` | `f: A→B` — inject left |
| InjR(f) | `A → Sum(B, C)` | `f: A→C` — inject right |
| Case(f, g) | `Sum(A, B) → C` | `f: A→C, g: B→C` — branch on tag |
| Fold(f, z, k) | `Product(Bound(k), A) → B` | `z: A→B, f: Product(A, B)→B` — bounded iteration |
| ListFold(f, z) | `Product(List(A), B) → B` | `z: B→B, f: Product(A, B)→B` — list iteration |
| Jet(id) | per jet | Native operation (Section 7) |
| Witness | `Unit → T` | Read value from witness data at evaluation time |
| MerkleHidden(hash) | — | Pruned subtree placeholder (cannot be evaluated) |
| Const(v) | `Unit → T` | Constant value embedded in program |

**DAG invariant:** Nodes are stored in an arena. Children have strictly higher indices than their parent. Node 0 is the root. All nodes must be reachable from the root.

### 6.3 Typing Rules

Type inference proceeds bottom-up (from leaves to root). `Unit` serves as a wildcard in type inference: any type position occupied by `Unit` is compatible with any other type.

For each combinator, with child types already inferred:

- **Iden:** `A → A`. Initially typed as input = Unit, output = Unit (both unconstrained). Parent context refines A to a concrete type. The input and output are always the same type.
- **Unit:** `A → Unit`. Input is unconstrained (initially Unit). Output is always Unit.
- **Comp(f, g):** f.output must be compatible with g.input. Result: input = f.input, output = g.output.
- **Pair(f, g):** Both children take the same input. Result: input = f.input (or g.input if f.input is Unit), output = Product(f.output, g.output).
- **Take(f):** Result: input = Product(f.input, Unit), output = f.output.
- **Drop(f):** Result: input = Product(Unit, f.input), output = f.output.
- **InjL(f):** Result: input = f.input, output = Sum(f.output, Unit).
- **InjR(f):** Result: input = f.input, output = Sum(Unit, f.output).
- **Case(f, g):** f.output must be compatible with g.output. Result: input = Sum(f.input, g.input), output = f.output (or g.output if f.output is Unit).
- **Fold(f, z, k):** z.output and f.output must be compatible. Result: input = Product(Bound(k), z.input), output = z.output (or f.output if z.output is Unit).
- **ListFold(f, z):** z.output and f.output must be compatible. Element type extracted from f.input if it is Product(A, B). Result: input = Product(List(elem_type), z.input), output = z.output (or f.output if z.output is Unit).
- **Jet(id):** Input and output types are fixed per jet (Section 7).
- **Witness:** input = Unit, output = Unit (refined by parent context).
- **MerkleHidden(hash):** input = Unit, output = Unit.
- **Const(v):** input = Unit, output = inferred from value.

**Compatibility rule:** Two types are compatible if they are equal, or if either is Unit, or if they are structurally matching (both Sum, both Product, both List) with pairwise compatible components.

**Refinement exception:** During type refinement, fixed-output combinators (Unit, Const, Jet) are never refined. Their output types are determined by their definition and cannot be overridden by parent context. This prevents the typechecker from claiming a Unit combinator produces U64.

### 6.4 Evaluation Semantics

Programs are evaluated recursively on the DAG with a resource budget (steps and cells). Maximum evaluation depth: 128.

- **Iden:** Return input unchanged. Cost: 1 step.
- **Unit:** Return Unit. Cost: 1 step.
- **Comp(f, g):** Evaluate f on input, then evaluate g on f's result. Cost: 1 step + f's cost + g's cost.
- **Pair(f, g):** Evaluate f and g both on the same input. Return Product(f_result, g_result). Cost: 1 step + 1 cell + f's cost + g's cost.
- **Take(f):** Input must be Product(a, b). Evaluate f on a. Cost: 1 step + f's cost.
- **Drop(f):** Input must be Product(a, b). Evaluate f on b. Cost: 1 step + f's cost.
- **InjL(f):** Evaluate f on input. Return Left(result). Cost: 1 step + 1 cell + f's cost.
- **InjR(f):** Evaluate f on input. Return Right(result). Cost: 1 step + 1 cell + f's cost.
- **Case(f, g):** Input must be Left(a), Right(b), or Bool. If Left(a) or Bool(false): evaluate f on a (or Unit). If Right(b) or Bool(true): evaluate g on b (or Unit). Cost: 1 step + selected branch cost.
- **Fold(f, z, k):** Input must be Product(_, init). Evaluate z on init to get initial accumulator. Then k times: evaluate f on Product(init, accumulator). Cost: 1 step + z's cost + k × (1 step + f's cost).
- **ListFold(f, z):** Input must be Product(list, init). Evaluate z on init to get initial accumulator. For each element in list: evaluate f on Product(element, accumulator). Cost: 1 step + z's cost + n × (1 step + f's cost), where n = list length.
- **Jet(id):** Charge runtime cost (data-proportional). Execute native operation. Cost: varies per jet.
- **Witness:** Read next value from witness byte stream. Cost: 1 step. When a Witness combinator is evaluated, the deserialized value is validated against the expected output type from the typechecker. Values that don't match (e.g., Left(U64(7)) when Bool is expected) are rejected with a WitnessError before they can influence control flow. If the expected type is Unit (unresolved by the typechecker), any value is accepted.
- **MerkleHidden(hash):** Cannot be evaluated. Always errors.
- **Const(v):** Return the constant value. Cost: 1 step + 1 cell.

**Witness consumption:** After evaluation completes, all witness bytes must be consumed. Unconsumed witness bytes cause validation failure (prevents witness malleability).

**Script success:** A script succeeds if and only if evaluation returns `Bool(true)`.

### 6.5 Cost Model

Static cost is computed bottom-up on the DAG before evaluation. Cost has two components: **steps** (execution operations) and **cells** (heap allocations).

| Combinator | Steps | Cells |
|------------|-------|-------|
| Iden | 1 | 0 |
| Unit | 1 | 0 |
| Comp(f, g) | cost(f).steps + cost(g).steps + 1 | cost(f).cells + cost(g).cells |
| Pair(f, g) | cost(f).steps + cost(g).steps + 1 | cost(f).cells + cost(g).cells + 1 |
| Take(f) | cost(f).steps + 1 | cost(f).cells |
| Drop(f) | cost(f).steps + 1 | cost(f).cells |
| InjL(f) | cost(f).steps + 1 | cost(f).cells + 1 |
| InjR(f) | cost(f).steps + 1 | cost(f).cells + 1 |
| Case(f, g) | max(cost(f).steps, cost(g).steps) + 1 | max(cost(f).cells, cost(g).cells) + 1 |
| Fold(f, z, k) | 1 + cost(z).steps + k × (cost(f).steps + 1) | cost(z).cells + k × cost(f).cells |
| ListFold(f, z) | 1 + cost(z).steps + n × (cost(f).steps + 1) | cost(z).cells + n × cost(f).cells |
| Jet(id) | jet_cost(id).steps | jet_cost(id).cells |
| Witness | 1 | 0 |
| MerkleHidden | 0 | 0 |
| Const(v) | 1 + ceil_div(serialized_bytes(v), 64) | 1 + ceil_div(serialized_bytes(v), 64) |

For ListFold, `n = max(input_count, output_count)` of the spending transaction (known at validation time).

**Per-input step cap:** 4,000,000 steps. Scripts exceeding this are rejected.
**Per-transaction step budget:** 20,000,000 steps (sum over all inputs).
**Memory limit:** 16,777,216 bytes (16 MiB) per script evaluation.
**Maximum DAG depth:** 128.
**Maximum node count:** 65,535.

### 6.6 Serialization and Merkle Commitment

**Binary serialization format:**

```
node_count(u32 LE) || root_index(u32 LE) || node[0] || node[1] || ... || node[node_count-1]
```

Each node is serialized with a tag byte followed by combinator-specific data:

| Tag | Combinator | Data |
|-----|------------|------|
| 0x00 | Iden | — |
| 0x01 | Comp(f, g) | f(u32 LE) g(u32 LE) |
| 0x02 | Unit | — |
| 0x03 | Pair(f, g) | f(u32 LE) g(u32 LE) |
| 0x04 | Take(f) | f(u32 LE) |
| 0x05 | Drop(f) | f(u32 LE) |
| 0x06 | InjL(f) | f(u32 LE) |
| 0x07 | InjR(f) | f(u32 LE) |
| 0x08 | Case(f, g) | f(u32 LE) g(u32 LE) |
| 0x09 | Fold(f, z, k) | f(u32 LE) z(u32 LE) k(u64 LE) |
| 0x0A | ListFold(f, z) | f(u32 LE) z(u32 LE) |
| 0x0B | Jet(id) | id(u32 LE) |
| 0x0C | Witness | — |
| 0x0D | MerkleHidden(h) | hash(32 bytes) |
| 0x0E | Const(v) | value_len(u32 LE) value_bytes |

**Value serialization tags:**

| Tag | Value | Data |
|-----|-------|------|
| 0x00 | Unit | — |
| 0x01 | Left(v) | value |
| 0x02 | Right(v) | value |
| 0x03 | Pair(a, b) | a then b |
| 0x04 | List(vs) | count(u32 LE) then elements |
| 0x05 | Bytes(bs) | length(u32 LE) then data |
| 0x06 | U64(n) | n(u64 LE) |
| 0x07 | U256(d) | data(32 bytes, big-endian) |
| 0x08 | Bool(b) | 0x00=false, 0x01=true |
| 0x09 | Hash(h) | hash(32 bytes) |

**Merkle commitment:**

The Merkle hash of a program is computed bottom-up. For each node:

```
node_merkle_hash = domain_hash("EXFER-SCRIPT", tag_byte || child_hash_1 || child_hash_2 || ...)
```

Children are referenced by their Merkle hash (not their NodeId). Specific formats:
- Leaf nodes (Iden, Unit, Witness): `domain_hash("EXFER-SCRIPT", [tag])`
- Single-child (Take, Drop, InjL, InjR): `domain_hash("EXFER-SCRIPT", [tag] || child_hash)`
- Two-child (Comp, Pair, Case, ListFold): `domain_hash("EXFER-SCRIPT", [tag] || f_hash || g_hash)`
- Fold: `domain_hash("EXFER-SCRIPT", [tag] || f_hash || z_hash || k_le8)`
- Jet: `domain_hash("EXFER-SCRIPT", [tag] || id_le4)`
- MerkleHidden(h): returns `h` directly (the hash IS the commitment)
- Const(v): `domain_hash("EXFER-SCRIPT", [tag] || value_bytes)`

**Canonical serialization:** Deserializing a script and re-serializing it must produce identical bytes. Non-canonical encodings are rejected.

---

## 7. Jets

Jets are native operations with fixed type signatures and known costs. Each jet has a 32-bit numeric ID.

### 7.1 Jet Registry

| Category | ID Range | Jets |
|----------|----------|------|
| Cryptographic | 0x0001–0x0004 | Sha256, Ed25519Verify, SchnorrVerify, MerkleVerify |
| Arithmetic (64-bit) | 0x0100–0x0107 | Add64, Sub64, Mul64, Div64, Mod64, Eq64, Lt64, Gt64 |
| Arithmetic (256-bit) | 0x0200–0x0207 | Add256, Sub256, Mul256, Div256, Mod256, Eq256, Lt256, Gt256 |
| Byte Operations | 0x0300–0x0304 | Cat, Slice, Len, EqBytes, EqHash |
| Introspection | 0x0400–0x0408 | TxInputs, TxOutputs, TxValue, TxScriptHash, TxInputCount, TxOutputCount, SelfIndex, BlockHeight, TxSigHash |
| List Operations | 0x0500–0x0505 | ListLen, ListAt, ListSum, ListAll, ListAny, ListFind |

**SchnorrVerify** (0x0003) is reserved. It is not implemented and always fails. Output scripts containing unimplemented jets are rejected (funds would be permanently locked).

### 7.2 Cryptographic Jets

**Sha256** (0x0001)
- Input: `Bytes`
- Output: `Hash256`
- Computes SHA-256 of input bytes.
- Static cost: 1,000 steps, 1 cell.
- Runtime cost: `500 + (len / 64) × 8` steps.

**Ed25519Verify** (0x0002)
- Input: `Product(Bytes, Product(Bytes, Bytes))` — (message, (pubkey, signature))
- Output: `Bool`
- Pubkey must be exactly 32 bytes. Signature must be exactly 64 bytes. Returns false if lengths are wrong.
- Rejects small-order (weak) public keys. Returns false if the pubkey is a point of order dividing 8.
- Uses ZIP-215 verification (accepts non-canonical point encodings).
- Static cost: 5,000 steps, 1 cell.
- Runtime cost: `5,000 + ceil_div(message_bytes, 64) × 8` steps.

**MerkleVerify** (0x0004)
- Input: `Product(Hash256, Product(Hash256, Bytes))` — (root, (leaf, proof))
- Output: `Bool`
- Proof format: sequence of 33-byte steps `[side(u8) || sibling(32 bytes)]`. Side 0 = current is left child, side 1 = current is right child. Returns false if proof length is not a multiple of 33 or any side byte exceeds 1.
- Internal hashing: `domain_hash("EXFER-MERKLE", left || right)`.
- Static cost: 32,000 steps, 1 cell.
- Runtime cost: `500 + (proof_len / 33) × 500` steps.

### 7.3 Arithmetic Jets (64-bit)

All take `Product(U64, U64)` input.

| Jet | ID | Output | Behavior | Error |
|-----|----|--------|----------|-------|
| Add64 | 0x0100 | U64 | a + b | Overflow if result > u64 max |
| Sub64 | 0x0101 | U64 | a - b | Overflow if a < b |
| Mul64 | 0x0102 | U64 | a × b | Overflow if result > u64 max |
| Div64 | 0x0103 | U64 | a / b (floor) | DivisionByZero if b = 0 |
| Mod64 | 0x0104 | U64 | a mod b | DivisionByZero if b = 0 |
| Eq64 | 0x0105 | Bool | a = b | — |
| Lt64 | 0x0106 | Bool | a < b | — |
| Gt64 | 0x0107 | Bool | a > b | — |

Static cost: 10 steps, 1 cell (all).

### 7.4 Arithmetic Jets (256-bit)

All take `Product(U256, U256)` input. U256 values are 32 bytes, big-endian.

| Jet | ID | Output | Behavior | Error |
|-----|----|--------|----------|-------|
| Add256 | 0x0200 | U256 | a + b | Overflow if result ≥ 2^256 |
| Sub256 | 0x0201 | U256 | a - b | Overflow if a < b |
| Mul256 | 0x0202 | U256 | a × b | Overflow if result ≥ 2^256 |
| Div256 | 0x0203 | U256 | a / b (floor) | DivisionByZero if b = 0 |
| Mod256 | 0x0204 | U256 | a mod b | DivisionByZero if b = 0 |
| Eq256 | 0x0205 | Bool | a = b | — |
| Lt256 | 0x0206 | Bool | a < b (big-endian) | — |
| Gt256 | 0x0207 | Bool | a > b (big-endian) | — |

Static cost: 50 steps, 1 cell (all).

### 7.5 Byte Operation Jets

**Cat** (0x0300)
- Input: `Product(Bytes, Bytes)` — Output: `Bytes`
- Concatenates the two byte sequences.
- Static cost: 100 steps, 1 cell.
- Runtime cost: `10 + total_len / 8` steps.

**Slice** (0x0301)
- Input: `Product(Bytes, Product(U64, U64))` — (source, (start, length))
- Output: `Bytes`
- Returns `source[start .. min(start+length, source.len())]`. If start > source.len(), returns empty bytes.
- Static cost: 100 steps, 1 cell.
- Runtime cost: `10 + source_len / 8` steps.

**Len** (0x0302)
- Input: `Bytes` — Output: `U64`
- Returns byte count.
- Static cost: 10 steps, 0 cells.

**EqBytes** (0x0303)
- Input: `Product(Bytes, Bytes)` — Output: `Bool`
- Accepts both Bytes and Hash values. Returns true if byte-equal.
- Static cost: 500 steps, 0 cells.
- Runtime cost: `10 + max(len_a, len_b) / 8` steps.

**EqHash** (0x0304)
- Input: `Product(Hash256, Hash256)` — Output: `Bool`
- Accepts both Bytes and Hash values. Returns true if byte-equal.
- Static cost: 500 steps, 0 cells.
- Runtime cost: 14 steps.

### 7.6 Introspection Jets

These jets access the transaction context during script evaluation.

**TxInputs** (0x0400)
- Input: `Unit`
- Output: `List(Product(Hash256, Product(U64, Product(U64, Hash256))))`
- Each element: (prev_tx_id, (output_index, (value, script_hash))).
- Static cost: 1,000 steps, 0 cells.
- Runtime cost: `10 + input_count × 10` steps.

**TxOutputs** (0x0401)
- Input: `Unit`
- Output: `List(Product(U64, Product(Hash256, Option(Hash256))))`
- Each element: (value, (script_hash, datum_hash)).
- Static cost: 1,000 steps, 0 cells.
- Runtime cost: `10 + output_count × 10` steps.

**TxValue** (0x0402)
- Input: `U64` (input index)
- Output: `U64` (value in exfers)
- Error: OutOfBounds if index ≥ input count.
- Static cost: 10 steps, 0 cells.

**TxScriptHash** (0x0403)
- Input: `U64` (input index)
- Output: `Hash256`
- Error: OutOfBounds if index ≥ input count.
- Static cost: 10 steps, 0 cells.

**TxInputCount** (0x0404)
- Input: `Unit` — Output: `U64`
- Static cost: 5 steps, 0 cells.

**TxOutputCount** (0x0405)
- Input: `Unit` — Output: `U64`
- Static cost: 5 steps, 0 cells.

**SelfIndex** (0x0406)
- Input: `Unit` — Output: `U64`
- Returns the index of the input currently being validated.
- Static cost: 5 steps, 0 cells.

**BlockHeight** (0x0407)
- Input: `Unit` — Output: `U64`
- Returns current block height.
- Static cost: 5 steps, 0 cells.

**TxSigHash** (0x0408)
- Input: `Unit` — Output: `Bytes`
- Returns the domain-separated signing digest: `"EXFER-SIG" || genesis_block_id(32) || tx_header || tx_body`.
- Static cost: 5 steps, 0 cells.
- Runtime cost: `5 + sig_hash_len / 64` steps.

### 7.7 List Operation Jets

**ListLen** (0x0500)
- Input: `List(A)` — Output: `U64`
- Static cost: 10 steps, 0 cells.

**ListAt** (0x0501)
- Input: `Product(List(A), U64)` — Output: `Option(A)`
- Returns Some(element) if index in bounds, None otherwise.
- Static cost: 10 steps, 1 cell.

**ListSum** (0x0502)
- Input: `List(U64)` — Output: `U64`
- Sums all elements. Returns 0 for empty list. Error: Overflow.
- Static cost: 1,000 steps, 0 cells.
- Runtime cost: `10 + list_length` steps.

**ListAll** (0x0503)
- Input: `List(Bool)` — Output: `Bool`
- Returns true if all elements are true (vacuously true for empty list).
- Static cost: 1,000 steps, 0 cells.
- Runtime cost: `10 + list_length` steps.

**ListAny** (0x0504)
- Input: `List(Bool)` — Output: `Bool`
- Returns true if any element is true (false for empty list).
- Static cost: 1,000 steps, 0 cells.
- Runtime cost: `10 + list_length` steps.

**ListFind** (0x0505)
- Input: `List(Bool)` — Output: `Option(U64)`
- Returns Some(index) of first true element, None if none found.
- Static cost: 1,000 steps, 0 cells.
- Runtime cost: `10 + list_length` steps.

---

## 8. Script Evaluation (Locking and Unlocking)

### 8.1 Output Locking

An output is locked by placing a script commitment in its `script` field:

- **Pubkey hash lock (32-byte script):** The script field contains `domain_hash("EXFER-ADDR", pubkey)`, a 32-byte pubkey hash. This is the simple signature-based locking mechanism.
- **Script lock (>32-byte script):** The script field contains the full serialized program (Section 6.6). At spend time, the validator deserializes, type-checks, computes cost, and evaluates the program.

The distinction is purely by length: exactly 32 bytes = pubkey hash lock. Any other length = script lock.

**Ambiguity guard:** If a 32-byte script also deserializes as a valid Exfer Script program, the output is rejected (prevents ambiguous spending semantics).

### 8.2 Input Validation

For each input in a transaction:

**If the spent output's script is a pubkey hash lock (32 bytes):**
1. Witness must be exactly 96 bytes: `pubkey(32) || signature(64)`.
2. Redeemer must be absent.
3. Compute `domain_hash("EXFER-ADDR", pubkey)`. Must equal the script.
4. Signing message: `"EXFER-SIG" || genesis_block_id(32) || tx_header || tx_body`.
5. Reject the pubkey if it is a small-order (weak) Ed25519 point — such keys can validate signatures across unrelated messages.
6. Ed25519 verify (ZIP-215) the signature over the signing message with the pubkey.

**If the spent output's script is a script lock (≠32 bytes):**
1. Deserialize the script. Re-serialize and verify byte-for-byte equality (canonical check).
2. Type-check the program. Root must output Bool.
3. Strict type edge check: all composition edges have exact type matches (no Unit wildcards in internal edges).
4. Reject scripts containing unimplemented jets, MerkleHidden nodes, or heterogeneous list constants.
5. Root input type must be compatible with the runtime input shape (Section 8.5).
6. DAG depth must not exceed 128.
7. Minimum-case cost must not exceed 4,000,000 steps.
8. Resolve datum (Section 8.3).
9. Build script input value (Section 8.5).
10. Compute cost with actual list sizes from the transaction.
11. Reject if cost exceeds 4,000,000 steps.
12. Evaluate with budget = 4,000,000 steps, computed cells.
13. Result must be `Bool(true)`.

### 8.3 Datum Resolution

```
if output has inline datum:
    if output also has datum_hash:
        verify SHA-256(datum) = datum_hash
    return datum
else if output has datum_hash:
    spender must provide datum in witness redeemer field
    verify SHA-256(provided_datum) = datum_hash
    verify provided datum length ≤ 4,096 bytes
    return provided_datum
else:
    return None
```

### 8.4 Redeemer Handling

The redeemer is an optional byte string in the witness. For pubkey hash locks, the redeemer must be absent. For script locks, the redeemer is available to the script via the input value and may also serve as the datum provider for hash-committed datums.

### 8.5 Script Context

The runtime provides each script with an input value of type:

```
Product(Bytes, Product(Option(Bytes), Product(Option(Bytes), Unit)))
```

Meaning: `(witness, (redeemer_opt, (datum_opt, ())))`.

The script context — accessed via introspection jets — contains:
- All transaction inputs: (prev_tx_id, output_index, value, script_hash) per input
- All transaction outputs: (value, script_hash, datum_hash) per output
- Self index: the index of the input being evaluated
- Block height
- Signing digest: `"EXFER-SIG" || genesis_block_id(32) || tx_header || tx_body`

### 8.6 Budget Enforcement

- Per-input: 4,000,000 steps maximum.
- Per-transaction: 20,000,000 steps maximum (sum of actual runtime costs across all inputs).
- Memory: 16 MiB per script evaluation.
- Actual runtime cost (not static estimate) is used for fee calculation.

---

## 9. Proof of Work

The PoW hash is computed using Argon2id with independent domain separators for password and salt:

```
pw   = domain_hash("EXFER-POW-P", header_bytes)
salt = domain_hash("EXFER-POW-S", header_bytes)
pow  = Argon2id(password=pw, salt=salt, m=65536, t=2, p=1, output_len=32)
```

Parameters:
- Memory: 65,536 KiB (64 MiB)
- Iterations: 2
- Parallelism: 1
- Output length: 32 bytes
- Algorithm version: 0x13

**Validity condition:** `pow < difficulty_target`, where both values are compared as 256-bit big-endian unsigned integers (lexicographic byte comparison).

---

## 10. Difficulty Adjustment

**Retarget window:** 4,320 blocks.
**Target block time:** 10 seconds.
**Expected time for a window:** (4,320 - 1) × 10 = 43,190 seconds.

**When to retarget:** At every block whose height is a non-zero multiple of 4,320.

**Retarget formula:**

```
actual_time = timestamp(height - 1) - timestamp(height - 4320)
if actual_time = 0: actual_time = 1
min_time = expected_time / 4
max_time = expected_time × 4
clamped_time = clamp(actual_time, min_time, max_time)
new_target = old_target × clamped_time / expected_time
```

- `old_target` is the parent block's difficulty_target.
- Arithmetic uses 256-bit multiply/divide (no floating point).
- Result clamped to minimum value 1 (target = 0 means no valid hash exists).
- No maximum target clamp (can reach [0xFF; 32]).
- Overflow in multiply saturates to [0xFF; 32].

**Non-retarget blocks:** Inherit parent's difficulty_target unchanged.

**Genesis target:** 2^248 (byte representation: `[0x01, 0x00, ..., 0x00]`).

---

## 11. Emission

Block reward formula:

```
R(height) = BASE_REWARD + floor(DECAY_COMPONENT × 2^(-height / HALF_LIFE))
```

Constants:
- BASE_REWARD = 100,000,000 (1 EXFER, the asymptotic minimum)
- DECAY_COMPONENT = 9,900,000,000 (99 EXFER)
- HALF_LIFE = 6,307,200 blocks (~2 years at 10s blocks)
- 1 EXFER = 100,000,000 exfers

**Implementation:** Q64.64 fixed-point arithmetic with a 4,097-entry lookup table.

LUT construction: `LUT[0] = 2^64`. `LUT[i] = LUT[i-1] × K >> 64` where K = 18,443,622,869,203,936,790 (consensus-canonical constant). LUT[4096] = 9,223,758,693,993,446,757.

Interpolation: `bucket_size = ceil(HALF_LIFE / 4096) = 1540`. For height h, decompose: `q = h / HALF_LIFE`, `r = h % HALF_LIFE`, `bucket = r / bucket_size`, `frac = r % bucket_size`. Linear interpolation between `LUT[bucket]` and `LUT[bucket+1]`. If q ≥ 128: return BASE_REWARD.

**Canonical reward vectors** (all implementations must produce these exact values):

| Height | Reward (exfers) |
|--------|----------------|
| 0 | 10,000,000,000 |
| 1 | 9,999,998,912 |
| 100 | 9,999,891,228 |
| 1,000 | 9,998,912,280 |
| 4,320 | 9,995,301,790 |
| 10,000 | 9,989,127,892 |
| 43,200 | 9,953,117,900 |
| 100,000 | 9,891,814,300 |
| 6,307,200 | 5,050,000,000 |
| 12,614,400 | 2,575,000,000 |
| 18,921,600 | 1,337,500,000 |
| 63,072,000 | 109,667,968 |
| 630,720,000 | 100,000,000 |

---

## 12. Transaction Validation

A non-coinbase transaction is valid if and only if all of the following hold:

1. **At least one input.**
2. **At least one output.**
3. **Witness count equals input count.**
4. **No duplicate inputs** (same outpoint referenced twice).
5. **Each input references an existing UTXO.**
6. **Script validation passes** for every input (Section 8.2).
7. **Value conservation:** `sum(input_values) ≥ sum(output_values)`, computed with u128 intermediates. Both sums must fit in u64.
8. **Minimum fee:** `fee ≥ ceil_div(tx_cost, 100)`, where fee = sum(inputs) - sum(outputs) and tx_cost is the 8-component cost (Section 14). Uses actual runtime script cost, not the static estimate.
9. **Dust threshold:** Every output value ≥ 200 exfers.
10. **Coinbase maturity:** Inputs spending coinbase outputs must have age ≥ 360 blocks.
11. **Size limit:** Serialized transaction ≤ 1,048,576 bytes (1 MiB).
12. **Output script validity:** Every output script must be well-typed with Bool output, pass strict type edge checks, contain no unimplemented jets or hidden nodes, have compatible root input type, depth ≤ 128, and minimum-case cost ≤ 4,000,000 steps (for script locks). Pubkey hash scripts (32 bytes) must not also deserialize as valid programs.
13. **Per-transaction script budget:** Sum of actual script costs across all inputs ≤ 20,000,000 steps.

**Witness size limits:** Witness data ≤ 65,535 bytes per input. Redeemer ≤ 16,384 bytes. Datum ≤ 4,096 bytes per output.

**Datum consistency:** If both datum and datum_hash are present on an output, `SHA-256(datum)` must equal datum_hash.

**Validation order:** Cheap checks (UTXO existence, maturity, value sums, output script typing) run before expensive checks (signature verification, script evaluation) to prevent CPU amplification attacks.

---

## 13. Coinbase Rules

1. **Exactly one input** with sentinel outpoint: prev_tx_id = all zeros.
2. **output_index encodes height:** `output_index = height as u32`. Height > u32::MAX is invalid.
3. **Reward:** `sum(output_values) = block_reward(height) + total_fees`. Exact equality required.
4. **Dust threshold:** Every output value ≥ 200 exfers.
5. **Exactly one witness:** Empty witness data, no redeemer. Exception: the genesis coinbase (height 0) may carry arbitrary witness data (used for the NIST Beacon attestation).
6. **Position 0** in the block's transaction list.
7. **Output script validity:** Same rules as non-coinbase outputs (Section 12, rule 12).
8. **Size limit:** ≤ 1,048,576 bytes.
9. **Datum consistency:** Same as non-coinbase transactions.

---

## 14. Fee and Cost Model

**tx_cost** is the sum of 8 components:

```
tx_cost = script_eval_cost
        + output_typecheck_cost
        + witness_deser_cost
        + datum_deser_cost
        + tx_deser_cost
        + utxo_io_cost
        + smt_cost
        + script_validation_cost
```

1. **script_eval_cost:** Sum over all inputs. Per input: `5,000 + ceil_div(sig_message_bytes, 64) × 8` if the spent output's script is a pubkey hash (32 bytes), where `sig_message_bytes` is the length of the domain-separated signing message; actual runtime step count from evaluation if the spent output's script is a script lock.
2. **output_typecheck_cost:** 1,000 per non-pubkey-hash output (0 for 32-byte scripts).
3. **witness_deser_cost:** `sum over inputs of ceil_div(witness_bytes, 64) + ceil_div(redeemer_bytes, 64)`.
4. **datum_deser_cost:** `sum over outputs of ceil_div(datum_bytes, 64)`.
5. **tx_deser_cost:** `ceil_div(total_serialized_tx_bytes, 64)`.
6. **utxo_io_cost:** `input_count × 100 + output_count × 100`.
7. **smt_cost:** `input_count × 500 + output_count × 500`.
8. **script_validation_cost:** `sum over script-locked inputs of ceil_div(script_bytes, 64) × 10`. Covers deserialization, canonicalization, type-checking, and cost analysis of each spent script. The multiplier (10) reflects that these operations are more expensive per byte than raw deserialization. Zero for pubkey-hash inputs.

All arithmetic uses u128 intermediates. Result must fit in u64.

**Minimum fee:**
```
min_fee = ceil_div(tx_cost, 100)
```

**Dust threshold:** 200 exfers (consensus-enforced).

---

## 15. Block Validation

A block is valid if and only if all of the following hold:

1. **Header is 156 bytes** (implied by deserialization).
2. **Version = 1.**
3. **Height = parent.height + 1** (genesis: height = 0).
4. **prev_block_id = parent.block_id()** (genesis: all zeros).
5. **PoW valid:** Argon2id hash < difficulty_target.
6. **Difficulty target** matches expected value from retarget algorithm.
7. **Timestamp > MTP** (median of up to 11 ancestor timestamps).
8. **Timestamp ≤ wall_clock + 120 seconds** (policy, skipped during initial block download).
9. **Timestamp ≤ parent.timestamp + 604,800** (7-day gap limit, consensus).
10. **tx_root** matches computed Merkle root of WtxIds.
11. **state_root** matches computed SMT root after applying all transactions.
12. **First transaction is coinbase;** no other transaction has sentinel outpoint.
13. **Coinbase valid** (Section 13).
14. **No duplicate TxIds** in the block.
15. **No double-spends** within the block (no two non-coinbase transactions spend the same outpoint).
16. **Block size ≤ 4,194,304 bytes** (4 MiB).
17. **Each non-coinbase transaction valid** (Section 12).
18. **Coinbase reward = block_reward + total_fees.**

**Intra-block spending:** Transaction at position i may spend outputs created by transactions at positions 0..i-1 in the same block (subject to all validation rules except coinbase maturity, which naturally prevents spending new coinbase outputs).

---

## 16. Fork Choice

**Work computation:**
```
work = floor(2^256 / target)
```

Both target and result are 256-bit big-endian unsigned integers. Target = 0 yields maximum representable work. Computed via: `floor((2^256 - target) / target) + 1`, saturating at 2^256 - 1.

**Cumulative work:** Sum of per-block work values from genesis to tip. Saturates at 2^256 - 1.

**Fork choice rules** (in priority order):
1. **Higher cumulative work** is preferred.
2. **If equal work:** higher height is preferred.
3. **If equal work and equal height:** keep the current tip (no reorg).

---

## 17. Network Protocol

### Wire Format

Handshake messages (Hello, AuthAck):
```
msg_type(u8) || payload_length(u32 LE) || payload[payload_length]
```

Post-handshake messages (all other types):
```
counter(u64 LE) || msg_type(u8) || payload_length(u32 LE) || payload[payload_length] || hmac(16 bytes)
```

The 8-byte counter is a monotonically increasing 64-bit integer, starting at 0 for each direction. The sender increments after each frame. The receiver rejects any frame whose counter is less than the minimum acceptable value (initially 0; set to counter + 1 after each accepted frame). This prevents replay attacks where a network-level attacker re-injects a previously observed authenticated frame.

The 16-byte HMAC is HMAC-SHA256 truncated to 128 bits, computed over `counter(u64 LE) || msg_type || payload_length || payload` using the session MAC key. Including the counter in the HMAC binds each tag to a specific sequence position, making replayed frames fail verification even if the frame bytes are identical. The receiver verifies the HMAC before processing the message; verification failure causes immediate disconnection.

**Session key derivation:** after the handshake completes, both sides convert their Ed25519 identity keys to X25519 (via `to_montgomery()`) and compute a Diffie-Hellman shared secret with the peer's converted public key. The session MAC key mixes this DH secret with the handshake transcript:
```
transcript = SHA-256("EXFER-AUTH" || genesis_id || version_le || nonce_a || nonce_b)
dh_shared_secret = X25519(our_identity_scalar, their_identity_montgomery)
session_key = SHA-256("EXFER-SESSION" || transcript || dh_shared_secret)
```
The DH shared secret can only be computed by holders of either peer's identity private key. An active MITM who relays the handshake cannot derive the session key and therefore cannot forge valid frame MACs. The per-session random nonces ensure each connection gets a unique key.

**Direction binding:** the session key is further split into two directional MAC keys to prevent cross-direction reflection attacks (where a captured frame from one direction is replayed as the other direction):
```
i2r_key = SHA-256("EXFER-MAC-IR" || session_key)   // initiator → responder
r2i_key = SHA-256("EXFER-MAC-RI" || session_key)   // responder → initiator
```
The initiator uses `i2r_key` for sending and `r2i_key` for receiving; the responder uses the reverse. Because each direction has a distinct key, a frame authenticated for one direction will fail HMAC verification when injected into the other.

**Note:** EXFER-AUTH, EXFER-SESSION, EXFER-MAC-IR, and EXFER-MAC-RI use raw `SHA-256(separator || data)` — they do **not** include the length-prefix byte used by `domain_hash`. These four are exceptions to the general `domain_hash` pattern because they are session-scoped handshake/key-derivation operations, not consensus-critical content-addressed hashes.

Maximum message size: 8,388,608 bytes (8 MiB).

### Message Types

| ID | Name | Payload |
|----|------|---------|
| 0x01 | Hello | Handshake message (see below) |
| 0x02 | Ping | empty |
| 0x03 | Pong | empty |
| 0x10 | NewBlock | Serialized Block |
| 0x11 | GetBlocks | u32 LE count, then count × Hash256 |
| 0x12 | BlockResponse | Serialized Block |
| 0x13 | GetTip | empty |
| 0x14 | TipResponse | height(u64 LE) block_id(Hash256) cumulative_work([u8; 32]) |
| 0x15 | Inv | u32 LE count, then count × Hash256 |
| 0x16 | GetAddr | empty |
| 0x17 | Addr | u32 LE count, then count × AddrEntry |
| 0x18 | AuthAck | signature(64 bytes) |
| 0x20 | NewTx | Serialized Transaction |
| 0x21 | GetHeaders | start_height(u64 LE) max_count(u32 LE) |
| 0x22 | Headers | u32 LE count, then count × header(156 bytes) |

**Hello message (268 bytes for protocol version 5):**
```
version(u32 LE)
|| genesis_block_id(Hash256)
|| best_height(u64 LE)
|| best_block_id(Hash256)
|| cumulative_work([u8; 32])
|| nonce([u8; 32])          -- random, for liveness
|| echo([u8; 32])           -- echo peer's nonce
|| pubkey([u8; 32])         -- Ed25519 identity key
|| sig([u8; 64])            -- handshake transcript signature
```

**AddrEntry (26 bytes):**
```
ip(16 bytes, IPv4-mapped-v6) || port(u16 LE) || last_seen(u64 LE)
```

### Handshake

Mutually authenticated via Ed25519. Both peers prove identity key possession. Small-order (weak) identity keys are rejected before signature verification.

**Transcript hash:**
```
transcript = SHA-256("EXFER-AUTH" || genesis_id || version_le4 || nonce_a || nonce_b || role || tip_a || tip_b)
```
where role = 0x00 for responder, 0x01 for initiator. Each `tip_x` is a 72-byte tip commitment: `best_height(8 bytes LE) || best_block_id(32 bytes) || cumulative_work(32 bytes)`, taken from that peer's Hello message. The initiator's tip is `tip_a` and the responder's is `tip_b`. Including these binds each peer's claimed chain tip into the authentication transcript, preventing an attacker from replaying a handshake while substituting different chain-tip fields.

**Protocol:**
1. Initiator sends Hello with nonce_a, pubkey_a, sig=[0; 64].
2. Responder verifies version and genesis. Sends Hello with nonce_b, echo=nonce_a, pubkey_b, sig_b over transcript(role=0x00).
3. Initiator verifies echo, verifies sig_b, sends AuthAck with sig_a over transcript(role=0x01).
4. Responder verifies sig_a. Connection established.

**Timeout:** 5 seconds for handshake completion.

### Rate Limits

| Resource | Limit | Window |
|----------|-------|--------|
| Blocks per peer | 12 | per minute |
| Global blocks | 24 | per minute |
| Transactions per peer | 60 | per minute |
| Global transactions | 200 | per minute |
| Pings per peer | 10 | per minute |
| Requests per peer | 30 | per minute |
| Unsolicited messages per peer | 10 | per minute |
| Response bytes per peer | 16 MiB | per minute |
| Global response bytes | 128 MiB | per minute |
| Invalid blocks per peer | 3 | per minute |
| Invalid transactions per peer | 16 | per minute |

GetTip, GetBlocks, and GetHeaders share a single request_count counter, capped at MAX_REQUESTS_PER_MIN (30) per peer per minute.

During Initial Block Download (CatchingUp state), the per-peer and global response byte budgets are not enforced for GetBlocks and GetHeaders responses. This allows the serving peer to deliver blocks and headers at full speed during IBD.

During IBD, only the active IBD peer is exempt from per-peer block rate limits. All other peers are rate-limited normally even during CatchingUp state. This prevents sybil peers from flooding unsolicited blocks.

**Assume-valid optimization.** Blocks at or below the hardcoded checkpoint height (130,000) skip Argon2id PoW verification during IBD and replay. All other validation is performed: block linkage, transaction validation, Ed25519 signature verification, UTXO accounting, state root verification, fee calculation, coinbase rules, and timestamp checks. The trust assumption is the binary author, not the peer — the checkpoint hash guarantees the block at that height matches the canonical chain. If the block hash at the checkpoint height does not match, the chain is rejected. Use `--no-assume-valid` to disable this optimization and verify full PoW for every block. `--verify-all` also disables assume-valid.

Global transaction rate limit slots are refunded when a transaction fails pre-check validation, full validation, mempool insertion, or is discarded due to a tip change during validation. Only transactions that successfully enter the mempool consume the slot permanently.

After receiving a TipResponse, the node verifies the claimed tip by requesting the header at the claimed height. The header must match the claimed block_id and height, pass PoW verification, and have a difficulty target consistent with the local chain. Only after verification is the peer's tip marked as confirmed. Unconfirmed peers cannot trigger IBD.

### Peer Discovery

On startup, the node resolves `seed.exfer.org` via DNS to discover healthy peers. The DNS seed returns A records pointing to nodes that are reachable and synced (tip within 100 blocks of the network's best height). A seed crawler probes all known nodes every 10 minutes and updates the DNS record with the current healthy set.

If DNS resolution fails (no internet, DNS blocked, seed.exfer.org not configured), the node falls back to three hardcoded seed IPs. The `--peers` flag overrides both DNS and hardcoded seeds.

### Peer Limits

- Maximum outbound peers: 8
- Maximum inbound peers: 256
- Maximum inbound per IP: 1
- Ping interval: 60 seconds
- Pong deadline: 15 seconds

### Address Book

- Maximum size: 1,024 entries
- Accepted per Addr message: 16
- Addr response window: 30 seconds after sending GetAddr; Addr messages outside this window are dropped as unsolicited
- Per /16 subnet cap: 32 entries per IPv4 /16 prefix (first two octets)
- Per-peer contribution cap: a single peer may contribute at most 25% of the address book
- Multi-source preference: outbound connection selection prefers addresses seen from at least 2 independent sources; single-source addresses are used only as fallback (e.g., bootstrap from a single seed)

### Security Considerations

Post-handshake traffic is authenticated via per-frame HMAC-SHA256 (truncated to 16 bytes). The session MAC key is derived from an X25519 Diffie-Hellman shared secret (computed from the authenticated Ed25519 identity keys converted to Montgomery form) mixed with the handshake transcript. An active MITM cannot forge valid frame MACs without possessing a peer's identity private key, because the DH shared secret is only computable by the two endpoints. Traffic is **not encrypted** — message contents are visible to passive observers.

**Consequence for consensus:** all received blocks and transactions also undergo full consensus validation (PoW, difficulty, script evaluation, UTXO checks) before acceptance. The HMAC provides a fast first-pass rejection of tampered traffic; consensus validation provides defense-in-depth.

**Consequence for penalties:** consensus-violation strikes (invalid blocks, invalid transactions) trigger disconnection and IP-level rate limiting, but do **not** ban the peer's cryptographic identity. Because post-handshake frames are now HMAC-authenticated, a MITM cannot inject invalid traffic to frame a peer. Identity-level bans are reserved for handshake-level violations (wrong genesis, failed authentication signature) where the cryptographic handshake itself proves the peer is the source of the violation.

**Consequence for address book:** Addr messages are only accepted within a 30-second window after sending a GetAddr request. Subnet diversity, per-peer contribution caps, and multi-source preference for outbound connections limit the impact of address-book poisoning. An attacker controlling many peers across diverse /16 subnets can still bias discovery; fully closing this requires out-of-band seed diversity and is a known residual risk.

**Consequence for bandwidth:** aggregate outbound response bandwidth is capped at 128 MiB/min globally (in addition to 16 MiB/min per peer) to prevent many concurrent peers from driving egress to exhaustion.

Encrypted transport (confidentiality) is planned for a future protocol version.

---

## 18. Mempool

**Capacity:** 8,192 transactions.

**Admission:** Full UTXO validation and script evaluation. Rejects: coinbase transactions, duplicate TxIds, double-spends with existing mempool entries, fee density below lowest existing entry when at capacity.

**Fee density:** `fee × 1,000,000 / tx_cost` (scaled integer). Higher density = higher priority.

**Eviction:** When at capacity, the lowest fee-density entry is evicted to make room for a higher-density transaction.

**Block selection:** Transactions are selected in descending fee-density order until the block size limit is reached.

**Revalidation:** After a chain reorganization, the mempool is purged of transactions that are no longer valid against the new UTXO set. Two-phase: first a cheap UTXO existence check, then full re-validation of survivors.

---

## 19. Genesis Block

**Fixed values (production network):**

| Field | Value |
|-------|-------|
| Version | 1 |
| Height | 0 |
| prev_block_id | `0000000000000000000000000000000000000000000000000000000000000000` |
| Timestamp | 1,773,536,400 (2026-03-15T01:00:00Z) |
| Difficulty target | 2^248 = `0100000000000000000000000000000000000000000000000000000000000000` |
| Nonce | 259 |
| tx_root | `96d29616a481eac5ffa35f3f7cf2add76ac921e733f72174d45035b5996341d3` |
| state_root | `aafc1988635522e0fdaa4249ccda596127ff689eba8cd1de01a9cdaaf671e9a8` |

**Block ID:**
```
d7b6805c8fd793703db88102b5aed2600af510b79e3cb340ca72c1f762d1e051
```

**Serialized header (156 bytes):**
```
0100000000000000000000000000000000000000000000000000000000000000000000
0000000000000000009004b66900000000010000000000000000000000000000000000
0000000000000000000000000000030100000000000096d29616a481eac5ffa35f3f7c
f2add76ac921e733f72174d45035b5996341d3aafc1988635522e0fdaa4249ccda5961
27ff689eba8cd1de01a9cdaaf671e9a8
```

**Coinbase transaction (349 bytes):**
- Input: prev_tx_id = all zeros, output_index = 0
- Output: value = 10,000,000,000 (100 EXFER), script = `[0x00; 32]` (unspendable)
- Witness: `b"NIST Beacon 2026-03-14T22:23:00Z 561AA26B...881F81 — Designed, audited, and built by autonomous machines. A human provided minimal necessary support."`, no redeemer

```
0100010000000000000000000000000000000000000000000000000000000000000000
000000000000e40b540200000020000000000000000000000000000000000000000000
000000000000000000000000000006014e49535420426561636f6e20323032362d3033
2d31345432323a32333a30305a20353631414132364234323134454538463341414434
4635423842443342343439444633353033433039363131313130453530414332384633
3933373942364438393034463833333034374546463631303943393442423539414434
4242333333353933303743373746373143324643334241364431303733414538383146
383120e280942044657369676e65642c20617564697465642c20616e64206275696c74
206279206175746f6e6f6d6f7573206d616368696e65732e20412068756d616e207072
6f7669646564206d696e696d616c206e656365737361727920737570706f72742e00
```

| Identifier | Value |
|------------|-------|
| TxId | `5e63e65ea2a30d9c874f16eccb366022bfe692d6d933470cb50107df7c2b04c6` |
| WtxId | `96d29616a481eac5ffa35f3f7cf2add76ac921e733f72174d45035b5996341d3` |

---

## 20. Constants

### Consensus

| Constant | Value | Description |
|----------|-------|-------------|
| VERSION | 1 | Block version |
| PROTOCOL_VERSION | 5 | Network protocol version |
| TARGET_BLOCK_TIME_SECS | 10 | Target seconds between blocks |
| RETARGET_WINDOW | 4,320 | Blocks between difficulty adjustments |
| MAX_RETARGET_FACTOR | 4 | Maximum difficulty change per retarget |
| COINBASE_MATURITY | 360 | Blocks before coinbase is spendable |
| MAX_BLOCK_SIZE | 4,194,304 | Maximum block size in bytes |
| MAX_TX_SIZE | 1,048,576 | Maximum transaction size in bytes |
| MTP_WINDOW | 11 | Ancestor count for median time past |
| MAX_TIMESTAMP_DRIFT | 120 | Maximum seconds ahead of wall clock (policy) |
| MAX_TIMESTAMP_GAP | 604,800 | Maximum seconds between parent and child timestamps |
| BLOCK_HEADER_SIZE | 156 | Header size in bytes |

### Emission

| Constant | Value | Description |
|----------|-------|-------------|
| BASE_REWARD | 100,000,000 | Minimum reward (1 EXFER) |
| DECAY_COMPONENT | 9,900,000,000 | Decaying component (99 EXFER) |
| HALF_LIFE | 6,307,200 | Blocks per halving (~2 years) |
| EXFER_UNIT | 100,000,000 | Exfers per 1 EXFER |

### Proof of Work

| Constant | Value | Description |
|----------|-------|-------------|
| ARGON2_MEMORY_KIB | 65,536 | Memory parameter (64 MiB) |
| ARGON2_ITERATIONS | 2 | Time parameter |
| ARGON2_PARALLELISM | 1 | Parallelism parameter |
| ARGON2_OUTPUT_LEN | 32 | Output length in bytes |

### Fee and Cost

| Constant | Value | Description |
|----------|-------|-------------|
| UTXO_LOOKUP_COST | 100 | Cost per input UTXO lookup |
| UTXO_CREATE_COST | 100 | Cost per output UTXO creation |
| SMT_DELETE_COST | 500 | Cost per SMT leaf deletion |
| SMT_INSERT_COST | 500 | Cost per SMT leaf insertion |
| STANDARD_SPEND_COST | 20,000 | Reference cost for dust calculation |
| MIN_FEE_DIVISOR | 100 | Divisor for minimum fee |
| DUST_THRESHOLD | 200 | Minimum output value in exfers |
| PUBKEY_HASH_EVAL_COST | 5,000 | Base cost per pubkey hash input (+ data-proportional Ed25519 charge) |
| OUTPUT_TYPECHECK_COST | 1,000 | Cost per script-locked output |

### Script Limits

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_WITNESS_SIZE | 65,535 | Maximum witness bytes per input |
| MAX_DATUM_SIZE | 4,096 | Maximum datum bytes per output |
| MAX_REDEEMER_SIZE | 16,384 | Maximum redeemer bytes per input |
| MAX_SCRIPT_MEMORY | 16,777,216 | Maximum script evaluation memory |
| MAX_SCRIPT_STEPS | 4,000,000 | Maximum steps per input |
| MAX_TX_SCRIPT_BUDGET | 20,000,000 | Maximum steps per transaction |
| MAX_SCRIPT_NODES | 65,535 | Maximum nodes in a program |
| MAX_LIST_LENGTH | 65,536 | Maximum list length |
| MAX_VALUE_DEPTH | 128 | Maximum value nesting depth |

### Network

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_MESSAGE_SIZE | 8,388,608 | Maximum network message size |
| MAX_OUTBOUND_PEERS | 8 | Outbound peer limit |
| MAX_INBOUND_PEERS | 64 | Inbound peer limit |
| MAX_INBOUND_PER_IP | 4 | Per-IP inbound limit |
| PING_INTERVAL_SECS | 60 | Keepalive interval |
| PONG_DEADLINE_SECS | 15 | Pong timeout |
| HANDSHAKE_TIMEOUT_SECS | 5 | Handshake timeout |
| MAX_GETBLOCKS_ITEMS | 64 | Max hashes per GetBlocks |
| MEMPOOL_CAPACITY | 8,192 | Maximum mempool entries |
| MAX_ADDR_ITEMS | 64 | Max addresses per Addr message |
| MAX_ADDR_BOOK_SIZE | 1,024 | Maximum address book entries |
| MAX_ADDR_PER_MSG_ACCEPT | 16 | Max addresses accepted per message |
| MAX_GETADDR_PER_CONN | 2 | Max GetAddr requests per connection |
| MAX_UNSOLICITED_ADDR_PER_MIN | 3 | Unsolicited Addr messages per minute |
| ADDR_FLUSH_INTERVAL_SECS | 300 | Address book flush interval |
| MAX_GETBLOCKS_RESPONSE | 8 | Max blocks per GetBlocks response |
| MAX_INV_ITEMS | 64 | Max items per Inv message |

### Rate Limits

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_BLOCKS_PER_MIN | 12 | Blocks per peer per minute |
| MAX_GLOBAL_BLOCKS_PER_MIN | 24 | Global blocks per minute |
| MAX_TXS_PER_MIN | 60 | Transactions per peer per minute |
| MAX_GLOBAL_TXS_PER_MIN | 200 | Global transactions per minute |
| MAX_PINGS_PER_MIN | 10 | Pings per peer per minute |
| MAX_REQUESTS_PER_MIN | 30 | Requests per peer per minute |
| MAX_UNSOLICITED_PER_MIN | 10 | Unsolicited messages per peer per minute |
| MAX_RESPONSE_BYTES_PER_MIN | 16,777,216 | Response bytes per peer per minute (16 MiB) |
| MAX_GLOBAL_RESPONSE_BYTES_PER_MIN | 134,217,728 | Global response bytes per minute (128 MiB) |

### Peer Penalties

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_INVALID_BLOCKS_PER_PEER | 3 | Invalid blocks before disconnect |
| MAX_INVALID_TXS_PER_PEER | 16 | Invalid transactions before disconnect |
| MAX_CONTROL_MSGS_DURING_IBD | 50 | Max interleaved non-response messages during IBD |

### Orphan and Fork Handling

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_ORPHAN_BLOCKS | 16 | Maximum orphan blocks cached |
| MAX_ORPHAN_BLOCK_SIZE | 4,194,304 | Maximum orphan block size (= MAX_BLOCK_SIZE) |
| MAX_ORPHAN_CACHE_BYTES | 67,108,864 | Total orphan cache size (64 MiB) |
| MAX_FORK_BLOCK_SIZE | 4,194,304 | Maximum fork block size (= MAX_BLOCK_SIZE) |
| MAX_FORK_BLOCKS | 128 | Maximum fork chain length for reorg |
| MAX_RETAINED_FORK_HEADERS | 10,000 | Maximum retained non-canonical headers after fork eviction |

### Transaction Limits

| Constant | Value | Description |
|----------|-------|-------------|
| MIN_TX_SIZE | 50 | Minimum serialized transaction size |
| MAX_SPENT_UTXOS_SIZE | 16,777,216 | Maximum serialized undo metadata per block (16 MiB) |

---

# Part II: Operational Interface

## 21. Transaction Construction

### 21.1 Simple Payment

**Given:** A set of spendable UTXOs controlled by key pair (sk, pk), a recipient address (Hash256), an amount.

**Procedure:**

1. **Compute sender address:** `address = domain_hash("EXFER-ADDR", pk)`.

2. **Select inputs:** Choose UTXOs whose scripts match the sender address. Skip coinbase UTXOs with age < 360 blocks. Accumulate until `total_input ≥ amount + estimated_fee`.

3. **Construct outputs:**
   - Output 0: `value = amount, script = recipient_address.bytes (32 bytes), datum = None, datum_hash = None`.
   - Output 1 (change): `value = total_input - amount - fee, script = sender_address.bytes (32 bytes), datum = None, datum_hash = None`. Omit if change < 200 (dust threshold); fold sub-dust change into fee.

4. **Estimate fee:** Construct a preliminary transaction to compute tx_cost:
   - `script_eval_cost = input_count × (5,000 + ceil_div(sig_message_bytes, 64) × 8)`
   - `witness_deser_cost = input_count × ceil_div(96, 64) = input_count × 2`
   - `utxo_io_cost = input_count × 100 + output_count × 100`
   - `smt_cost = input_count × 500 + output_count × 500`
   - `tx_deser_cost = ceil_div(serialized_size, 64)`
   - `min_fee = ceil_div(tx_cost, 100)`

   If total_input < amount + min_fee, select additional inputs and recompute.

5. **Serialize tx_header and tx_body:**
   - tx_header: `input_count(u16 LE) || output_count(u16 LE)`.
   - tx_body: for each input `prev_tx_id(32) || output_index(u32 LE)`, then for each output the canonical serialization (Section 5.4).

6. **Compute signing message:** `"EXFER-SIG" || genesis_block_id(32) || tx_header || tx_body`.

7. **Sign:** Ed25519 sign the message with sk. Signature is 64 bytes.

8. **Construct witnesses:** For each input: `witness = pk(32) || signature(64)`, redeemer = None.

9. **Final serialization:** `tx_header || tx_body || witnesses`.

10. **Compute TxId:** `domain_hash("EXFER-TX", tx_header || tx_body)`.

11. **Compute WtxId:** `domain_hash("EXFER-WTXID", full_serialization)`.

### 21.2 Script-Locked Output

To lock funds to a script program:

1. Construct the program as a DAG of combinators using the builder interface (Section 22).
2. Serialize the program (Section 6.6): `node_count(u32 LE) || root_index(u32 LE) || nodes...`.
3. Place the serialized bytes in the output's `script` field.
4. Set `datum` and `datum_hash` as needed by the script's logic.

The script must be well-typed with Bool output, pass all output validation checks (Section 12, rule 12), and have length ≠ 32 bytes.

### 21.3 Spending from Script-Locked Output

1. Deserialize the script from the output being spent.
2. Determine the script's expected input shape.
3. Construct the witness data: serialize the values the script expects to read via Witness nodes.
4. Construct the redeemer if the script expects one (or if the output has datum_hash requiring a datum).
5. Place in the transaction witness: `witness = serialized_witness_values`, `redeemer = redeemer_bytes`.
6. The validator will build the input value `(witness_bytes, (redeemer_opt, (datum_opt, ())))` and evaluate the script.

### 21.4 Coinbase Spending (Maturity Constraints)

Coinbase outputs cannot be spent until 360 blocks after the block containing the coinbase. When constructing a transaction that spends coinbase outputs, ensure `current_height - coinbase_height ≥ 360`.

---

## 22. Script Patterns

All patterns below specify:
- The exact combinator DAG construction
- The script commitment (how to compute the hash for the output script field)
- The witness format for spending
- The cost (steps and cells from static analysis)

### 22.1 Signature Lock

**Purpose:** Lock funds to a single Ed25519 public key.

**Output script:** `domain_hash("EXFER-ADDR", pubkey)` — exactly 32 bytes. This is the pubkey hash lock, not a script program.

**Witness to unlock:** `pubkey(32 bytes) || signature(64 bytes)` = 96 bytes. Redeemer: absent.

**Cost:** `5,000 + ceil_div(sig_message_bytes, 64) × 8` steps per input.

### 22.2 Multisig (N-of-M)

**2-of-2 Multisig**

**DAG construction:**

```
and(sig_check(pk_a), sig_check(pk_b))
```

where `sig_check(pk)` is:
```
Comp(
  Pair(
    Comp(Jet(TxSigHash), Unit),           -- get signing digest
    Pair(Const(pk_bytes), Witness)         -- (message, (pubkey, sig))
  ),
  Jet(Ed25519Verify)
)
```

`and(a, b) = Comp(Pair(a, b), Case(Comp(Drop(Iden), Case(InjL(Unit), InjR(Unit))), InjL(Unit)))`

**Witness:** Two signatures read by two Witness nodes: `[sig_a_serialized][sig_b_serialized]`.

**Cost:** ~10,010 + data-proportional Ed25519 cost per verify (2 × `5,000 + ceil_div(msg_len, 64) × 8` + overhead), ~6 cells.

**1-of-2 Multisig**

**DAG construction:**
```
Comp(Witness, Case(sig_check(pk_a), sig_check(pk_b)))
```

**Witness:** `[selector: Left(Unit) or Right(Unit)][signature]`. Selector is a serialized Value.

**2-of-3 Multisig**

**DAG construction:**
```
Comp(Witness, Case(
    Case(and(check_a, check_b), and(check_a, check_c)),
    and(check_b, check_c)
))
```

**Witness:** `[selector: Left(Left(Unit))=A+B, Left(Right(Unit))=A+C, Right(Unit)=B+C][sig_1][sig_2]`.

### 22.3 Hash Lock

**Purpose:** Lock funds to a SHA-256 preimage.

**DAG construction:**
```
Comp(
  Pair(Comp(Witness, Jet(Sha256)), Const(expected_hash)),
  Jet(EqHash)
)
```

**Witness:** `[preimage_bytes]` (serialized as Value::Bytes).

**Cost:** ~1,520 steps (Sha256: 1,000 + EqHash: 500 + overhead), 3 cells.

### 22.4 Timelock

**Purpose:** Lock funds until a specific block height.

**height_gt(h) construction:**
```
Comp(
  Pair(Jet(BlockHeight), Const(U64(h))),
  Jet(Gt64)
)
```

Combined with signature: `and(height_gt(h), sig_check(pk))`.

**Witness:** `[signature]`.

**Cost:** ~5,030 steps (one Ed25519Verify + Gt64 + overhead).

### 22.5 HTLC (Atomic Swap)

**Purpose:** Hash-locked time-locked contract for cross-chain atomic swaps.

**Parameters:** sender_key, receiver_key, hash_lock (Hash256), timeout_height (u64).

**DAG construction:**
```
Comp(Witness, Case(
    and(hash_eq(hash_lock), sig_check(receiver_key)),    -- hash path
    and(height_gt(timeout_height), sig_check(sender_key)) -- timeout path
))
```

**Witness (hash path):** `[Left(Unit)][preimage_bytes][receiver_signature]`.
**Witness (timeout path):** `[Right(Unit)][sender_signature]`.

**Cost:** ~6,530 steps (max branch: Sha256 + EqHash + Ed25519Verify + overhead).

### 22.6 Escrow

**Purpose:** Three-path dispute resolution.

**Parameters:** party_a, party_b, arbiter, timeout_height.

**DAG construction:**
```
Comp(Witness, Case(
    Case(
        and(sig_check(party_a), sig_check(party_b)),   -- mutual agreement
        sig_check(arbiter)                               -- arbiter decision
    ),
    and(height_gt(timeout_height), sig_check(party_a))  -- timeout refund
))
```

**Witness (mutual):** `[Left(Left(Unit))][sig_a][sig_b]`.
**Witness (arbiter):** `[Left(Right(Unit))][sig_arbiter]`.
**Witness (timeout):** `[Right(Unit)][sig_a]`.

**Cost:** ~10,040 steps (max branch: 2× Ed25519Verify + overhead).

### 22.7 Vault

**Purpose:** Primary key with timelock + emergency recovery key without timelock.

**Parameters:** primary_key, recovery_key, locktime (block height).

**DAG construction:**
```
Comp(Witness, Case(
    and(height_gt(locktime), sig_check(primary_key)),   -- normal (after locktime)
    sig_check(recovery_key)                              -- recovery (anytime)
))
```

**Witness (normal):** `[Left(Unit)][primary_signature]`.
**Witness (recovery):** `[Right(Unit)][recovery_signature]`.

**Cost:** ~5,040 steps (max branch: Ed25519Verify + Gt64 + overhead).

### 22.8 Delegation

**Purpose:** Owner can always spend; delegate can spend before expiry.

**Parameters:** owner_key, delegate_key, expiry_height.

**DAG construction:**
```
Comp(Witness, Case(
    sig_check(owner_key),                                    -- owner (unrestricted)
    and(sig_check(delegate_key), height_lt(expiry_height))   -- delegate (before expiry)
))
```

where `height_lt(h)` = `Comp(Pair(Jet(BlockHeight), Const(U64(h))), Jet(Lt64))`.

**Witness (owner):** `[Left(Unit)][owner_signature]`.
**Witness (delegate):** `[Right(Unit)][delegate_signature]`.

**Cost:** ~5,040 steps (max branch: Ed25519Verify + Lt64 + overhead).

---

## 23. Covenants

Covenants in Exfer are script programs that use introspection jets to constrain the spending transaction's structure (inputs, outputs, values).

### 23.1 Multisig Covenant

See Section 22.2. The 2-of-2, 1-of-2, and 2-of-3 patterns are implemented as covenant templates.

### 23.2 HTLC Covenant

See Section 22.5. Supports atomic cross-chain swaps.

### 23.3 Escrow Covenant

See Section 22.6. Three-path (mutual, arbiter, timeout) dispute resolution.

### 23.4 Vault Covenant

See Section 22.7. Primary + recovery key pattern with timelock.

### 23.5 Delegation Covenant

See Section 22.8. Time-limited delegation of spending authority.

---

## 24. Payment Channels

Payment channels enable off-chain value transfer between two parties. The on-chain footprint is a single funding UTXO.

### 24.1 Open

**Funding transaction:** Create a single output locked by a 2-of-2 multisig script:
```
and(sig_check(party_a), sig_check(party_b))
```

**Initial state:** `{sequence: 0, balance_a: funding_amount, balance_b: 0}`. Total = `balance_a + balance_b`.

### 24.2 Update

Off-chain: parties sign a new state `{sequence: N+1, balance_a: new_a, balance_b: new_b}` where `new_a + new_b = total`. Each update exchanges pre-signed dispute transactions that allow challenging stale states.

The sequence number is monotonically increasing. A state is newer if its sequence number is higher.

### 24.3 Cooperative Close

Both parties agree to close. Construct a closing transaction spending the funding UTXO with outputs:

```
Output 0: value = balance_a, script = domain_hash("EXFER-ADDR", pk_a)
Output 1: value = balance_b, script = domain_hash("EXFER-ADDR", pk_b)
```

Omit any output with value < 200 (dust threshold).

**Witness:** 2-of-2 multisig witness `[sig_a][sig_b]`.

### 24.4 Unilateral Close

One party publishes a commitment transaction with two outputs:

```
Output 0: value = counterparty_balance, script = P2PKH(counterparty)   -- immediate
Output 1: value = publisher_balance, script = close_script              -- timelocked
```

**close_script:**
```
Case(
    and(sig_check(party_a), sig_check(party_b)),        -- cooperative (dispute path)
    and(height_gt(close_height + dispute_window), sig_check(publisher))  -- finalize
)
```

The publisher's funds are locked for a dispute window. After the window expires, the publisher can claim with their signature alone.

### 24.5 Dispute

If a counterparty publishes a stale commitment (old state), the other party challenges by spending the close_script output via the cooperative path using a pre-signed dispute transaction.

**dispute_script:**
```
Case(
    and(and(sig_check(party_a), sig_check(party_b)), height_lt(close_height + dispute_window)),
    and(sig_check(party_a), sig_check(party_b))    -- cooperative override
)
```

**Dispute window:** A parameter of the channel (in blocks). During this window, the counterparty can submit a dispute transaction proving a newer state. After the window, the publisher's close becomes final.

**Witness (challenge):** `[Left(Unit)][sig_a][sig_b]`.
**Witness (cooperative):** `[Right(Unit)][sig_a][sig_b]`.

---

## 25. Cost Computation

### 25.1 Fee Formula (Complete)

For a transaction with `I` inputs and `O` outputs:

```
tx_cost =
    script_eval_cost                                    // varies per input
  + output_typecheck_cost                               // 1,000 per script-locked output
  + sum_i(ceil_div(witness_bytes_i, 64))                // witness deserialization
  + sum_i(ceil_div(redeemer_bytes_i, 64))               // redeemer deserialization
  + sum_j(ceil_div(datum_bytes_j, 64))                  // datum deserialization
  + ceil_div(total_tx_bytes, 64)                        // transaction deserialization
  + I × 100 + O × 100                                  // UTXO I/O
  + I × 500 + O × 500                                  // SMT operations
  + sum_k(ceil_div(script_bytes_k, 64) × 10)           // script validation (script-locked inputs only)

min_fee = ceil_div(tx_cost, 100)
```

### 25.2 Script Cost by Pattern

| Pattern | Steps (per input) | Cells |
|---------|-------------------|-------|
| Pubkey hash (32-byte script) | 5,000 + ceil_div(sig_msg_bytes, 64) × 8 | 0 |
| 2-of-2 multisig | ~10,010 | ~6 |
| 1-of-2 multisig | ~5,020 | ~4 |
| 2-of-3 multisig | ~10,020 | ~8 |
| Hash lock | ~1,520 | ~3 |
| Timelock + signature | ~5,030 | ~4 |
| HTLC | ~6,530 | ~5 |
| Escrow | ~10,040 | ~8 |
| Vault | ~5,040 | ~4 |
| Delegation | ~5,040 | ~4 |

### 25.3 Cost Optimization Constraints

- Script cost is determined before execution. No estimation needed.
- Minimum-case cost check at output creation prevents permanently locked funds.
- Per-input cap: 4,000,000 steps. Per-transaction cap: 20,000,000 steps.
- Memory limit: 16 MiB per evaluation.
- Fee density (fee × 1,000,000 / tx_cost) determines mempool priority.

---

## 26. Jet Reference

### 26.1 Cryptographic

| Jet | ID | Input | Output | Steps | Cells | Behavior |
|-----|----|-------|--------|-------|-------|----------|
| Sha256 | 0x0001 | Bytes | Hash256 | 1,000 | 1 | SHA-256(input). Runtime: 500 + len/64 × 8. |
| Ed25519Verify | 0x0002 | Product(Bytes, Product(Bytes, Bytes)) | Bool | 5,000 | 1 | ZIP-215 verify(msg, pk, sig). False if pk≠32, sig≠64, or pk is small-order. Runtime: 5,000 + ceil(msg_len/64) × 8. |
| SchnorrVerify | 0x0003 | Product(Bytes, Product(Bytes, Bytes)) | Bool | 5,000 | 1 | Reserved. Always fails. |
| MerkleVerify | 0x0004 | Product(Hash256, Product(Hash256, Bytes)) | Bool | 32,000 | 1 | Verify Merkle proof. Runtime: 500 + proof_len/33 × 500. |

### 26.2 Arithmetic (64-bit)

| Jet | ID | Input | Output | Steps | Cells | Behavior |
|-----|----|-------|--------|-------|-------|----------|
| Add64 | 0x0100 | Product(U64, U64) | U64 | 10 | 1 | a + b. Error on overflow. |
| Sub64 | 0x0101 | Product(U64, U64) | U64 | 10 | 1 | a - b. Error if a < b. |
| Mul64 | 0x0102 | Product(U64, U64) | U64 | 10 | 1 | a × b. Error on overflow. |
| Div64 | 0x0103 | Product(U64, U64) | U64 | 10 | 1 | a / b. Error if b = 0. |
| Mod64 | 0x0104 | Product(U64, U64) | U64 | 10 | 1 | a mod b. Error if b = 0. |
| Eq64 | 0x0105 | Product(U64, U64) | Bool | 10 | 1 | a = b. |
| Lt64 | 0x0106 | Product(U64, U64) | Bool | 10 | 1 | a < b. |
| Gt64 | 0x0107 | Product(U64, U64) | Bool | 10 | 1 | a > b. |

### 26.3 Arithmetic (256-bit)

| Jet | ID | Input | Output | Steps | Cells | Behavior |
|-----|----|-------|--------|-------|-------|----------|
| Add256 | 0x0200 | Product(U256, U256) | U256 | 50 | 1 | a + b. Error on overflow. |
| Sub256 | 0x0201 | Product(U256, U256) | U256 | 50 | 1 | a - b. Error if a < b. |
| Mul256 | 0x0202 | Product(U256, U256) | U256 | 50 | 1 | a × b. Error on overflow. |
| Div256 | 0x0203 | Product(U256, U256) | U256 | 50 | 1 | a / b. Error if b = 0. |
| Mod256 | 0x0204 | Product(U256, U256) | U256 | 50 | 1 | a mod b. Error if b = 0. |
| Eq256 | 0x0205 | Product(U256, U256) | Bool | 50 | 1 | a = b. |
| Lt256 | 0x0206 | Product(U256, U256) | Bool | 50 | 1 | a < b (big-endian). |
| Gt256 | 0x0207 | Product(U256, U256) | Bool | 50 | 1 | a > b (big-endian). |

### 26.4 Byte Operations

| Jet | ID | Input | Output | Steps | Cells | Behavior |
|-----|----|-------|--------|-------|-------|----------|
| Cat | 0x0300 | Product(Bytes, Bytes) | Bytes | 100 | 1 | Concatenate. Runtime: 10 + total_len/8. |
| Slice | 0x0301 | Product(Bytes, Product(U64, U64)) | Bytes | 100 | 1 | source[start..start+len]. Clamps to bounds. Runtime: 10 + src_len/8. |
| Len | 0x0302 | Bytes | U64 | 10 | 0 | Byte count. |
| EqBytes | 0x0303 | Product(Bytes, Bytes) | Bool | 500 | 0 | Byte equality. Runtime: 10 + max(len_a, len_b)/8. |
| EqHash | 0x0304 | Product(Hash256, Hash256) | Bool | 500 | 0 | Hash equality. Runtime: 14. |

### 26.5 Introspection

| Jet | ID | Input | Output | Steps | Cells | Behavior |
|-----|----|-------|--------|-------|-------|----------|
| TxInputs | 0x0400 | Unit | List(...) | 1,000 | 0 | All inputs. Runtime: 10 + n×10. |
| TxOutputs | 0x0401 | Unit | List(...) | 1,000 | 0 | All outputs. Runtime: 10 + n×10. |
| TxValue | 0x0402 | U64 | U64 | 10 | 0 | Input value by index. Error if OOB. |
| TxScriptHash | 0x0403 | U64 | Hash256 | 10 | 0 | Input script hash by index. Error if OOB. |
| TxInputCount | 0x0404 | Unit | U64 | 5 | 0 | Number of inputs. |
| TxOutputCount | 0x0405 | Unit | U64 | 5 | 0 | Number of outputs. |
| SelfIndex | 0x0406 | Unit | U64 | 5 | 0 | Current input index. |
| BlockHeight | 0x0407 | Unit | U64 | 5 | 0 | Current block height. |
| TxSigHash | 0x0408 | Unit | Bytes | 5 | 0 | Signing digest. Runtime: 5 + len/64. |

### 26.6 List Operations

| Jet | ID | Input | Output | Steps | Cells | Behavior |
|-----|----|-------|--------|-------|-------|----------|
| ListLen | 0x0500 | List(A) | U64 | 10 | 0 | Element count. |
| ListAt | 0x0501 | Product(List(A), U64) | Option(A) | 10 | 1 | Element at index. None if OOB. |
| ListSum | 0x0502 | List(U64) | U64 | 1,000 | 0 | Sum. 0 if empty. Error on overflow. Runtime: 10 + n. |
| ListAll | 0x0503 | List(Bool) | Bool | 1,000 | 0 | All true. True if empty. Runtime: 10 + n. |
| ListAny | 0x0504 | List(Bool) | Bool | 1,000 | 0 | Any true. False if empty. Runtime: 10 + n. |
| ListFind | 0x0505 | List(Bool) | Option(U64) | 1,000 | 0 | Index of first true. None if not found. Runtime: 10 + n. |

---

## 27. Datum and Redeemer Interface

### Attaching Inline Datums

Set the output's `datum` field to the datum bytes. Serialization:
```
... || has_datum=0x01 || VarBytes(datum_bytes) || ...
```

### Attaching Hash-Committed Datums

Compute `datum_hash = SHA-256(datum_bytes)`. Set the output's `datum_hash` field. Serialization:
```
... || has_datum=0x00 || has_datum_hash=0x01 || datum_hash(32 bytes)
```

### Providing Datums at Spend Time

When spending an output with datum_hash but no inline datum, the spender must provide the datum in the witness `redeemer` field. The validator computes `SHA-256(redeemer)` and verifies it equals datum_hash.

### Resolution Logic

```
if output.datum is present:
    if output.datum_hash is also present:
        verify SHA-256(output.datum) = output.datum_hash
    datum = output.datum
else if output.datum_hash is present:
    require witness.redeemer is present
    require len(witness.redeemer) ≤ 4,096
    verify SHA-256(witness.redeemer) = output.datum_hash
    datum = witness.redeemer
else:
    datum = None
```

The resolved datum is passed to the script as the third element of the input tuple.

---

## 28. UTXO Selection

**Constraint satisfaction problem:**

Given:
- Available UTXOs: `{(outpoint_i, value_i, is_coinbase_i, height_i)}`
- Target amount: `A`
- Current height: `H`
- Recipient script

Select a subset S such that:
1. For all UTXO in S: if `is_coinbase`, then `H - height ≥ 360`.
2. `sum(values in S) ≥ A + min_fee(tx with |S| inputs, estimated outputs)`.
3. If `sum(values in S) - A - fee ≥ 200`: create a change output (additional output in fee calculation).
4. If `sum(values in S) - A - fee < 200` and > 0: fold residual into fee.
5. Every output value ≥ 200 (dust threshold).
6. Serialized transaction size ≤ 1,048,576 bytes.

The fee depends on the transaction structure, which depends on the fee. Iterate: estimate fee, construct transaction, recompute fee, adjust if needed.

---

## 29. Key Management

**Key generation:** Generate an Ed25519 key pair. The signing key is 32 bytes (seed). The verifying key (public key) is 32 bytes.

**Address derivation:**
```
address = domain_hash("EXFER-ADDR", pubkey)
```

Returns a 32-byte Hash256. This is used as the `script` field for pubkey hash locked outputs.

**Signature construction:**
1. Compute signing message: `"EXFER-SIG" || genesis_block_id(32) || tx_header || tx_body`.
2. Ed25519 sign the message with the signing key.
3. Signature is 64 bytes.

**Witness format:** `pubkey(32 bytes) || signature(64 bytes)` = 96 bytes total.

**Wallet encryption (reference implementation):**
- Algorithm: Argon2id key derivation + AES-256-GCM encryption.
- Argon2id parameters: m=262,144 KiB, t=3, p=1.
- File format: `EXFK(4 bytes) || version(1) || salt(16) || nonce(12) || ciphertext(48)` = 81 bytes.
- Ciphertext contains the 32-byte signing key + 16-byte GCM authentication tag.

---

## 30. Network Submission

To submit a transaction to the network:

1. **Serialize the transaction** (Section 5.1).
2. **Construct a NewTx message:** `msg_type=0x20 || payload_length(u32 LE) || serialized_transaction`.
3. **Send** to one or more connected peers. On established (post-handshake) connections, the message is wrapped in the authenticated frame format (Section 17): `counter(u64 LE) || msg_type(0x20) || payload_length(u32 LE) || serialized_transaction || hmac(16 bytes)`.

**Expected behavior:**
- If valid: peers relay the transaction to their peers and add it to their mempools.
- If invalid: peers silently drop the transaction. No error response is sent.

**Error conditions:**
- Transaction fails validation (any rule in Section 12).
- Transaction is a duplicate (already in mempool or confirmed).
- Transaction spends outputs already spent by a mempool transaction.
- Mempool is full and transaction's fee density is too low.

---

## Appendix A: Test Vectors

All hex values below are computed from the reference implementation. Implementations must produce identical outputs for correctness.

### A.1 Domain-Separated Hashes

`domain_hash(separator, data)` = `SHA-256(len(separator) || separator || data)`.

Each row: `domain_hash(separator, [0x00])`.

| Separator | Result |
|-----------|--------|
| EXFER-SIG | `c32adc238ff3a66535a9180383711c5b84528fd535ff7e1934372f0a30efbbe6` |
| EXFER-TX | `7cf80b71d07b2c0f8a0645a57c5d98c511fbe267503224a93c38968d4411ca03` |
| EXFER-TXROOT | `f53925c44981d10789596e61503f829fd717420a4e77f7a1c58dc6dcbc09d2a7` |
| EXFER-STATE | `1cb15b3427e2260373722ae99aff98358e2c03bd2760b9493cf6d3fc30a54d7d` |
| EXFER-ADDR | `48e0d24cf73d51393cd3102222cdf69d02394261d1c9ce6e4d599214c3a9d228` |
| EXFER-AGENT | `e02ef4eaf362f7cb4bbf0cb1f7bdc3410db8e7d3cd3397a8fa0646933f14de12` |
| EXFER-SCRIPT | `0136103e88d1ccc06c639d3a2e99002941e61e691b775259268e0280c4bcca23` |
| EXFER-POW-P | `0e4b0b5d4652e52c57e77e90bac1fc8fb83e7feb932f5a1b1f398deda962c749` |
| EXFER-POW-S | `65974595a51e46671a67197774f0b2b2b11164b51b696cf9efd2d20dba16040c` |
| EXFER-WTXID | `8a9366392187901fdeccaae02cacf9a63dbf7a60d112e4b13ca13230e3743613` |
| EXFER-AUTH | `89edf3fdddaa59667639e471be147918056ae1a00b8502a60fd9c8f6871e72c2` |
| EXFER-SESSION | `5e4c61773f051a55a8138785a3ac5987b233b4765c376229c8f4a717b4da36ca` |
| EXFER-MERKLE | `ce2039c9d6b0f0ea92b42b8a3a9c3b7b7d4e3bd8f1fedeb3d3e52dad820116ad` |
| EXFER-MAC-IR | `cafb477b835296bc0bb56ef0ebf24f513e5a2df9dd657c813cafa41732aca082` |
| EXFER-MAC-RI | `214b628b02f189b484f32ee032c5c98a1b309e57673165041d47417e8be0eb8b` |

**Note:** The EXFER-AUTH, EXFER-SESSION, EXFER-MAC-IR, and EXFER-MAC-RI rows above use raw `SHA-256(separator || [0x00])`, **not** `domain_hash`. They omit the length-prefix byte. The remaining separators in this table use the standard `domain_hash` construction with the length prefix.

### A.2 Genesis Block

**Serialized header (156 bytes):**
```
0100000000000000000000000000000000000000000000000000000000000000000000
0000000000000000009004b66900000000010000000000000000000000000000000000
0000000000000000000000000000030100000000000096d29616a481eac5ffa35f3f7c
f2add76ac921e733f72174d45035b5996341d3aafc1988635522e0fdaa4249ccda5961
27ff689eba8cd1de01a9cdaaf671e9a8
```

**block_id** = `SHA-256(header_bytes)`:
```
d7b6805c8fd793703db88102b5aed2600af510b79e3cb340ca72c1f762d1e051
```

**Coinbase transaction (349 bytes):**
```
0100010000000000000000000000000000000000000000000000000000000000000000
000000000000e40b540200000020000000000000000000000000000000000000000000
000000000000000000000000000006014e49535420426561636f6e20323032362d3033
2d31345432323a32333a30305a20353631414132364234323134454538463341414434
4635423842443342343439444633353033433039363131313130453530414332384633
3933373942364438393034463833333034374546463631303943393442423539414434
4242333333353933303743373746373143324643334241364431303733414538383146
383120e280942044657369676e65642c20617564697465642c20616e64206275696c74
206279206175746f6e6f6d6f7573206d616368696e65732e20412068756d616e207072
6f7669646564206d696e696d616c206e656365737361727920737570706f72742e00
```

- TxId = `5e63e65ea2a30d9c874f16eccb366022bfe692d6d933470cb50107df7c2b04c6`
- WtxId = `96d29616a481eac5ffa35f3f7cf2add76ac921e733f72174d45035b5996341d3`
- tx_root = WtxId (single-transaction block)
- state_root = `aafc1988635522e0fdaa4249ccda596127ff689eba8cd1de01a9cdaaf671e9a8`

### A.3 Argon2id PoW (Genesis Block)

Using the genesis header bytes from A.2:

```
pw   = domain_hash("EXFER-POW-P", header)
     = 3e5bd47e30df181035ecb70f9ad0ba16c48fd8f7e96f5e5b82cd8ff8d843e44c

salt = domain_hash("EXFER-POW-S", header)
     = d28d116248882eb65ad03605dce15f9920e21978e221ca18b4f43886d0521d73

pow  = Argon2id(pw, salt, m=65536, t=2, p=1, len=32)
     = 00c0782180c6270ff26b8d19deb26f65dcf144753d0d2dffc7b604552789a21c

target = 0100000000000000000000000000000000000000000000000000000000000000

pow < target = true (valid PoW)
```

### A.4 Serialized Transaction

1-input, 1-output transaction. Input: prev_tx_id = `[0xAA; 32]`, output_index = 0. Output: value = 1,000,000,000 (10 EXFER), script = `[0xBB; 32]`, no datum, no datum_hash. Witness: `[0xCC; 96]`, no redeemer.

**Serialized (183 bytes):**
```
01000100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0000000000ca9a3b000000002000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
bbbbbbbbbbbbbbbbbbbbbb00006000cccccccccccccccccccccccccccccccccccccccccc
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
cccccccccc00
```

- TxId = `a2867b18dc2f273e0befe9946673a83586412eee009ff49196a484d7c7e925c0`
- WtxId = `37b6a8127c4a9b802c17482c208d4efe289c318f5bebcbf8c8b0809d5969d636`

### A.5 Merkle Root Computation

Using synthetic WtxId hashes: `h_i = domain_hash("EXFER-WTXID", [i])` for i = 1..4.

```
h_1 = 9beb7854b427d2f24abe3be7a8fa2af3f4a3751a17bd7647b41ac17c2dcdc80f
h_2 = e823db473776b2bcd056cc8491258f8cac56e86c0346995208e4974c9e4ab0b6
h_3 = cb00e7c119309a7fec156bae7a6da7d4f9e353644b64d170643e106c6c912d04
h_4 = 9475c87b5ff677fd4349b6cece2cd8e9a903a8847ab32ce00afc217f63b57219
```

| Transaction count | Merkle root |
|-------------------|-------------|
| 1 | `9beb7854b427d2f24abe3be7a8fa2af3f4a3751a17bd7647b41ac17c2dcdc80f` |
| 2 | `b5f5507bd7ff50450c1c818c90a0abad59a5c805926fa94b3ee8a1e6a346873a` |
| 3 | `3d6a38ee7cb8ac6f1f0d75b3a473ebf9212ee13ebab2307e432c0526d64ab5f7` |
| 4 | `8ff248a73262d32dc0ed7322fd61bbab0fc8bb95f9e84b22bbfe87f963e212a2` |

### A.6 Script Serialization and Merkle Commitment

**Program:** Single `Iden` node (identity function).

**Serialized (9 bytes):** `010000000000000000`
- node_count = 1 (`01000000`)
- root_index = 0 (`00000000`)
- node[0] = tag 0x00 (Iden) (`00`)

**Merkle hash:** `domain_hash("EXFER-SCRIPT", [0x00])` = `0136103e88d1ccc06c639d3a2e99002941e61e691b775259268e0280c4bcca23`

### A.7 State Root (Sparse Merkle Tree)

**Empty SMT root** (depth 256): `b178c245c947ea7e21ecede07728941a6ab1b706143c06873baff8ebd6de6308`

Canonical output used for all UTXOs below: value = 100,000,000 (1 EXFER), script = `[0x00; 32]`, no datum, no datum_hash. Serialized (44 bytes): `00e1f50500000000200000000000000000000000000000000000000000000000000000000000000000000000`.

**UTXO 1:** tx_id = `[0xAA; 32]`, output_index = 0, height = 0, coinbase = true.
```
leaf_key   = 47193d83874af8362d4a875497f76093ac9599585bc653f6c1e996f46c669166
leaf_value = 64dd17646ff5b528a303394bfcf769ef28e0e2f11679e002e625d4f51e994f3b
state_root = a9a2fcf06b7ea20b487714a71d17888ca7a2a86c4364a5287a43535662273a48
```

**UTXO 2 (cumulative):** tx_id = `[0xBB; 32]`, output_index = 0, height = 1, coinbase = false.
```
leaf_key   = 9314ba260f6c674f842c967f428359031986e567f1df590a644974b7fc8cb6a7
leaf_value = f23c28768873e140f0516f0bd87918d94f9cd0f7acd8a1cc68d53dae4663fe24
state_root = c891bd8ad650ef06f44fd2689ab0466f5b3b9355f5dc37a1bc43e30c9a1facce
```

**UTXO 3 (cumulative):** tx_id = `[0xCC; 32]`, output_index = 0, height = 2, coinbase = false.
```
leaf_key   = ecbf1c33256b2f0baadfe2b02c7d181e551a325bdf7952324a70bd644ed73669
leaf_value = fba36f58a7f6184e06de985aa9ab7c5baa02ea30dd000657cef9257ae9e05060
state_root = 9fc927b51f0e58a529d90404a584b3c77448e55ab9fe97e4b626a2e85eb53ae4
```

### A.8 Block Reward

| Height | Reward (exfers) |
|--------|----------------|
| 0 | 10,000,000,000 |
| 1 | 9,999,998,912 |
| 100 | 9,999,891,228 |
| 1,000 | 9,998,912,280 |
| 4,320 | 9,995,301,790 |
| 10,000 | 9,989,127,892 |
| 43,200 | 9,953,117,900 |
| 100,000 | 9,891,814,300 |
| 6,307,200 | 5,050,000,000 |
| 12,614,400 | 2,575,000,000 |
| 18,921,600 | 1,337,500,000 |
| 63,072,000 | 109,667,968 |
| 630,720,000 | 100,000,000 |

### A.9 Emission LUT Endpoints

```
LUT[0]    = 18,446,744,073,709,551,616  (2^64)
LUT[4096] = 9,223,758,693,993,446,757
K         = 18,443,622,869,203,936,790
```

### A.10 Difficulty Retarget

At genesis target 2^248, expected_time = 43,190 seconds:

**Double speed** (actual_time = 2 × expected_time = 86,380):
```
new_target = 2^248 × 86380 / 43190 = 2^249
           = 0200000000000000000000000000000000000000000000000000000000000000
```

**Half speed** (actual_time = expected_time / 2 = 21,595):
```
new_target = 2^248 × 21595 / 43190 = 2^247
           = 0080000000000000000000000000000000000000000000000000000000000000
```

### A.11 Cost Calculation

1-input, 1-output transaction, pubkey hash lock, 96-byte witness:
```
sig_message_bytes      = len("EXFER-SIG" || genesis_block_id || tx_header || tx_body)
ed25519_data_cost      = ceil_div(sig_message_bytes, 64) × 8
script_eval_cost       = 5,000 + ed25519_data_cost   (per pubkey hash input)
output_typecheck_cost  = 0              (32-byte script)
witness_deser_cost     = 2              (ceil_div(96, 64))
datum_deser_cost       = 0
tx_deser_cost          = ceil_div(total_serialized_bytes, 64)
utxo_io_cost           = 200            (1 × 100 + 1 × 100)
smt_cost               = 1,000          (1 × 500 + 1 × 500)

tx_cost = script_eval_cost + 0 + 2 + 0 + tx_deser_cost + 200 + 1,000
min_fee = ceil_div(tx_cost, 100)
```

For the transaction in A.4 (183 bytes): `tx_deser_cost = ceil_div(183, 64) = 3`. The signing message is 9 + 32 + tx_header + tx_body bytes; `ed25519_data_cost = ceil_div(sig_message_bytes, 64) × 8`. `tx_cost = 5,000 + ed25519_data_cost + 0 + 2 + 0 + 3 + 200 + 1,000`.

---

## Appendix B: Domain Separator Catalog

| Separator | Byte Encoding | Usage |
|-----------|--------------|-------|
| EXFER-SIG | `b"EXFER-SIG"` (9 bytes) | Transaction signing message prefix; followed by genesis_block_id(32) to bind signatures to this chain |
| EXFER-TX | `b"EXFER-TX"` (8 bytes) | TxId computation |
| EXFER-TXROOT | `b"EXFER-TXROOT"` (12 bytes) | Merkle tree internal nodes |
| EXFER-STATE | `b"EXFER-STATE"` (11 bytes) | SMT leaf key derivation |
| EXFER-ADDR | `b"EXFER-ADDR"` (10 bytes) | Address (pubkey hash) derivation |
| EXFER-AGENT | `b"EXFER-AGENT"` (11 bytes) | Agent identity derivation |
| EXFER-SCRIPT | `b"EXFER-SCRIPT"` (12 bytes) | Script Merkle commitment (program serialization) |
| EXFER-MERKLE | `b"EXFER-MERKLE"` (12 bytes) | MerkleVerify jet internal node hashing |
| EXFER-POW-P | `b"EXFER-POW-P"` (11 bytes) | PoW password derivation |
| EXFER-POW-S | `b"EXFER-POW-S"` (11 bytes) | PoW salt derivation |
| EXFER-WTXID | `b"EXFER-WTXID"` (11 bytes) | Witness-committed transaction hash |
| EXFER-AUTH | `b"EXFER-AUTH"` (10 bytes) | Peer authentication transcript |
| EXFER-SESSION | `b"EXFER-SESSION"` (13 bytes) | Session key derivation from transcript and DH secret |
| EXFER-MAC-IR | `b"EXFER-MAC-IR"` (12 bytes) | Directional MAC key derivation: initiator → responder |
| EXFER-MAC-RI | `b"EXFER-MAC-RI"` (12 bytes) | Directional MAC key derivation: responder → initiator |

All domain-separated hashes use the prefix-free construction: `SHA-256(len_byte || separator || data)`, **except** EXFER-AUTH, EXFER-SESSION, EXFER-MAC-IR, and EXFER-MAC-RI, which use raw `SHA-256(separator || data)` without the length-prefix byte. These four are session-scoped handshake and key-derivation operations, not content-addressed consensus hashes.

---

## Appendix C: Worked Examples

### C.1 Constructing a Simple Payment

**Scenario:** Alice (pk_a) sends 500 EXFER to Bob (pk_b), with one UTXO worth 1000 EXFER.

**Step 1: Compute addresses.**
```
addr_a = domain_hash("EXFER-ADDR", pk_a)
addr_b = domain_hash("EXFER-ADDR", pk_b)
```

**Step 2: Build transaction body.**

tx_header:
```
[0x01, 0x00]  -- input_count = 1 (u16 LE)
[0x02, 0x00]  -- output_count = 2 (u16 LE)
```

Input 0:
```
prev_tx_id (32 bytes)
output_index (u32 LE)
```

Output 0 (to Bob, 500 EXFER = 50,000,000,000 exfers):
```
value: [0x00, 0x74, 0x3B, 0xA4, 0x0B, 0x00, 0x00, 0x00]  -- 50,000,000,000 u64 LE
VarBytes(addr_b): [0x20, 0x00] || addr_b (32 bytes)
has_datum: [0x00]
has_datum_hash: [0x00]
```

Output 1 (change to Alice):
```
value: (total_input - 50,000,000,000 - fee) as u64 LE
VarBytes(addr_a): [0x20, 0x00] || addr_a (32 bytes)
has_datum: [0x00]
has_datum_hash: [0x00]
```

**Step 3: Compute signing message.**
```
sig_msg = "EXFER-SIG" || genesis_block_id(32) || tx_header || tx_body
```

**Step 4: Sign.**
```
signature = Ed25519_sign(sk_a, sig_msg)  -- 64 bytes
```

**Step 5: Build witness.**
```
VarBytes([pk_a (32) || signature (64)]): [0x60, 0x00] || pk_a || signature
has_redeemer: [0x00]
```

**Step 6: Compute identifiers.**
```
TxId = domain_hash("EXFER-TX", tx_header || tx_body)
WtxId = domain_hash("EXFER-WTXID", tx_header || tx_body || witnesses)
```

**Step 7: Verify fee.**
```
fee = total_input - 50,000,000,000 - change_value
sig_msg_len = len("EXFER-SIG" || genesis_block_id || tx_header || tx_body)
ed25519_data_cost = ceil_div(sig_msg_len, 64) × 8
tx_cost = (5,000 + ed25519_data_cost) + 0 + 2 + 0 + ceil_div(total_bytes, 64) + 200 + 1,000
min_fee = ceil_div(tx_cost, 100)
assert fee ≥ min_fee
```

### C.2 Constructing an HTLC

**Scenario:** Alice locks 10 EXFER. Bob can claim with preimage of H. Alice reclaims after block 100,000.

**Step 1: Build the HTLC script program.**

Using the builder:
1. `sig_check_bob = Comp(Pair(Comp(Jet(TxSigHash), Unit), Pair(Const(pk_bob), Witness)), Jet(Ed25519Verify))`
2. `hash_check = Comp(Pair(Comp(Witness, Jet(Sha256)), Const(H)), Jet(EqHash))`
3. `hash_path = and(hash_check, sig_check_bob)`
4. `sig_check_alice = [similar to sig_check_bob with pk_alice]`
5. `timeout_check = Comp(Pair(Jet(BlockHeight), Const(U64(100000))), Jet(Gt64))`
6. `timeout_path = and(timeout_check, sig_check_alice)`
7. `root = Comp(Witness, Case(hash_path, timeout_path))`

**Step 2: Serialize the program.** Apply Section 6.6 serialization.

**Step 3: Create the output.**
```
value = 1,000,000,000 (10 EXFER)
script = serialized_program_bytes
datum = None
datum_hash = None
```

**Step 4: Bob claims (hash path).**

Witness data (serialized Values in order of Witness node evaluation):
1. Selector: `Left(Unit)` → `[0x01, 0x00]`
2. Preimage: `Bytes(preimage)` → `[0x05, len_le4, preimage_bytes]`
3. Bob's signature: `Bytes(sig)` → `[0x05, 0x40, 0x00, 0x00, 0x00, sig_64_bytes]`

Redeemer: None.

**Step 5: Verify cost.**

The static cost of the HTLC script determines the minimum fee for the spending transaction.
