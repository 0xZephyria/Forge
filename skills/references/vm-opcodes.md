# ZephyriaVM Opcodes (RISC-V 64IM) + Forge Reference

Zephyria ZVM is a **register-based RISC-V VM**, not a stack-based EVM. This reference contains the standard RISC-V core instructions used by the Forge compiler and the custom Zephyria blockchain system calls.

## §1 — Zephyria ABI Register Mapping

| Reg | Name | Zephyria ABI Use |
| --- | --- | --- |
| x0 | zero | Hardwired zero |
| x1 | ra | Return address |
| x2 | sp | Stack pointer |
| x3 | gp | Global pointer (points to `mine.*` state base) |
| x4 | tp | Thread pointer (points to `params` base) |
| x5-7 | t0-t2 | Temporary / scratch registers |
| x8 | s0 | Saved / Frame pointer |
| x9 | s1 | Saved: contract state pointer |
| x10-16 | a0-a6 | Arguments / Return values |
| x17 | a7 | **Syscall / Custom-Op Number** |
| x18-27 | s2-s11 | Saved registers (access lists, linear tracking, etc.) |
| x28-31 | t3-t6 | Temporary scratch registers |

---

## §2 — Standard RISC-V 64IM Core

These are standard instructions emitted by the `src/riscv.zig` encoder.

| Instruction | Format | Description |
| --- | --- | --- |
| `ADD rd, rs1, rs2` | R-type | 64-bit addition (rd = rs1 + rs2) |
| `ADDI rd, rs1, imm` | I-type | Add immediate (rd = rs1 + imm12) |
| `SUB rd, rs1, rs2` | R-type | 64-bit subtraction (rd = rs1 - rs2) |
| `MUL rd, rs1, rs2` | R-type | 64-bit multiply (RV64M) |
| `DIV rd, rs1, rs2` | R-type | 64-bit divide (RV64M) |
| `AND / OR / XOR` | R-type | Bitwise logic |
| `SLL / SRL / SRA` | R-type | Shifts (Logical Left, Logical Right, Arithmetic Right) |
| `LUI rd, imm` | U-type | Load Upper Immediate (rd = imm << 12) |
| `AUIPC rd, imm` | U-type | Add Upper Imm to PC |
| `JAL rd, imm20` | J-type | Jump and Link (relative) |
| `JALR rd, rs1, imm12` | I-type | Jump and Link (absolute) |
| `BEQ / BNE / BLT / BGE` | B-type | Conditional branching |
| `LD / SD` | I/S-type | Load / Store Doubleword (64-bit) |
| `LW / SW` | I/S-type | Load / Store Word (32-bit) |
| `ECALL` | System | Environment call (triggers host syscall) |

---

## §3 — Zephyria Custom Opcodes (ZVM Opcodes)

Encoded in the RISC-V custom-0 through custom-3 opcode spaces. These provide specialized blockchain "superpowers" to the ZVM.

### ── Custom-0 (0x0B): State & Data
- `STATE_READ` (0x00): Read contract state field given ID and key.
- `STATE_WRITE` (0x01): Write contract state field.
- `STATE_EXISTS` (0x02): Check if entry exists in map/set.
- `STATE_DELETE` (0x03): Remove entry from map/set.

### ── Custom-1 (0x2B): Permissions & Flow
- `AUTH_CHECK` (0x10): Assert caller has a specific authority; panics on failure.
- `ACCESS_ASSERT` (0x11): Verify access list compliance for a memory entry.
- `DELEGATE_GAS` (0x12): Forward gas costs to a specified payer address.

### ── Custom-2 (0x5B): Assets & Ledger
- `ASSET_TRANSFER` (0x20): Linear asset transfer (IDs 0-0xFFF).
- `ASSET_MINT` (0x21): Create new asset units (authority guarded).
- `ASSET_BURN` (0x22): Destroy asset units.
- `NATIVE_PAY` (0x23): Pay native ZPH currency to an address.

### ── Custom-3 (0x7B): VM Environment
- `EMIT_EVENT` (0x30): Push log event into the transaction receipt.
- `SCHEDULE_CALL` (0x31): Deferred action call (async execution).
- `REVERT` (0x32): Abort execution with a message.
- `GET_CALLER` (0x34): Load current caller's address into memory.
- `GET_NOW` (0x35): Load current block timestamp (ms).
- `GET_BLOCK` (0x36): Load current block height.
- `ORACLE_QUERY` (0x38): Trigger a signed oracle request.

---

## §4 — Forge API Reference

### Cheatcodes (Test Harness)
Used within `.foztest` files to manipulate the blockchain state.
```zeph
vm.warp(ts: u64)      // Set block.timestamp
vm.roll(n: u64)       // Set block.number
vm.deal(a, amount)    // Fund address
vm.prank(a)           // Impersonate address (one call)
vm.startPrank(a)      // Permanent impersonation
vm.stopPrank()        // Clear impersonation
vm.expectRevert(msg)  // Anticipate failure
vm.expectEmit()       // Anticipate event log
vm.snapshot()         // Save state
vm.revertTo(id)       // Restore state
```

### Scripting & Assertions
```zig
assertEq(T, a, b);    // Check equality
assertGt(T, a, b);    // Greater than
assertReverts(res);   // Expect .revert status
assertEmitted(logs,t);// Expect topic in logs
```
