# eBPF Internals & Verifier Engineering Guide

Writing high-performance packet filtering code in eBPF requires satisfying the strict mathematical checks of the Linux Kernel Verifier. This document outlines the architectural constraints, pitfalls encountered, and solutions engineered in Abyss.

---

## 1. Verifier Constraints in Ring 0

The Linux eBPF verifier performs static analysis on every instruction before allowing bytecode into the kernel:
- **Instruction Complexity Limit**: Maximum 1,000,000 instructions processed across all simulated execution branches.
- **Stack Limit**: Maximum 512 bytes total per BPF program.
- **Pointer Safety**: All packet memory accesses (`ctx.data()` through `ctx.data_end()`) must be bounded by explicit conditional guards.
- **Unbounded Memory Accesses**: Variable-offset memory reads or writes into the stack (`PTR_TO_STACK`) are rejected if the offset range cannot be statically proven within bounds.
- **No Unresolved Relocations**: `#![no_std]` code running on bare-metal `bpfel-unknown-none` target cannot reference standard library symbols or runtime helpers (e.g. `__multi3` compiler-rt intrinsics).

---

## 2. Deep Packet Inspection: Verifier Challenges & Solutions

### 2.1 The Problem: Loop Branch Explosion (`1,000,001 insns`, `os error 7`)
In naive string search implementations, a sliding window compares each pattern byte against the payload:
```rust
// NAIVE APPROACH - REJECTED BY VERIFIER
for i in 0..MAX_WINDOW {
    for j in 0..MAX_PATTERN_LEN {
        if j >= pattern_len { break; } // Verifier forks state!
        if payload[i + j] != pattern[j] { // Verifier forks state!
            matched = false;
            break;
        }
    }
}
```
In eBPF, when the verifier encounters an inner loop condition that depends on runtime-loaded data (`pattern_len`), it simulates both the taken and not-taken branches for every iteration. For a window of 16 bytes and a pattern of 16 bytes, the state exploration branch count exceeds $2^{16} = 65,536$ states, causing the verifier to exceed its 1,000,000 instruction budget and reject the program with `Argument list too long (os error 7)`.

### 2.2 The Solution: Branchless Mask Table (`MASKS`)
In `abyss-gaze` ([`scanner.rs`](file:///home/kaddulive/Desktop/Projects/abyss/kernel-modules/abyss-gaze/src/scanner.rs)), dynamic branching was eliminated by introducing a zero-branch constant mask table:

```rust
pub const MASKS: [[u8; 16]; 17] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // len 0
    [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // len 1
    [0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // len 2
    // ... up to len 16
    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
];
```

The difference between the candidate chunk and the pattern is accumulated across the 16-byte window using bitwise operations:
```rust
let mut diff: u8 = 0;
let mut j = 0;
while j < MAX_MATCH_LEN {
    let chunk_byte = chunk[(offset + j) & 63];
    let pat_byte = sig.pattern[j & 15];
    let m = mask[j & 15];
    diff |= (chunk_byte ^ pat_byte) & m;
    j += 1;
}
return diff == 0;
```
**Why this passes the verifier:**
- The loop runs for a fixed number of iterations (`MAX_MATCH_LEN = 16`).
- No branch condition exists inside the loop (`if j >= plen` is replaced by `& m`).
- The verifier analyzes a single linear path through the loop, reducing processed instructions from 1,000,000+ down to under 6,000.

---

## 3. Stack Snapshotting & Offset Bounding

### 3.1 Packet Pointer Volatility vs Fixed Stack Buffers
Dereferencing pointers directly into packet memory (`ctx.data() + offset`) inside nested loops requires the verifier to prove that `offset + j < ctx.data_end()` for every possible dynamic path. If the offset is calculated from transport headers (e.g., TCP Data Offset), the verifier loses track of bounds and flags potential out-of-bounds reads.

### 3.2 Solution: Fixed 64-Byte Linear Snapshot
`abyss-gaze` snapshots a bounded 32-byte window of the payload into a fixed 64-byte stack array (`[u8; 64]`) in a single linear pass:
```rust
let mut chunk = [0u8; CHUNK_SIZE]; // CHUNK_SIZE = 64
let mut chunk_len: usize = 0;

for k in 0..MAX_SCAN_WINDOW {
    let p = (packet_start + payload_offset + k) as *const u8;
    if (p as usize) + 1 > packet_end {
        break;
    }
    chunk[k] = unsafe { core::ptr::read_volatile(p) };
    chunk_len += 1;
}
```

### 3.3 Stack Read Masking (`& 63`)
To prevent `invalid unbounded variable-offset read from stack R0`:
- Stack sizes are kept strictly to powers of two (`CHUNK_SIZE = 64`).
- All indexing into the stack buffer is bitwise masked: `chunk[idx & 63]`.
- This informs the verifier's value-range propagation pass that the register value is strictly bounded between `0` and `63`, never exceeding the stack frame.

---

## 4. LLVM Backend & Arithmetic Safety

### 4.1 Avoiding `__multi3` Compiler-RT Calls
On bare-metal target `bpfel-unknown-none`, the BPF instruction set has 64-bit multiplication (`MUL64`) but lacks native 128-bit operations. When using `saturating_mul` on `u64`:
```rust
// Causes LLVM to generate 128-bit arithmetic call:
let tokens_to_add = (elapsed_ns.saturating_mul(max_tokens)) / refill_interval_ns;
```
LLVM emits a call to `__multi3` (a 128-bit multiplication helper from `compiler-rt`), which causes Aya load failure:
```text
function 0x338 not found while relocating abyss_tide
```

### 4.2 Solution: Bounded `wrapping_mul`
Because `elapsed_ns < refill_interval_ns` is guaranteed by the preceding condition, `(elapsed_ns * max_tokens)` is mathematically bounded within `u64`. Switching to `wrapping_mul`:
```rust
let tokens_to_add = elapsed_ns.wrapping_mul(max_tokens) / refill_interval_ns;
```
instructs LLVM to emit a single native `MUL64` instruction with zero compiler-rt dependencies.

---

## 5. Tail Call Chaining & Program Lifetime

In eBPF, `bpf_tail_call()` jumps to another program stored in a `BPF_MAP_TYPE_PROG_ARRAY` without returning.
- When loading multiple modules via Aya, programs must be loaded (`prog.load()`) before taking maps (`take_map()`) to ensure map relocations succeed.
- To store a module into `MODULE_SLOTS`, clone its file descriptor:
  ```rust
  let fd = prog.fd()?.try_clone()?;
  module_slots.set(slot_index, fd, 0)?;
  ```
- This preserves the file descriptor in kernel space across program reloads and daemon updates.

