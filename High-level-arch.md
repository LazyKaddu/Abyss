Here is a clean, definitive blueprint of your monorepo. Save this layout in your mind (or notes); it maps out the entire anatomy of **Abyss**.

---

### Root Directory (`abyss/`)

* **What it does:** The Workspace root container. It ties all independent Rust packages together so they share a single lockfile and can be built concurrently.
* **What should be inside:**
* Root `Cargo.toml` (declaring `workspace.members`).



---

### `abyss-common/`

* **What it does:** The shared memory contract. Because kernel-space and user-space run in completely isolated memory environments, this crate defines the raw data structs (like packet telemetry metrics or map keys) that **both** sides must agree on identically.
* **What should be inside:**
* `src/lib.rs` configured with `#![no_std]` containing shared structs (`#[repr(C)]`).



---

### `abyss-daemon/`

* **What it does:** The background engine (running in user-space with root privileges). It reads the compiled eBPF bytecode, loads it into the Linux kernel via the Aya framework, attaches `abyss-core` to your network card, and asynchronously polls the eBPF maps for telemetry data.
* **What should be inside:**
* `src/main.rs`: The async runtime (Tokio), eBPF loader logic, and map-reading daemons.



---

### `abyss-cli/`

* **What it does:** The control panel (`abyssctl`). A lightweight command-line binary that lets you talk to the daemon or directly manipulate eBPF maps to check status, block IPs, or toggle settings on the fly.
* **What should be inside:**
* `src/main.rs`: CLI argument parsing and communication logic.



---

### `kernel-modules/`

* **What it does:** The Ring 0 staging ground. This parent directory groups all standalone eBPF payloads that compile down to raw bytecode (`bpfel-unknown-none`) and run directly inside the network driver.
* **What should be inside:**
* **`abyss-core/` (The Dispatcher):** The main XDP entry point attached to the NIC. It parses basic headers, inspects the routing tables, and executes `bpf_tail_call()` to jump into specific modules.
* **`abyss-tide/` (The Rate Limiter):** A standalone module for token-bucket tracking, timestamp comparisons (`bpf_ktime_get_ns()`), and dropping flood traffic via LRU Hash Maps.
* **`abyss-gaze/` (The DPI Engine):** A standalone module for deep packet inspection, performing strict bounds-checking to scan payload byte arrays for signatures.
