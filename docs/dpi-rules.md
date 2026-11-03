# Deep Packet Inspection (DPI) Rules Guide

Abyss includes an ultra-low-latency Deep Packet Inspection engine (`abyss-gaze`) operating in Slot 1 of the Ring 0 Module Bay. It parses L4 transport headers (TCP/UDP) and evaluates application payloads against signature patterns.

---

## 1. Rule Format & Syntax

DPI signature files follow a simple line-delimited format:
```text
<ACTION> <PAYLOAD_OFFSET> <PATTERN>
```

| Field | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `ACTION` | Keyword | Action to take upon match: `DROP`, `PASS`, `ALERT` | `DROP` |
| `PAYLOAD_OFFSET` | Integer | Starting byte offset within application payload (`0` for sliding window search) | `0` |
| `PATTERN` | String | Plaintext signature string (up to 16 bytes) | `UNION SELECT` |

Lines starting with `#` and empty lines are ignored as comments.

---

## 2. Default Built-in Signatures

If no custom signatures file is supplied via `--signatures`, Abyss loads the following default security signatures into `DPI_SIGNATURES`:

```text
# Default Abyss WAF & Exploitation Signatures
DROP 0 ../..
DROP 0 /etc/passwd
DROP 0 UNION SELECT
DROP 0 <script
```

- **`../..`**: Path traversal attempts in HTTP requests or filenames.
- **`/etc/passwd`**: Arbitrary file read / local file inclusion (LFI) attempts.
- **`UNION SELECT`**: SQL Injection (SQLi) attacks.
- **`<script`**: Cross-Site Scripting (XSS) script tag injection.

---

## 3. Creating Custom Rules

Create a file named `my_signatures.rules`:
```text
# Block common exploit payloads
DROP 0 /bin/sh
DROP 0 ../../
DROP 0 php://input
DROP 0 eval(

# HTTP Method filtering (anchored at payload offset 0)
DROP 0 TRACE 
```

Start the daemon with the custom rules file:
```bash
sudo ./target/debug/abyss-daemon --iface eth0 --signatures my_signatures.rules
```

Inspect active rules with `abyssctl`:
```bash
sudo ./target/debug/abyssctl rules
```

