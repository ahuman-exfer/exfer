#!/usr/bin/env python3
"""
Regenerate ASSUME_VALID_* constants for a new checkpoint height.

Per upstream release procedure (src/types/mod.rs):
  - ≥2 independent reference nodes must agree byte-exact on every value.
  - ASSUME_VALID_HASH = block_id at the checkpoint height.
  - ASSUME_VALID_CUMULATIVE_WORK = Σ work_from_target(target_i) × window_blocks_i
    across all retarget windows in [0, checkpoint_height].

Usage:
    python3 tools/regen_assume_valid.py <target_height>

Emits Rust source ready to paste into src/types/mod.rs + the fixture
file tests/assume_valid_cumulative_work_guard.rs.
"""

import json
import sys
import time
import urllib.request

S2 = "http://82.221.100.201:9334/"
S3 = "http://89.127.232.155:9334/"
RETARGET_WINDOW = 4_320
PER_REQUEST_DELAY_S = 0.15
MAX_RETRIES = 5


def rpc(url, method, params=None, timeout=15):
    body = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": 1,
    }).encode()
    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            if "error" in data:
                raise RuntimeError(f"{url} {method}: {data['error']}")
            time.sleep(PER_REQUEST_DELAY_S)
            return data["result"]
        except (ConnectionResetError, urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = e
            wait = 1.0 * (2 ** attempt)
            print(f"# retry {attempt + 1}/{MAX_RETRIES} on {url}: {e}; sleeping {wait}s", file=sys.stderr)
            time.sleep(wait)
    raise RuntimeError(f"{url} {method}: gave up after {MAX_RETRIES} retries; last={last_err}")


def get_block_at(url, height):
    return rpc(url, "get_block", {"height": height})


def hex_to_bytes(s):
    s = s.removeprefix("0x")
    return bytes.fromhex(s)


def bytes_to_int_be(b):
    return int.from_bytes(b, "big")


def int_to_bytes_be_32(n):
    """Saturate at 2^256 - 1; truncate to 32 BE bytes."""
    max_v = (1 << 256) - 1
    if n > max_v:
        n = max_v
    return n.to_bytes(32, "big")


def work_from_target(target_be_bytes):
    """Mirrors src/consensus/difficulty.rs::work_from_target.

    Returns 32-byte BE = floor(2^256 / target). target == 0 → all-FF.
    """
    if target_be_bytes == b"\x00" * 32:
        return b"\xff" * 32
    target_int = bytes_to_int_be(target_be_bytes)
    # floor(2^256 / target) where target > 0
    work = (1 << 256) // target_int
    return int_to_bytes_be_32(work)


def add_work_be(a_bytes, b_bytes):
    """Saturating add of two 32-byte BE values."""
    return int_to_bytes_be_32(bytes_to_int_be(a_bytes) + bytes_to_int_be(b_bytes))


def collect_retarget_boundaries(target_height):
    """Heights = [0, RETARGET_WINDOW, 2*RETARGET_WINDOW, ..., last_full_window].

    Includes only the retarget-window-start heights ≤ target_height. The
    terminal partial window (last_full_window..=target_height, when
    target_height is not a multiple of RETARGET_WINDOW) is handled by the
    recomputation loop's last-segment branch in
    `tests/assume_valid_cumulative_work_guard.rs`, NOT as a separate
    fixture entry. Appending a tuple at `target_height` here would
    double-count the checkpoint block during cumulative-work recomputation
    and would also fail the in-tree fixture's "last entry = floor()
    boundary" guard.

    See `fixture_height_list_matches_canonical_boundary_formula` in the
    Rust guard for the assertion that pins this contract.
    """
    return list(range(0, target_height + 1, RETARGET_WINDOW))


def fetch_target(height):
    """Get difficulty_target at `height` from both S2 and S3; require byte-exact match."""
    b2 = get_block_at(S2, height)
    b3 = get_block_at(S3, height)
    t2 = b2["difficulty_target"]
    t3 = b3["difficulty_target"]
    if t2 != t3:
        raise RuntimeError(
            f"NODE DISAGREEMENT at height {height}: S2={t2} S3={t3}"
        )
    return t2, b2  # also return full S2 block for caller convenience


def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    target_height = int(sys.argv[1])

    # 1. Tip check
    h2 = rpc(S2, "get_block_height")["height"]
    h3 = rpc(S3, "get_block_height")["height"]
    print(f"# S2 tip: {h2}", file=sys.stderr)
    print(f"# S3 tip: {h3}", file=sys.stderr)
    if h2 < target_height or h3 < target_height:
        raise RuntimeError(
            f"both reference nodes must be past target_height={target_height}; "
            f"got S2={h2}, S3={h3}"
        )

    # 2. Walk retarget boundaries, build fixture entries, compute cumulative work
    heights = collect_retarget_boundaries(target_height)
    print(f"# Walking {len(heights)} retarget boundaries...", file=sys.stderr)

    fixture_entries = []  # list of (height, hex_target)
    targets_at = {}       # height -> raw bytes
    for h in heights:
        target_hex, _ = fetch_target(h)
        targets_at[h] = hex_to_bytes(target_hex)
        fixture_entries.append((h, target_hex))
        if h % (RETARGET_WINDOW * 10) == 0 or h == target_height:
            print(f"#   height {h:>7}: target {target_hex}", file=sys.stderr)

    # 3. Get block_id at the checkpoint height — must match across nodes
    cp2 = get_block_at(S2, target_height)
    cp3 = get_block_at(S3, target_height)
    if cp2["hash"] != cp3["hash"]:
        raise RuntimeError(
            f"NODE DISAGREEMENT on checkpoint hash at {target_height}: "
            f"S2={cp2['hash']} S3={cp3['hash']}"
        )
    checkpoint_hash = cp2["hash"]
    print(f"# Checkpoint hash @ {target_height}: {checkpoint_hash}", file=sys.stderr)

    # 4. Cumulative work = Σ work_from_target(target_i) × blocks_in_window_i
    #    Window i covers heights [boundary_i, boundary_{i+1}) (the last window
    #    runs through the checkpoint height itself, inclusive). Same convention
    #    as the existing fixture (heights 0..=ASSUME_VALID_HEIGHT inclusive).
    cumulative = b"\x00" * 32
    for i, (h, _) in enumerate(fixture_entries):
        if i + 1 < len(fixture_entries):
            next_h = fixture_entries[i + 1][0]
            blocks_in_window = next_h - h
        else:
            # Final entry: include the checkpoint block itself.
            blocks_in_window = target_height - h + 1
        per_block_work = work_from_target(targets_at[h])
        for _ in range(blocks_in_window):
            cumulative = add_work_be(cumulative, per_block_work)
    cumulative_decimal = bytes_to_int_be(cumulative)

    # 5. Emit Rust source
    print()
    print(f"// === src/types/mod.rs ===")
    print(f"pub const ASSUME_VALID_HEIGHT: u64 = {target_height:_};")
    print(f"pub const ASSUME_VALID_HASH: [u8; 32] = [")
    cp_bytes = hex_to_bytes(checkpoint_hash)
    for row in range(0, 32, 8):
        line = "    " + ", ".join(f"0x{b:02x}" for b in cp_bytes[row:row + 8]) + ","
        print(line)
    print(f"];")
    print(f"// Cumulative work decimal: {cumulative_decimal:,}")
    print(f"pub const ASSUME_VALID_CUMULATIVE_WORK: [u8; 32] = [")
    for row in range(0, 32, 8):
        line = "    " + ", ".join(f"0x{b:02x}" for b in cumulative[row:row + 8]) + ","
        print(line)
    print(f"];")
    print()
    print(f"// === tests/assume_valid_cumulative_work_guard.rs RETARGET_BOUNDARY_TARGETS ===")
    print(f"const RETARGET_BOUNDARY_TARGETS: &[(u64, &str)] = &[")
    for h, t in fixture_entries:
        print(f'    ({h}, "{t}"),')
    print(f"];")


if __name__ == "__main__":
    main()
