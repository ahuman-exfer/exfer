//! v1.5.0 Fix 2 release-hardening guard.
//!
//! `ASSUME_VALID_CUMULATIVE_WORK` is the hardcoded cumulative work at
//! `ASSUME_VALID_HEIGHT` on the canonical chain. Cold-bootstrap tip validation
//! (path 2b) uses it as the anchor's cumulative work when the node has not yet
//! reached the checkpoint via normal block-by-block validation. A wrong constant
//! would quietly skew IBD `is_better_chain` decisions for every fresh-node
//! bootstrap on this release.
//!
//! This test is the runnable version of the build-time consistency check the
//! v1.5.0 spec calls for. It fails until the constant is populated from a real
//! canonical-node snapshot. Do NOT suppress this test by setting the constant
//! to an arbitrary non-zero value — the constant must equal
//! `get_cumulative_work(get_block_id_by_height(ASSUME_VALID_HEIGHT))` on a
//! trusted canonical node, computed at release-build time.
//!
//! Release procedure (documented in `src/types/mod.rs`):
//!   1. On a canonical node at or past `ASSUME_VALID_HEIGHT`:
//!      - `get_block_id_by_height(ASSUME_VALID_HEIGHT)` → verify equals `ASSUME_VALID_HASH`
//!      - `get_cumulative_work(<that block_id>)` → record the 32-byte value
//!   2. Update `ASSUME_VALID_CUMULATIVE_WORK` in `src/types/mod.rs` to that value.
//!   3. Re-run this test; it must pass.
//!
//! Complementary runtime guard: `process_block` also compares the hardcoded
//! constant against the computed cumulative work when the node reaches the
//! checkpoint organically, and flips `assume_valid_cumulative_work_trusted`
//! to `false` on mismatch (see `src/network/sync.rs`). This test is the
//! build-time counterpart.

use exfer::types::{ASSUME_VALID_CUMULATIVE_WORK, ASSUME_VALID_HASH, ASSUME_VALID_HEIGHT};

#[test]
fn assume_valid_cumulative_work_is_not_placeholder_zero() {
    assert_ne!(
        ASSUME_VALID_CUMULATIVE_WORK,
        [0u8; 32],
        "\n\n\
         ASSUME_VALID_CUMULATIVE_WORK is still the zero placeholder.\n\
         \n\
         This is a v1.5.0 release-hardening guard. Before shipping:\n\
         \n\
         1. On a trusted canonical node at or past height {} run:\n\
         \n\
               get_cumulative_work(get_block_id_by_height({}))\n\
         \n\
         2. Verify `get_block_id_by_height({})` equals ASSUME_VALID_HASH:\n\
               {:02x?}\n\
         \n\
         3. Paste the 32-byte cumulative_work value into ASSUME_VALID_CUMULATIVE_WORK\n\
            in `src/types/mod.rs` alongside ASSUME_VALID_HEIGHT and ASSUME_VALID_HASH.\n\
         \n\
         4. Re-run `cargo test --test assume_valid_cumulative_work_guard`.\n\
         \n\
         Failure to populate this constant leaves cold-bootstrap tip validation\n\
         (path 2b) using a zero cumulative_work anchor. The runtime guard in\n\
         process_block will flip `assume_valid_cumulative_work_trusted` to false\n\
         on first encounter, but that just means path 2b falls through to the\n\
         legacy single-header path — i.e., Fix 2 is silently disabled for every\n\
         fresh-node bootstrap. The design intent is that this release ships with\n\
         a correct constant.\n\
         ",
        ASSUME_VALID_HEIGHT,
        ASSUME_VALID_HEIGHT,
        ASSUME_VALID_HEIGHT,
        ASSUME_VALID_HASH
    );
}

#[test]
fn assume_valid_constants_are_internally_consistent() {
    // Sanity: the hash is not all-zero (that would be a separate mistake).
    assert_ne!(
        ASSUME_VALID_HASH, [0u8; 32],
        "ASSUME_VALID_HASH must be non-zero"
    );
    // ASSUME_VALID_HEIGHT must be > 0 (a checkpoint at genesis is pointless).
    assert!(
        ASSUME_VALID_HEIGHT > 0,
        "ASSUME_VALID_HEIGHT must be positive"
    );
}

/// Fixture-based cross-check: recompute ASSUME_VALID_CUMULATIVE_WORK from the
/// sequence of retarget-boundary difficulty targets on the canonical chain
/// (heights 0, 4320, 8640, ..., 129600), assert the result matches the
/// hardcoded constant.
///
/// A typo in the hardcoded constant would pass the non-zero guard above but
/// fail this test. The fixture must be updated alongside the constant whenever
/// the checkpoint height changes.
///
/// The 31 entries below were captured from the canonical chain on 2026-04-18
/// via RPC against a trusted node (S2 = 82.221.100.201). Each entry is the
/// difficulty_target hex at the given retarget-window start height.
#[test]
fn assume_valid_cumulative_work_matches_fixture_recomputation() {
    use exfer::consensus::difficulty::work_from_target;
    use exfer::types::hash::Hash256;
    use exfer::types::RETARGET_WINDOW;

    // (window_start_height, difficulty_target_hex_big_endian)
    // First 30 full retarget windows (4320 blocks each) + partial final window.
    const RETARGET_BOUNDARY_TARGETS: &[(u64, &str)] = &[
        (0, "0100000000000000000000000000000000000000000000000000000000000000"),
        (4320, "0314ef6a58fb086d0000000000000000000000000000000000000000000000f0"),
        (8640, "0450e4953a8ff25e0000000000000000000000000000000000000000000000f0"),
        (12960, "02a988b1b5e19de60000000000000000000000000000000000000000000000f0"),
        (17280, "025c934c1e91c1dc0000000000000000000000000000000000000000000000f0"),
        (21600, "028dae35b87896030000000000000000000000000000000000000000000000f0"),
        (25920, "028724667983f5230000000000000000000000000000000000000000000000f0"),
        (30240, "06131e7ca5e0264c0000000000000000000000000000000000000000000000f0"),
        (34560, "0bdddd7d2077bfe00000000000000000000000000000000000000000000000f0"),
        (38880, "0b437996ec58c4da0000000000000000000000000000000000000000000000f0"),
        (43200, "0ad751d21b60494b0000000000000000000000000000000000000000000000f0"),
        (47520, "0aa7f61018685bac0000000000000000000000000000000000000000000000f0"),
        (51840, "1179c15a1d3d6ddc0000000000000000000000000000000000000000000000f0"),
        (56160, "164161fd102f06070000000000000000000000000000000000000000000000f0"),
        (60480, "4bbd91c5e031d5090000000000000000000000000000000000000000000000f0"),
        (64800, "12ef2afab758bde60000000000000000000000000000000000000000000000f0"),
        (69120, "05dd9f8a8b306a3f0000000000000000000000000000000000000000000000f0"),
        (73440, "05cccbaa8a26a3430000000000000000000000000000000000000000000000f0"),
        (77760, "0452d76329f201e60000000000000000000000000000000000000000000000f0"),
        (82080, "0309c2ff8e1f68e50000000000000000000000000000000000000000000000f0"),
        (86400, "022d8f9b7965bdc30000000000000000000000000000000000000000000000f0"),
        (90720, "02228c965bd2bb7d0000000000000000000000000000000000000000000000f0"),
        (95040, "015dbbb6c39229570000000000000000000000000000000000000000000000f0"),
        (99360, "00cb9ce974b49ce60000000000000000000000000000000000000000000000f0"),
        (103680, "00f3b2f75ccd86860000000000000000000000000000000000000000000000f0"),
        (108000, "00a2ed46c6c1d55f0000000000000000000000000000000000000000000000f0"),
        (112320, "00691bbf190a82090000000000000000000000000000000000000000000000f0"),
        (116640, "00465632ab9d16530000000000000000000000000000000000000000000000f0"),
        (120960, "0037095c29feb5bf0000000000000000000000000000000000000000000000f0"),
        (125280, "0025828e61d422d10000000000000000000000000000000000000000000000f0"),
        (129600, "001a8599d12f7f993764041a52adcd4a78594be7392ff8e5e3ab1e98e46349f3"),
    ];

    // 256-bit accumulator via saturating u8 arithmetic.
    fn add_big(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry: u16 = 0;
        for i in (0..32).rev() {
            let s = a[i] as u16 + b[i] as u16 + carry;
            out[i] = (s & 0xff) as u8;
            carry = s >> 8;
        }
        out
    }

    fn scale_big(b: &[u8; 32], k: u64) -> [u8; 32] {
        // Compute k * b as big-endian u256 by repeated add. For k ≤ 4320 this is
        // fine; for bigger k we'd want proper multiplication.
        let mut out = [0u8; 32];
        for _ in 0..k {
            out = add_big(&out, b);
        }
        out
    }

    let mut expected_acc = [0u8; 32];
    for (i, (start, target_hex)) in RETARGET_BOUNDARY_TARGETS.iter().enumerate() {
        // Determine block count in this retarget-window segment, clamped to checkpoint height.
        let next_start = if i + 1 < RETARGET_BOUNDARY_TARGETS.len() {
            RETARGET_BOUNDARY_TARGETS[i + 1].0
        } else {
            // Terminal segment: runs from `start` through checkpoint inclusive.
            ASSUME_VALID_HEIGHT + 1
        };
        let count = (next_start.min(ASSUME_VALID_HEIGHT + 1)) - start;

        let target_bytes = hex_decode_32(target_hex);
        let target = Hash256(target_bytes);
        let per_block_work = work_from_target(&target);
        let segment_work = scale_big(&per_block_work, count);
        expected_acc = add_big(&expected_acc, &segment_work);
    }

    // Also sanity-check the final retarget-window start maps to the correct
    // checkpoint height alignment. `ASSUME_VALID_HEIGHT / RETARGET_WINDOW = 30`
    // whole windows at the time of this fixture; terminal window starts at 129600.
    let expected_terminal_start = (ASSUME_VALID_HEIGHT / RETARGET_WINDOW) * RETARGET_WINDOW;
    assert_eq!(
        RETARGET_BOUNDARY_TARGETS.last().unwrap().0,
        expected_terminal_start,
        "fixture terminal window start must align with ASSUME_VALID_HEIGHT / RETARGET_WINDOW"
    );

    assert_eq!(
        expected_acc, ASSUME_VALID_CUMULATIVE_WORK,
        "\n\n\
         Hardcoded ASSUME_VALID_CUMULATIVE_WORK does NOT match the value \
         recomputed from the retarget-boundary fixture.\n\n\
         expected (from fixture): {:02x?}\n\
         hardcoded:               {:02x?}\n\n\
         Either the constant or the fixture is wrong. If you changed ASSUME_VALID_HEIGHT \
         or the canonical chain replayed, regenerate both together from a trusted \
         canonical node (see src/types/mod.rs and the release procedure in \
         docs/v1.5.0-brief.md).\n\n",
        expected_acc, ASSUME_VALID_CUMULATIVE_WORK
    );
}

fn hex_decode_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "target hex must be 64 chars");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .unwrap_or_else(|_| panic!("bad hex at char {}: {:?}", 2 * i, &s[2 * i..2 * i + 2]));
    }
    out
}
