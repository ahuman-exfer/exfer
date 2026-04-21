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
/// (heights 0, 4320, 8640, ..., 302400), assert the result matches the
/// hardcoded constant.
///
/// A typo in the hardcoded constant would pass the non-zero guard above but
/// fail this test. The fixture must be regenerated alongside the constant
/// whenever the checkpoint height changes, per the v1.7.0 multi-source
/// ceremony (see docs/v1.7.0-brief.md Change 1).
///
/// The 71 entries below were captured from the canonical chain on 2026-04-19
/// via RPC against TWO independent canonical nodes (S2 = 82.221.100.201 and
/// S3 = 89.127.232.155), requiring byte-exact agreement on each entry. Each
/// entry is the `difficulty_target` hex at the given retarget-window start
/// height.
#[test]
fn assume_valid_cumulative_work_matches_fixture_recomputation() {
    use exfer::consensus::difficulty::work_from_target;
    use exfer::types::hash::Hash256;
    use exfer::types::RETARGET_WINDOW;

    // (window_start_height, difficulty_target_hex_big_endian)
    // 70 full retarget windows (4320 blocks each) + terminal checkpoint window.
    const RETARGET_BOUNDARY_TARGETS: &[(u64, &str)] = &[
        (0, "0100000000000000000000000000000000000000000000000000000000000000"),
        (4320, "0314ef6a58fb086db9e454d4dc72b47f820e88a2d5b0e1e6b3c96be38065aa3e"),
        (8640, "0450e4953a8ff25ec0aac7cbc222d786acf922da4182accff5267e68cf2939a5"),
        (12960, "02a988b1b5e19de69954105f1810aab34d51df3bd93b6d2828ea68049b31068e"),
        (17280, "025c934c1e91c1dc643fd03d1efac32b1e0b2dc28ba2a0392ebd4731e1612644"),
        (21600, "028dae35b87896038317e3c8bde4b9dd73774fc0d97b272657d791e05a7d09f5"),
        (25920, "028724667983f523da133aa3f6e038b006a8d80dd32510dfe621a380d051a82f"),
        (30240, "06131e7ca5e0264c0dcd1e8fdc22186f459f2160713a3cd87f6a3d73ecf1b355"),
        (34560, "0bdddd7d2077bfe0428df75c1f2c7ecd647077e8bb84bb7f71b2d9042eb4a5eb"),
        (38880, "0b437996ec58c4da951e319711cb4eed18d46081e412f825e566743046c48a29"),
        (43200, "0ad751d21b60494b89a81d97af9f684c58af02f86cdb4fcf9883638f9d335baa"),
        (47520, "0aa7f61018685bacf1b5691c6f85754b93bc4720094515080207d3b221c8f53f"),
        (51840, "1179c15a1d3d6ddc6fe205ffbf9a9d54596a6924c586a164db522041877be2ec"),
        (56160, "164161fd102f060791dce2097bc0463baff458b33d2dc0da51622848bc593bc8"),
        (60480, "4bbd91c5e031d509e984d6461d3ae03fe2e3b575fe031afce555efbedc46ab55"),
        (64800, "12ef2afab758bde632e40e47a4dad01e62d24386799e0403a0c33ae26d470c38"),
        (69120, "05dd9f8a8b306a3f7d7adeaabba2cd301e608d994544cf0a12fb38b5d0e2f9e2"),
        (73440, "05cccbaa8a26a34370017d2223bd128fbb6810d1a7011538cf847aec3ae593d2"),
        (77760, "0452d76329f201e6f88ee40b333d572e57c773f2018998f126ac4da4f7607d7c"),
        (82080, "0309c2ff8e1f68e5fee3e443c8878400cfdc336d7bae3c0ec6505ac37841e03b"),
        (86400, "022d8f9b7965bdc324d1acbe16c1624810b69910efe4a200ccbc503164a0088b"),
        (90720, "02228c965bd2bb7d89c9595a95c7490d563e08bf88f09cee383b62c617fbc4cd"),
        (95040, "015dbbb6c3922957a3b343f56d6d79084a89dcf8e27036fdf53d63c52cd7527a"),
        (99360, "00cb9ce974b49ce669b537017dad98d302152b0771fd769d28adfeb94cb21cc8"),
        (103680, "00f3b2f75ccd8686e531126314bfd8db679e4bf3546b75eb3bbb231a70b66d67"),
        (108000, "00a2ed46c6c1d55ffe7750f5e5d5514ae7b661a986a6717b09700ad0541167d8"),
        (112320, "00691bbf190a82098666da456adb809a94f9588a0c3f626f96d3c1b2afd6c2a9"),
        (116640, "00465632ab9d1653ff740534fc1ca6417c31bc098a101f50c144318aa2e7ce31"),
        (120960, "0037095c29feb5bf0774989cc6566ea62baf4d93c36db45507d8271edc77ea55"),
        (125280, "0025828e61d422d119759407517080918b82de9537768c36655e570cbf3a9f90"),
        (129600, "001a8599d12f7f993764041a52adcd4a78594be7392ff8e5e3ab1e98e46349f3"),
        (133920, "0010b6989b1c505af36f0b465f49b944b0182b6d89179c1e66b21a32d68d7913"),
        (138240, "000a4d4b9b88b5af790ae78f0ce4a1bf2f5c9ad87e5c7923101582fbed328960"),
        (142560, "0007e52c5ee57b6a16593492f91b55412386cec01d81ba4f8182597a3d93f86d"),
        (146880, "0006b6a10be02cde1e8fb8526a40e181918637e4ad45bc9f2e7e65a16866f8ab"),
        (151200, "00068c7d326701e29e7e62acee663b7d42669cd6fdaa68bb2adbbc249325094b"),
        (155520, "0006ab76f681f8a0457a54bb6977f88b06784672e74ce229177c4c9b15d26810"),
        (159840, "000608be5be75a803c3381aec78f63e2c3f724ee8ce1506215a98b97579f274b"),
        (164160, "0005d810d4ce220f73b7488468f77a415689608a66bcf4ef49b57b0c1fd13269"),
        (168480, "00062662897a684dc02f1eb6fd85e29da1e4617ca6f368fca4fd42618678dc37"),
        (172800, "0005fbcef01ea66615760740f5ee916f95009e58015b0d30d918fa7439e4eb13"),
        (177120, "0005f70535222b7addad67d895da2c652091afed55d0bff24f7f9737ff4524c8"),
        (181440, "0005fbb901248e9c8fc6a0781f26bb8290bc9f6a7f7240e9392c0c112060b300"),
        (185760, "000486d8a4abe17b034e29938e7b3d49a3312f2b503d6127f1553036c7c11181"),
        (190080, "00042052dad600de62391c5df72be3561ba158891c2baafdda1763294aba0ee4"),
        (194400, "00033240de6f379e73fd0edf75b7a9366e86a1c8589630e1173be150b23ba633"),
        (198720, "00035051de82d251f98f7600cd7227a44d7e7dd23d17482df6d45df70915cbd2"),
        (203040, "00037b1e69d4f58d9d231c4bc09069624b18df3357b14dc56d01f828137ed4bb"),
        (207360, "0003787f9bd4e25c966f0355f92db357d6c8c637f68a8ba186467a2a4e3693e3"),
        (211680, "0003832255c4e8e3738b5ed0f1dd9540587451aa82194c1a23eb32e3480351d9"),
        (216000, "00036cc13104daacd4a1e484705214cbe70e7f49f2530d2fb790149b6a95a42f"),
        (220320, "00036b3b6eb9d5f7ecfae06a7bfaed0c27f1d0459484dfd96bf00f5af42df33c"),
        (224640, "000376f7258843002fd26fe6c2d055e3eca96ac2de1e25458120e997432b11ab"),
        (228960, "000386539cfd323fb1f2c50f054d3755ba77689461d0ff11ca0ac1d8735bd376"),
        (233280, "00035b84d382da8183510c79ab541f0ba15989586f80c70f2638fd52a6ab5edc"),
        (237600, "0002b916808e23a53326c3557b6ef5bebf99db04972c9c76566e72aaece896c9"),
        (241920, "00038f5ce9884a5d9adc05692ac210011049032279f08d899b54fea36f0f4b35"),
        (246240, "000341ab0b3adddff4cde93bc5b11a819865f8e8da17e027687fb43c8b4402e8"),
        (250560, "00038b2202a41b615eda57ae10f391076702b0b7f36ad0e980ba2fb32662cdf2"),
        (254880, "0002cc719e6c9d8cac8ad637f21640b62456b9a022df661898297ea132f01951"),
        (259200, "0002851d578715995760bdb0afb91ccf654cba3b048cd13b8c09264584860ad2"),
        (263520, "00027b2ab3367d04712d72b3766025724de0b5efaf3ecfe11444542cd4d273e6"),
        (267840, "000264411b235870deb5952c7f253be95cac2c737ad238ea8130da45cac92d7c"),
        (272160, "000230c0e61c98bd5861aeac526d7dc7bff73a8d9d423d8163e6d4b106b1b31e"),
        (276480, "0001d63f03ff316e8636a0767ce33bf084223af8b20e6851c1a0bb196a2b9871"),
        (280800, "00017b1241be386b96923ee4ed189efe14a9e5662488a806101543793121dfd9"),
        (285120, "000135ed6cf5495be94b87b85c16d53c162871342e0a22c932ab542c9a362dc3"),
        (289440, "0001128758600bb62bf3575d1b1967cfaee3069c6710af0622f42ab67978c111"),
        (293760, "0001090b8af9e565625fc62049bc4f9c2619dbc3eaaec7f7368703f45ed2a620"),
        (298080, "0000ee9d3d982429e7d226ae0fcf9152dcfcd8138680dd6eca11443ba361cb0b"),
        (302400, "0000db6358852f4c2ad9d10e2a8382c4ecf7a52d46e9b55d1714e9db3266e4f1"),
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
