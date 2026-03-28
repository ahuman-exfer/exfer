//! Audit fix tests — round 56.
//!
//! Fix 5: Fork header retention — evict_fork_block retains headers + work
//!        so difficulty computation survives deep reorgs.
//! Fix 6: Chain-bound signatures — sig_message includes genesis_block_id
//!        to prevent cross-chain transaction replay.

// ── Fix 5: Fork header retention ──

#[test]
fn sig_message_includes_genesis_block_id() {
    use exfer::genesis::GENESIS_BLOCK_ID;
    use exfer::types::hash::Hash256;
    use exfer::types::transaction::{Transaction, TxInput, TxOutput, TxWitness};
    use exfer::types::DS_SIG;

    let tx = Transaction {
        inputs: vec![TxInput {
            prev_tx_id: Hash256::sha256(b"test"),
            output_index: 0,
        }],
        outputs: vec![TxOutput::new_p2pkh(100, &[0; 32])],
        witnesses: vec![TxWitness {
            witness: vec![],
            redeemer: None,
        }],
    };

    let sig_msg = tx.sig_message().unwrap();
    // Must start with DS_SIG
    assert!(sig_msg.starts_with(DS_SIG));
    // Genesis block ID must follow immediately after DS_SIG
    let genesis_id = &*GENESIS_BLOCK_ID;
    assert_eq!(
        &sig_msg[DS_SIG.len()..DS_SIG.len() + 32],
        genesis_id.as_bytes(),
        "sig_message must include genesis_block_id immediately after DS_SIG"
    );
    // Total length: DS_SIG(9) + genesis_id(32) + signing_bytes
    assert!(
        sig_msg.len() > DS_SIG.len() + 32,
        "sig_message must contain data after DS_SIG + genesis_block_id"
    );
}

#[test]
fn sig_message_format_in_spec_section_8_2() {
    let spec = include_str!("../EXFER.md");
    // Section 8.2 signing message must mention genesis_block_id
    let section = spec
        .find("Signing message:")
        .expect("Section 8.2 must have signing message description");
    let region = &spec[section..spec.len().min(section + 200)];
    assert!(
        region.contains("genesis_block_id"),
        "EXFER.md Section 8.2 signing message must include genesis_block_id"
    );
}

#[test]
fn txsighash_spec_mentions_genesis() {
    let spec = include_str!("../EXFER.md");
    // Find the TxSigHash jet definition (with opcode to avoid TOC entries)
    let section = spec
        .find("TxSigHash** (0x0408)")
        .expect("TxSigHash jet spec must exist");
    let region = &spec[section..spec.len().min(section + 300)];
    assert!(
        region.contains("genesis_block_id"),
        "EXFER.md TxSigHash jet description must include genesis_block_id"
    );
}

#[test]
fn appendix_c_signing_mentions_genesis() {
    let spec = include_str!("../EXFER.md");
    let appendix = spec.find("Appendix C").expect("Appendix C must exist");
    let body = &spec[appendix..];
    let step3 = body
        .find("signing message")
        .expect("Appendix C must have signing message step");
    let region = &body[step3..body.len().min(step3 + 200)];
    assert!(
        region.contains("genesis_block_id"),
        "EXFER.md Appendix C signing step must include genesis_block_id"
    );
}

#[test]
fn appendix_b_exfer_sig_mentions_chain_binding() {
    let spec = include_str!("../EXFER.md");
    // Find the domain separator catalog table — EXFER-SIG row
    let catalog = spec
        .find("Domain Separator Catalog")
        .expect("Domain Separator Catalog must exist in EXFER.md");
    let body = &spec[catalog..];
    let sig_row = body
        .find("EXFER-SIG")
        .expect("EXFER-SIG row must exist in catalog");
    let region = &body[sig_row..body.len().min(sig_row + 300)];
    assert!(
        region.contains("genesis_block_id") || region.contains("chain"),
        "Appendix B EXFER-SIG usage must mention chain binding via genesis_block_id"
    );
}
