//! Audit fix tests — round 17 (findings F1–F4).

// ── F1: Global block limiter — bounds aggregate expensive checks ──

#[test]
fn f2_schnorr_verify_not_implemented() {
    use exfer::script::jets::JetId;
    assert!(
        !JetId::SchnorrVerify.is_implemented(),
        "SchnorrVerify must report is_implemented() == false"
    );
}

#[test]
fn f2_sha256_is_implemented() {
    use exfer::script::jets::JetId;
    assert!(JetId::Sha256.is_implemented());
}

#[test]
fn f2_ed25519_verify_is_implemented() {
    use exfer::script::jets::JetId;
    assert!(JetId::Ed25519Verify.is_implemented());
}

#[test]
fn f2_arithmetic_jets_implemented() {
    use exfer::script::jets::JetId;
    assert!(JetId::Add64.is_implemented());
    assert!(JetId::Sub64.is_implemented());
    assert!(JetId::Mul64.is_implemented());
    assert!(JetId::Add256.is_implemented());
}

#[test]
fn f2_byte_jets_implemented() {
    use exfer::script::jets::JetId;
    assert!(JetId::Cat.is_implemented());
    assert!(JetId::Slice.is_implemented());
    assert!(JetId::Len.is_implemented());
}

#[test]
fn f2_merkle_verify_is_implemented() {
    use exfer::script::jets::JetId;
    assert!(JetId::MerkleVerify.is_implemented());
}
