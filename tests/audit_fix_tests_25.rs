//! Audit fix tests — round 25 (P1 + P1 + P2).
//! F1: Spec/code mismatch on consensus-critical hashes (wtx_id in tx_root, SMT leaf metadata).
//! F2: validate_output_script checks root input type compatibility.
//! F3: validate_output_script rejects scripts that provably exceed the step cap.

#[test]
fn f1_code_ds_wtxid_exists() {
    // DS_WTXID must exist in code (already existed before this round)
    assert_eq!(exfer::types::DS_WTXID, b"EXFER-WTXID");
}

// ── F2 (P1): validate_output_script checks root input type ──

#[test]
fn f2_types_compatible_unit_wildcard() {
    // Unit acts as wildcard — compatible with anything
    use exfer::script::{types_compatible, Type};
    assert!(types_compatible(&Type::Unit, &Type::bytes()));
    assert!(types_compatible(&Type::bytes(), &Type::Unit));
    assert!(types_compatible(&Type::Unit, &Type::Unit));
}

#[test]
fn f2_types_compatible_exact_match() {
    use exfer::script::{types_compatible, Type};
    let expected = Type::Product(
        Box::new(Type::bytes()),
        Box::new(Type::Product(
            Box::new(Type::option(Type::bytes())),
            Box::new(Type::Product(
                Box::new(Type::option(Type::bytes())),
                Box::new(Type::Unit),
            )),
        )),
    );
    // Exact match is compatible
    assert!(types_compatible(&expected, &expected));
}

#[test]
fn f2_types_compatible_sum_vs_product_rejected() {
    use exfer::script::{types_compatible, Type};
    let product = Type::Product(Box::new(Type::bytes()), Box::new(Type::bytes()));
    let sum = Type::Sum(Box::new(Type::bytes()), Box::new(Type::bytes()));
    // Sum ≠ Product — must be rejected
    assert!(!types_compatible(&product, &sum));
    assert!(!types_compatible(&sum, &product));
}

// ── F3 (P2): validate_output_script rejects provably over-cap scripts ──
