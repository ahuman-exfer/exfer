//! Arithmetic jet implementations: 64-bit and 256-bit operations.
//!
//! All operations use checked arithmetic. Overflow/underflow/division-by-zero
//! returns JetError (mapped to script returns false).

use super::JetError;
use crate::script::value::Value;

// ============================================================
// 64-bit arithmetic
// ============================================================

/// Extract (u64, u64) from a Pair input.
fn extract_u64_pair(input: &Value) -> Result<(u64, u64), JetError> {
    match input {
        Value::Pair(a, b) => match (a.as_ref(), b.as_ref()) {
            (Value::U64(x), Value::U64(y)) => Ok((*x, *y)),
            _ => Err(JetError::TypeMismatch(
                "expected Pair(U64, U64)".to_string(),
            )),
        },
        _ => Err(JetError::TypeMismatch("expected Pair".to_string())),
    }
}

pub fn jet_add64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    let result = a
        .checked_add(b)
        .ok_or(JetError::Overflow("add64 overflow".to_string()))?;
    Ok(Value::U64(result))
}

pub fn jet_sub64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    let result = a
        .checked_sub(b)
        .ok_or(JetError::Overflow("sub64 underflow".to_string()))?;
    Ok(Value::U64(result))
}

pub fn jet_mul64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    let result = a
        .checked_mul(b)
        .ok_or(JetError::Overflow("mul64 overflow".to_string()))?;
    Ok(Value::U64(result))
}

pub fn jet_div64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    if b == 0 {
        return Err(JetError::DivisionByZero);
    }
    Ok(Value::U64(a / b))
}

pub fn jet_mod64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    if b == 0 {
        return Err(JetError::DivisionByZero);
    }
    Ok(Value::U64(a % b))
}

pub fn jet_eq64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    Ok(Value::Bool(a == b))
}

pub fn jet_lt64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    Ok(Value::Bool(a < b))
}

pub fn jet_gt64(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u64_pair(input)?;
    Ok(Value::Bool(a > b))
}

// ============================================================
// 256-bit arithmetic (big-endian [u8; 32])
// ============================================================

/// Extract (U256, U256) pair — each is a Pair(U64(hi), U64(lo)) or U256([u8;32]).
/// U256 is stored as Product(Bound(u64::MAX), Bound(u64::MAX)) in types
/// but at runtime as Value::U256([u8; 32]).
fn extract_u256_pair(input: &Value) -> Result<([u8; 32], [u8; 32]), JetError> {
    match input {
        Value::Pair(a, b) => {
            let x = extract_u256(a)?;
            let y = extract_u256(b)?;
            Ok((x, y))
        }
        _ => Err(JetError::TypeMismatch("expected Pair".to_string())),
    }
}

fn extract_u256(v: &Value) -> Result<[u8; 32], JetError> {
    v.as_u256()
        .ok_or_else(|| JetError::TypeMismatch("expected U256 or Pair(U64, U64)".to_string()))
}

/// Convert big-endian [u8; 32] to two u128s (hi, lo).
fn u256_to_parts(data: &[u8; 32]) -> (u128, u128) {
    let hi = u128::from_be_bytes(data[..16].try_into().unwrap());
    let lo = u128::from_be_bytes(data[16..].try_into().unwrap());
    (hi, lo)
}

/// Convert (hi, lo) u128 parts back to big-endian [u8; 32].
fn parts_to_u256(hi: u128, lo: u128) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&hi.to_be_bytes());
    result[16..].copy_from_slice(&lo.to_be_bytes());
    result
}

pub fn jet_add256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    let (ah, al) = u256_to_parts(&a);
    let (bh, bl) = u256_to_parts(&b);

    let (lo, carry) = al.overflowing_add(bl);
    let hi = ah
        .checked_add(bh)
        .and_then(|h| h.checked_add(if carry { 1 } else { 0 }))
        .ok_or(JetError::Overflow("add256 overflow".to_string()))?;

    Ok(Value::U256(parts_to_u256(hi, lo)))
}

pub fn jet_sub256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    let (ah, al) = u256_to_parts(&a);
    let (bh, bl) = u256_to_parts(&b);

    let (lo, borrow) = al.overflowing_sub(bl);
    let hi = ah
        .checked_sub(bh)
        .and_then(|h| h.checked_sub(if borrow { 1 } else { 0 }))
        .ok_or(JetError::Overflow("sub256 underflow".to_string()))?;

    Ok(Value::U256(parts_to_u256(hi, lo)))
}

pub fn jet_mul256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    // Simple approach: treat as big-endian integers and multiply
    // Use grade-school multiplication with u128 limbs
    let (ah, al) = u256_to_parts(&a);
    let (bh, bl) = u256_to_parts(&b);

    // If either hi limb is nonzero AND the other value is > 0, check for overflow
    // (a_hi * b) or (b_hi * a) would overflow 256 bits
    if ah > 0 && (bh > 0 || bl > 0) {
        // ah * bh would be >= 2^256, definitely overflow
        if bh > 0 {
            return Err(JetError::Overflow("mul256 overflow".to_string()));
        }
        // ah * bl: need this to fit in the upper 128 bits
        // ah * bl could be up to 128+128 = 256 bits — only ok if result fits in upper half
        let cross = ah.checked_mul(bl);
        if cross.is_none() {
            return Err(JetError::Overflow("mul256 overflow".to_string()));
        }
    }
    if bh > 0 && al > 0 {
        // Same check for bh * al
        let cross = bh.checked_mul(al);
        if cross.is_none() {
            return Err(JetError::Overflow("mul256 overflow".to_string()));
        }
    }

    // Full multiplication: result = ah*bh*2^256 + (ah*bl + bh*al)*2^128 + al*bl
    // ah*bh must be 0 (checked above)
    let lo_full = al.checked_mul(bl);
    // For u128 * u128, we need wider arithmetic. Simplify: split into 64-bit limbs.
    let result = mul_u256_full(&a, &b)?;
    let _ = lo_full; // suppress warning

    Ok(Value::U256(result))
}

/// Full 256-bit multiplication using 64-bit limbs.
fn mul_u256_full(a: &[u8; 32], b: &[u8; 32]) -> Result<[u8; 32], JetError> {
    // Split each into four 64-bit limbs (big-endian)
    let a_limbs = [
        u64::from_be_bytes(a[0..8].try_into().unwrap()),
        u64::from_be_bytes(a[8..16].try_into().unwrap()),
        u64::from_be_bytes(a[16..24].try_into().unwrap()),
        u64::from_be_bytes(a[24..32].try_into().unwrap()),
    ];
    let b_limbs = [
        u64::from_be_bytes(b[0..8].try_into().unwrap()),
        u64::from_be_bytes(b[8..16].try_into().unwrap()),
        u64::from_be_bytes(b[16..24].try_into().unwrap()),
        u64::from_be_bytes(b[24..32].try_into().unwrap()),
    ];

    // Result in 8 limbs (512 bits), but we only keep the lower 4 (256 bits)
    // and check for overflow in the upper 4.
    // Each limb stores a 64-bit value; carries are propagated immediately
    // to prevent u128 overflow from accumulating multiple products.
    let mut result = [0u64; 8];

    for i in 0..4 {
        for j in 0..4 {
            let prod = (a_limbs[3 - i] as u128) * (b_limbs[3 - j] as u128);
            let pos = i + j;
            // Add product to accumulator with carry propagation
            let mut carry = prod;
            let mut k = pos;
            while carry != 0 && k < 8 {
                let sum = result[k] as u128 + (carry & 0xFFFF_FFFF_FFFF_FFFF);
                result[k] = sum as u64;
                carry = (carry >> 64) + (sum >> 64);
                k += 1;
            }
        }
    }

    // Check overflow: upper 4 limbs must be zero
    if result[4] != 0 || result[5] != 0 || result[6] != 0 || result[7] != 0 {
        return Err(JetError::Overflow("mul256 overflow".to_string()));
    }

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&result[3].to_be_bytes());
    out[8..16].copy_from_slice(&result[2].to_be_bytes());
    out[16..24].copy_from_slice(&result[1].to_be_bytes());
    out[24..32].copy_from_slice(&result[0].to_be_bytes());

    Ok(out)
}

pub fn jet_div256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    if b == [0u8; 32] {
        return Err(JetError::DivisionByZero);
    }
    let result = div_u256(&a, &b);
    Ok(Value::U256(result))
}

pub fn jet_mod256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    if b == [0u8; 32] {
        return Err(JetError::DivisionByZero);
    }
    let result = mod_u256(&a, &b);
    Ok(Value::U256(result))
}

/// Simple 256-bit division via repeated subtraction with bit shifting.
fn div_u256(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if cmp_u256(a, b) < 0 {
        return [0u8; 32];
    }

    // Use long division approach
    let mut quotient = [0u8; 32];
    let mut remainder = [0u8; 32];

    for bit in 0..256 {
        // Shift remainder left by 1
        shift_left_1(&mut remainder);
        // Set lowest bit of remainder to bit (255-bit) of a
        let byte_idx = bit / 8;
        let bit_idx = 7 - (bit % 8);
        if (a[byte_idx] >> bit_idx) & 1 == 1 {
            remainder[31] |= 1;
        }
        // If remainder >= b, subtract
        if cmp_u256(&remainder, b) >= 0 {
            remainder = sub_u256_unchecked(&remainder, b);
            let q_byte = bit / 8;
            let q_bit = 7 - (bit % 8);
            quotient[q_byte] |= 1 << q_bit;
        }
    }

    quotient
}

fn mod_u256(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if cmp_u256(a, b) < 0 {
        return *a;
    }

    let mut remainder = [0u8; 32];

    for bit in 0..256 {
        shift_left_1(&mut remainder);
        let byte_idx = bit / 8;
        let bit_idx = 7 - (bit % 8);
        if (a[byte_idx] >> bit_idx) & 1 == 1 {
            remainder[31] |= 1;
        }
        if cmp_u256(&remainder, b) >= 0 {
            remainder = sub_u256_unchecked(&remainder, b);
        }
    }

    remainder
}

/// Compare two 256-bit big-endian values. Returns -1, 0, or 1.
fn cmp_u256(a: &[u8; 32], b: &[u8; 32]) -> i32 {
    for i in 0..32 {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
    }
    0
}

/// Shift a 256-bit big-endian value left by 1 bit.
fn shift_left_1(v: &mut [u8; 32]) {
    let mut carry = 0u8;
    for i in (0..32).rev() {
        let new_carry = v[i] >> 7;
        v[i] = (v[i] << 1) | carry;
        carry = new_carry;
    }
}

/// Subtract b from a (unchecked — assumes a >= b).
fn sub_u256_unchecked(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }
    result
}

pub fn jet_eq256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    Ok(Value::Bool(a == b))
}

pub fn jet_lt256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    Ok(Value::Bool(cmp_u256(&a, &b) < 0))
}

pub fn jet_gt256(input: &Value) -> Result<Value, JetError> {
    let (a, b) = extract_u256_pair(input)?;
    Ok(Value::Bool(cmp_u256(&a, &b) > 0))
}
