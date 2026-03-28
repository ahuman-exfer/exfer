use std::fmt;

/// Amount in exfers (the smallest unit). 1 EXFER = 100,000,000 exfers.
/// All arithmetic is checked — overflow is an error.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

#[allow(dead_code)]
impl Amount {
    pub const ZERO: Amount = Amount(0);
    pub const EXFER: u64 = 100_000_000;

    pub fn new(exfers: u64) -> Self {
        Amount(exfers)
    }

    /// Create from whole EXFER units.
    pub fn from_exfer(exfer: u64) -> Option<Self> {
        exfer.checked_mul(Self::EXFER).map(Amount)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Checked addition. Returns None on overflow.
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// Checked subtraction. Returns None on underflow.
    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }

    /// Returns true if the amount is zero.
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Amount({} exfers, {}.{:08} EXFER)",
            self.0,
            self.0 / Self::EXFER,
            self.0 % Self::EXFER
        )
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{:08} EXFER",
            self.0 / Self::EXFER,
            self.0 % Self::EXFER
        )
    }
}

/// Sum a slice of amounts with checked arithmetic.
#[allow(dead_code)]
pub fn sum_amounts(amounts: &[Amount]) -> Option<Amount> {
    let mut total = Amount::ZERO;
    for &a in amounts {
        total = total.checked_add(a)?;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_exfer() {
        let a = Amount::from_exfer(100).unwrap();
        assert_eq!(a.as_u64(), 10_000_000_000);
    }

    #[test]
    fn test_checked_add() {
        let a = Amount::new(100);
        let b = Amount::new(200);
        assert_eq!(a.checked_add(b), Some(Amount::new(300)));
    }

    #[test]
    fn test_checked_add_overflow() {
        let a = Amount::new(u64::MAX);
        let b = Amount::new(1);
        assert_eq!(a.checked_add(b), None);
    }

    #[test]
    fn test_checked_sub() {
        let a = Amount::new(300);
        let b = Amount::new(100);
        assert_eq!(a.checked_sub(b), Some(Amount::new(200)));
    }

    #[test]
    fn test_checked_sub_underflow() {
        let a = Amount::new(100);
        let b = Amount::new(200);
        assert_eq!(a.checked_sub(b), None);
    }

    #[test]
    fn test_sum_amounts() {
        let amounts = vec![Amount::new(100), Amount::new(200), Amount::new(300)];
        assert_eq!(sum_amounts(&amounts), Some(Amount::new(600)));
    }

    #[test]
    fn test_display() {
        let a = Amount::new(10_000_000_000);
        assert_eq!(format!("{}", a), "100.00000000 EXFER");
    }
}
