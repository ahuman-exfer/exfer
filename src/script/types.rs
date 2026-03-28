//! Type system for Exfer Script.
//!
//! Types: Unit, Sum(A, B), Product(A, B), List(A), Bound(k).
//! Option(A) is sugar for Sum(Unit, A).

/// The type of an Exfer Script value.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    /// The unit type — a single value.
    Unit,
    /// Sum (tagged union): Left(A) | Right(B).
    Sum(Box<Type>, Box<Type>),
    /// Product (pair): (A, B).
    Product(Box<Type>, Box<Type>),
    /// Variable-length list of homogeneous elements.
    List(Box<Type>),
    /// Bounded natural: values 0..k-1.
    /// At the type level, k is the exclusive upper bound.
    Bound(u64),
    /// 256-bit unsigned integer. Distinct from Product(U64, U64) to prevent
    /// type confusion: U256 jets return Value::U256 which is incompatible
    /// with product projections (Take/Drop) and 64-bit jets (Eq64 etc.).
    U256,
}

impl Type {
    /// Convenience: Option(A) = Sum(Unit, A).
    pub fn option(inner: Type) -> Type {
        Type::Sum(Box::new(Type::Unit), Box::new(inner))
    }

    /// Convenience: Bool = Sum(Unit, Unit).
    pub fn bool_type() -> Type {
        Type::Sum(Box::new(Type::Unit), Box::new(Type::Unit))
    }

    /// Convenience: Bytes = List(Bound(256)).
    pub fn bytes() -> Type {
        Type::List(Box::new(Type::Bound(256)))
    }

    /// Convenience: Hash256 = fixed 32-byte value.
    /// Represented as Bound(0) — a sentinel meaning "256-bit hash".
    /// In practice, jets handle this opaquely.
    pub fn hash256() -> Type {
        Type::Bound(0)
    }

    /// U64 type = Bound(2^64) — but we can't represent 2^64 in u64.
    /// Use Bound(u64::MAX) as the canonical representation.
    pub fn u64_type() -> Type {
        Type::Bound(u64::MAX)
    }

    /// U256 type for 256-bit integers.
    /// Distinct from Product(U64, U64) — prevents type confusion between
    /// 256-bit arithmetic results and plain 64-bit pairs.
    pub fn u256_type() -> Type {
        Type::U256
    }
}
