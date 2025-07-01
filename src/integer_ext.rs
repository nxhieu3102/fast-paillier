// Helper utilities for working with malachite::Integer when the desired
// arithmetic trait is implemented only for Natural.
// All helpers live in this crate, so they avoid Rust's orphan-rule
// restrictions.

use malachite::Integer;
use malachite_base::num::arithmetic::traits::{Mod, ModInverse, ModPow, UnsignedAbs};

/// Modular exponentiation for `Integer`.
///
/// This delegates to the already-implemented `ModPow` for `Natural`.
/// `base`, `exp`, and `m` may be negative - the computation is carried
/// out on their absolute values and the result returned as a signed
/// `Integer` in the usual Paillier range (non-negative < m).
pub(crate) fn mod_pow_int(base: &Integer, exp: &Integer, m: &Integer) -> Integer {
    let base_red = base.mod_op(m).unsigned_abs();
    let res_nat = base_red.mod_pow(exp.unsigned_abs_ref(), m.unsigned_abs_ref());
    res_nat.into()
}

/// Modular inverse for `Integer` (`a^{-1} mod m`).
/// Returns `None` when the inverse does not exist.
pub(crate) fn mod_inverse_int(a: &Integer, m: &Integer) -> Option<Integer> {
    let a_red = a.mod_op(m).unsigned_abs();
    a_red.mod_inverse(m.unsigned_abs_ref()).map(Integer::from)
}
