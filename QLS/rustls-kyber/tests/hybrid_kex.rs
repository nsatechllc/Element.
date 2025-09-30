use rustls_kyber::derive_hybrid_secret;
use proptest::prelude::*;

proptest! {
    #[test]
    fn no_equal_for_different_inputs(a in prop::array::uniform32(any::<u8>()), b in prop::array::uniform32(any::<u8>()), c in prop::array::uniform32(any::<u8>()), d in prop::array::uniform32(any::<u8>())) {
        prop_assume!(a != c || b != d);
        let s1 = derive_hybrid_secret(&a, &b);
        let s2 = derive_hybrid_secret(&c, &d);
        prop_assert!(s1 != s2 || (a==c && b==d));
    }
}

#[test]
fn stable_for_same_inputs() {
    let a = [1u8;32];
    let b = [2u8;32];
    let s1 = derive_hybrid_secret(&a,&b);
    let s2 = derive_hybrid_secret(&a,&b);
    assert_eq!(s1,s2);
}
