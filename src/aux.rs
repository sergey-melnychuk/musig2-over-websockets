use rand::{rngs::OsRng, TryRngCore};

pub fn random<const N: usize>() -> [u8; N] {
    let mut ret = [0u8; N];
    OsRng.try_fill_bytes(&mut ret).expect("random");
    ret
}
