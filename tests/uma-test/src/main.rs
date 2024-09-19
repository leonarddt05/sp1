#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, One};
use rand::Rng;
use sp1_zkvm::syscalls::syscall_u256x2048_mul;

// fn uint256_mul(x: &[u8; 32], y: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
//     println!("cycle-tracker-start: uint256_mul");
//     let mut result = [0u32; 8];
//     sys_bigint_uma(
//         result.as_mut_ptr() as *mut [u32; 8],
//         0,
//         x.as_ptr() as *const [u32; 8],
//         y.as_ptr() as *const [u32; 8],
//         modulus.as_ptr() as *const [u32; 8],
//     );
//     println!("cycle-tracker-end: uint256_mul");
//     bytemuck::cast::<[u32; 8], [u8; 32]>(result)
// }

fn u256_to_bytes_le(x: &BigUint) -> [u8; 32] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}

fn u2048_to_bytes_le(x: &BigUint) -> [u8; 256] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(256, 0);
    bytes.try_into().unwrap()
}

fn u256x2048_mul(a: [u8; 32], b: [u8; 256]) -> (BigUint, BigUint) {
    let a_big = BigUint::from_bytes_le(&a);
    // println!("a_big: {}", a_big);
    // let a_bytes = u256_to_bytes_le(&a_big);
    let b_big = BigUint::from_bytes_le(&b);
    // let b_bytes = u2048_to_bytes_le(&b_big);
    // println!("b_big: {}", b_big);

    let mut lo: [u32; 64] = [0; 64];
    let mut hi: [u32; 8] = [0; 8];

    syscall_u256x2048_mul(
        a.as_ptr() as *const [u32; 8],
        b.as_ptr() as *const [u32; 64],
        lo.as_mut_ptr() as *mut [u32; 64],
        hi.as_mut_ptr() as *mut [u32; 8],
    );

    // bytemuck::cast::<[u32; 64], [u8; 256]>(lo);
    // bytemuck::cast::<[u32; 8], [u8; 32]>(hi);
    let lo_bytes: [u8; 256] = bytemuck::cast::<[u32; 64], [u8; 256]>(lo);
    let hi_bytes: [u8; 32] = bytemuck::cast::<[u32; 8], [u8; 32]>(hi);

    let lo_big = BigUint::from_bytes_le(&lo_bytes);
    let hi_big = BigUint::from_bytes_le(&hi_bytes);
    (lo_big, hi_big)
}

pub fn main() {
    for _ in 0..50 {
        let mut rng = rand::thread_rng();
        let mut a: [u8; 32] = rng.gen();
        let mut b: [u8; 256] = [0; 256];
        rng.fill(&mut b);
        let a_big = BigUint::from_bytes_le(&a);
        // println!("a_big: {}", a_big);
        a = u256_to_bytes_le(&a_big);
        let b_big = BigUint::from_bytes_le(&b);
        b = u2048_to_bytes_le(&b_big);
        // println!("b_big: {}", b_big);

        let mut lo: [u32; 64] = [0; 64];
        let mut hi: [u32; 8] = [0; 8];

        syscall_u256x2048_mul(
            a.as_ptr() as *const [u32; 8],
            b.as_ptr() as *const [u32; 64],
            lo.as_mut_ptr() as *mut [u32; 64],
            hi.as_mut_ptr() as *mut [u32; 8],
        );

        // bytemuck::cast::<[u32; 64], [u8; 256]>(lo);
        // bytemuck::cast::<[u32; 8], [u8; 32]>(hi);
        let lo_bytes: [u8; 256] = bytemuck::cast::<[u32; 64], [u8; 256]>(lo);
        let hi_bytes: [u8; 32] = bytemuck::cast::<[u32; 8], [u8; 32]>(hi);

        let lo_big = BigUint::from_bytes_le(&lo_bytes);
        let hi_big = BigUint::from_bytes_le(&hi_bytes);
        // println!("hi: {}", hi_big);
        // println!("lo: {}", lo_big);

        let result_syscall = (hi_big << 2048) + lo_big;
        let result = a_big * b_big;
        // println!("result: {}", result);
        // println!("lo_true: {}", result.clone() % (BigUint::one() << 2048));

        assert_eq!(result, result_syscall);
    }

    // let mut rng = rand::thread_rng();
    let mut a_max: [u8; 32] = [0xff; 32];
    let mut b_max: [u8; 256] = [0xff; 256];

    let a_max_big = BigUint::from_bytes_le(&a_max);
    // println!("a_big: {}", a_big);
    a_max = u256_to_bytes_le(&a_max_big);
    let b_max_big = BigUint::from_bytes_le(&b_max);
    b_max = u2048_to_bytes_le(&b_max_big);
    // println!("b_big: {}", b_big);

    let mut lo_max: [u32; 64] = [0; 64];
    let mut hi_max: [u32; 8] = [0; 8];

    syscall_u256x2048_mul(
        a_max.as_ptr() as *const [u32; 8],
        b_max.as_ptr() as *const [u32; 64],
        lo_max.as_mut_ptr() as *mut [u32; 64],
        hi_max.as_mut_ptr() as *mut [u32; 8],
    );

    // bytemuck::cast::<[u32; 64], [u8; 256]>(lo);
    // bytemuck::cast::<[u32; 8], [u8; 32]>(hi);
    let lo_max_bytes: [u8; 256] = bytemuck::cast::<[u32; 64], [u8; 256]>(lo_max);
    let hi_max_bytes: [u8; 32] = bytemuck::cast::<[u32; 8], [u8; 32]>(hi_max);

    let lo_max_big = BigUint::from_bytes_le(&lo_max_bytes);
    let hi_max_big = BigUint::from_bytes_le(&hi_max_bytes);
    // println!("hi: {}", hi_big);
    // println!("lo: {}", lo_big);

    let result_max_syscall = (hi_max_big << 2048) + lo_max_big;
    let result_max = a_max_big * b_max_big;
    // println!("result: {}", result);
    // println!("lo_true: {}", result.clone() % (BigUint::one() << 2048));

    assert_eq!(result_max, result_max_syscall);

    println!("All tests passed successfully!");
}
