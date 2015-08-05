use std::default::Default;
use std::fmt;
use std::io;
use std::io::BufRead;

/// Stores one Keccak-512 output result.
pub struct Digest(pub [u8; OUTPUT_LEN]);

impl Digest {
    pub fn zeroed() -> Self {
        Digest([0; OUTPUT_LEN])
    }

    /// Performs SHA-3 on the input stream; returns a new Digest.
    ///
    /// For repeated usage, it may be faster to call `keccak_512` directly.
    pub fn with_512<R: io::Read>(input: &mut R) -> io::Result<Self> {
        let mut digest = Self::zeroed();
        try!(digest.keccak_512(input));
        Ok(digest)
    }

    /// Consumes the input byte stream, overwriting `self`.
    pub fn keccak_512<R: io::Read>(&mut self, input: &mut R) -> io::Result<()> {
        let ref mut state = [0; LANES];
        let mut input = io::BufReader::with_capacity(R_BYTES, input);

        loop {
            let last_block = {
                let buf = try!(input.fill_buf());
                let consumed = buf.len();
                debug_assert!(consumed <= R_BYTES);

                let last_block = consumed < R_BYTES;
                if last_block {
                    // can we re-use the internal `input.buf` here somehow?
                    let mut last = [0u8; R_BYTES];
                    // std::slice::bytes::copy_memory?
                    for i in 0..consumed {
                        last[i] = buf[i];
                    }
                    last[consumed] = 1;
                    last[R_BYTES-1] |= 0x80;
                    xor_lanes(state, &last);
                }
                else {
                    xor_lanes(state, buf);
                }
                keccak_f(state);
                last_block
            };

            if !last_block {
                input.consume(R_BYTES);
            }
            else {
                break;
            }
        }

        // std::slice::Chunks?
        let output_ptr = self.0.as_mut_ptr() as *mut Lane;
        for i in 0..(OUTPUT_LEN / 8) {
            let word = u64::to_le(state[i]);
            unsafe {
                *output_ptr.offset(i as isize) = word;
            }
        }
        Ok(())
    }
}

type Lane = u64;
type State = [Lane; LANES];

const LANES: usize = 25;
const ROUNDS: usize = 24;
const OUTPUT_LEN: usize = 64;
const R_BYTES: usize = (LANES * 8) - (2 * OUTPUT_LEN);

static ROUND_CONSTANTS: [Lane; ROUNDS] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];

static ROTATION_OFFSETS: [u8; LANES-1] = [
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
];

static PI_LOOKUP: [u8; LANES-1] = [
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
];

fn keccak_f(a: &mut State) {
    for i in 0..ROUNDS {
        round(a, i);
    }
}

fn round(a: &mut State, round: usize) {
    // theta step
    {
        let mut c = [0; 5];
        for i in 0..5 {
            c[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20];
        }
        for i in 0..5 {
            let d = c[(i+4) % 5] ^ c[(i+1) % 5].rotate_left(1);
            // step_by is unstable ;_;
            let mut j = 0;
            while j < 25 {
                a[i+j] ^= d;
                j += 5;
            }
        }
    }

    // rho and pi steps
    {
        debug_assert_eq!(PI_LOOKUP[23], 1);
        let mut wanderer = a[1];

        for i in 0..LANES-1 {
            let j = PI_LOOKUP[i] as usize;
            let rotated = wanderer.rotate_left(ROTATION_OFFSETS[i] as u32);
            wanderer = a[j];
            a[j] = rotated;
        }
    }

    // chi step
    {
        let mut b = [0; 5];
        let mut j = 0;
        while j < LANES {
            for i in 0..5 {
                b[i] = a[i+j];
            }
            for i in 0..5 {
                a[i+j] ^= !b[(i+1) % 5] & b[(i+2) % 5];
            }
            j += 5;
        }
    }

    // iota
    a[0] ^= ROUND_CONSTANTS[round];
}

// use std::slice::Chunks?
fn xor_lanes(a: &mut State, buf: &[u8]) {
    debug_assert_eq!(R_BYTES % 8, 0);
    debug_assert!(R_BYTES <= buf.len());

    for i in 0..(R_BYTES >> 3) {
        a[i] ^= unsafe {
            let ptr = buf.as_ptr() as *const Lane;
            let u = *(ptr.offset(i as isize));
            Lane::from_le(u)
        };
    }
}


// Digest can't be derived due to its big fixed-sized [u8].
// Here are some manual impls.

impl Clone for Digest {
    fn clone(&self) -> Self { *self }
}
impl Copy for Digest {}

impl fmt::LowerHex for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            try!(f.write_fmt(format_args!("{:02x}", byte)));
        }
        Ok(())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl Default for Digest {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        // yay, timing attack
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            if a != b {
                return false;
            }
        }
        true
    }
}

impl Eq for Digest {}


#[cfg(test)]
mod test {
    use super::{R_BYTES, Digest};

    fn check_512(input: &str, output: &str) {
        let digest = Digest::with_512(&mut input.as_bytes()).unwrap();
        assert_eq!(format!("{}", digest), output);
    }

    #[test]
    fn known_512_digests() {
        check_512("", "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e");
        check_512("A", "421a35a60054e5f383b6137e43d44e998f496748cc77258240ccfaa8730b51f40cf47c1bc09c728a8cd4f096731298d51463f15af89543fed478053346260c38");

        let block = "012345678901234567890123456789012345678901234567890123456789012345678901";
        assert_eq!(block.len(), R_BYTES);
        check_512(&block[..69], "5308edb15b386c77921367c483b65c7d3fe23c4b423ddb8df4a5b7f0de40b0ca60b3de5dbb8b153252bd1e66cdd10c1009cdd2ceb23b61bfc44f8ca4209aa75a");
        check_512(&block[..70], "c5eba2e8c8fe3a045d3de364a4581f65ad9e54756b58b957364304d209ff10783e58c88075efa3d92cdfa2c243247d8ff7ea360495632b023fa06cfabbc9d30a");
        check_512(&block[..71], "3173e7abc754a0b2909410d78986428a9183e996864af02f421d273d9fa1b4e4a5b14e2998b20767712f53a01ff8f6ae2c3e71e51e2c0f24257b03e6da09eb77");
        check_512(block, "90b1d032c3bf06dcc78a46fe52054bab1250600224bfc6dfbfb40a7877c55e89bb982799a2edf198568a4166f6736678b45e76b12fac813cfdf0a76714e5eae8");
        check_512(block, "90b1d032c3bf06dcc78a46fe52054bab1250600224bfc6dfbfb40a7877c55e89bb982799a2edf198568a4166f6736678b45e76b12fac813cfdf0a76714e5eae8");
        check_512(&[block, "2"].concat(), "7ecc23723c40dc1154611e2ba1752a5cb6082f592a10b8e3f3817ea634e40d272f2ecf72a99374860c311b8cb6cdadcc862198ac394c7f49a36687fb99f93501");
        check_512(&[block, block].concat(), "bad62fb72bc1d1ebc117523791dd49a03a65ffd3805363e902378256d34f1d4a6c6afdad5aeaea3bfc1a92fd10c3d97d8ad6b5df85e5a0cd7eb43770356dfcc2");
        check_512(&[block, block, block].concat(), "d22e9b6978a012bcb8a6a6e44c919336d8e847994190dbdf839ba10d8fc9c231a33bab45e90b2ceaa60d117331b617309c6f9d07c7bc2aa0a54c1d4622d6388d");
    }

    #[test]
    fn basic_traits() {
        let zero = Digest::zeroed();
        assert_eq!(zero, zero);
        assert_eq!(zero, Default::default());

        let basic = Digest::with_512(&mut "".as_bytes()).unwrap();
        let cloned = basic.clone();
        let copied = basic;
        assert_eq!(basic, cloned);
        assert_eq!(basic, copied);
        assert!(basic != zero);
        assert!(copied != zero);

        let another = Digest::with_512(&mut "a".as_bytes()).unwrap();
        assert!(another != basic);
    }
}
