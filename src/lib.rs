use std::default::Default;
use std::fmt;
use std::io::{self, BufRead};

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Stores one Keccak-256 output result.
pub struct Digest(pub [u8; OUTPUT_LEN]);

impl Digest {
    /// Performs Keccak-256 on the input stream; returns a new Digest.
    ///
    /// For repeated usage, it may be faster to call `keccak_256` directly.
    pub fn with_256<R: io::Read>(input: &mut R) -> io::Result<Self> {
        let mut digest = Self::default();
        digest.keccak_256(input)?;
        Ok(digest)
    }

    /// Consumes the input byte stream, overwriting `self`.
    pub fn keccak_256<R: io::Read>(&mut self, input: &mut R) -> io::Result<()> {
        let ref mut state = [0; LANES];
        let mut input = io::BufReader::with_capacity(R_BYTES, input);

        loop {
            let last_block = {
                let buf = input.fill_buf()?;
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
const OUTPUT_LEN: usize = 32;
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
            for j in (0..25).step_by(5) {
                a[i+j] ^= d;
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

impl fmt::LowerHex for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
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
        write!(f, "0x")?;
        fmt::LowerHex::fmt(self, f)
    }
}

#[cfg(test)]
mod test {
    use super::{R_BYTES, Digest};

    fn check_256(input: &str, output: &str) {
        let digest = Digest::with_256(&mut input.as_bytes()).unwrap();
        assert_eq!(format!("{}", digest), output);
        assert_eq!(format!("{:?}", digest), format!("0x{}", output));
    }

    #[test]
    fn known_256_digests() {
        check_256("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        check_256("A", "03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760");

        // set up a keccak-256 block's worth of repeating digits
        let block = (0..R_BYTES)
            .map(|i| char::from_digit((i % 10) as u32, 10).unwrap())
            .collect::<String>();
        assert_eq!(block.len(), R_BYTES);

        check_256("0123", "3eb0fa86b29ff88ffdd4458cd1f554dd6ad43237a86e38c862ab6c440a387964");
        check_256(&block[..133], "8a5065b879e6e40d546d443e21b14c2fbcac03d9c9c6bf56b7840d559ac6412b");
        check_256(&block[..134], "2a271cee3f8b64a4030387b5ca89be46a1ede06bf8c8875be50f93a8ed3463f5");
        check_256(&block[..135], "e1c34dc088c34f47a3d746bb2cdd07231130c59a9727360e79f4a264e949cb87");
        check_256(&block, "01247d7ddfd57394d74920f8ffeefcb196ba43c15801b6888a34a383c2866088");
        check_256(&block, "01247d7ddfd57394d74920f8ffeefcb196ba43c15801b6888a34a383c2866088");
        check_256(&[&block, "6"].concat(), "b6086ab48f4c24720d6e4d136b3e73c1a8406a2dc3295c3d1b66e0c85fd791cc");
        check_256(&format!("{}{}", block, &block[..135]), "6a9af1e56f93ecbbc859e440eded0a3ce5f97981c1e97b87c12748298d6dbbc6");
        check_256(&format!("{}{}", block, block), "962246ee09dd4e3737ebd1760082da5b7526e78217fc239b9f214ec02263d160");
        check_256(&format!("{}{}{}", block, block, block), "88087f98947b8679da6c44c3996cde147de2e23ba4cf816e683ca0b697a386ca");
    }

    #[test]
    fn basic_traits() {
        let zero = Digest::default();
        assert_eq!(zero, zero);

        let basic = Digest::with_256(&mut "".as_bytes()).unwrap();
        let cloned = basic.clone();
        let copied = basic;
        assert_eq!(basic, cloned);
        assert_eq!(basic, copied);
        assert!(basic != zero);
        assert!(copied != zero);

        let another = Digest::with_256(&mut "a".as_bytes()).unwrap();
        assert!(another != basic);
    }
}
