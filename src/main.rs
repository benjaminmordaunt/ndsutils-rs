use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use std::default::Default;

#[derive(Default)]
pub struct NDSCartridgeHeader {
    gametitle: [u8; 12],
    gamecode:  [u8;  4],
}

impl NDSCartridgeHeader {
    
    pub fn parse_nds<R: Read + Seek>(mut cart: R) -> Self {
        let mut hdr = Self::default();

        cart.seek(SeekFrom::Start(0)).unwrap();
        cart.read_exact(&mut hdr.gametitle).expect("Could not read gametitle");
        cart.read_exact(&mut hdr.gamecode).expect("Could not read gamecode");

        hdr
    }
}

pub fn blowfish_nds(v: &mut u64, kbuf: &[u32], enc: bool) {
    let mut x: u32 = *v as u32;
    let mut y: u32 = (*v >> 32) as u32;
    let mut z: u32;
    let koff: usize = if enc { 0x10 } else { 0x00 };

    let iter: Box<dyn Iterator<Item = usize>> =
        if enc {
            Box::new(0..16)
        } else {
            Box::new((2..18).rev())
    };

    for i in iter {
        z = kbuf[i] ^ x; // P-array XOR
        x = kbuf[(0x12  + ((z >> 24) & 0xFF)) as usize];     // S-box[0]
        x = kbuf[(0x112 + ((z >> 16) & 0xFF)) as usize] + x; // S-box[1]
        x = kbuf[(0x212 + ((z >> 8)  & 0xFF)) as usize] ^ x; // S-box[2]
        x = kbuf[(0x312 + ((z >> 0)  & 0xFF)) as usize] + x; // S-box[3]
        x = y ^ x;
        y = z;
    }

    // Swap + P-array[16,17] XOR
    *v = ((x ^ kbuf[koff]) as u64) | (((y ^ kbuf[1 + koff]) as u64) << 32); 
}

fn main() {
    let mut ndsfile = File::open("pokemon.nds").unwrap();
    let encr_data = File::open("encr_data.bin").unwrap();

    let titlecode = NDSCartridgeHeader::parse_nds(&mut ndsfile).gamecode;
    let titlecode4: u32 = u32::from_le_bytes(titlecode);

    let keycode: [u32; 3] = [
        titlecode4,
        titlecode4 >> 1,
        titlecode4 << 1,
    ];
}
