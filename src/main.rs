use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use std::default::Default;
use std::mem::transmute;

use byteorder::{ReadBytesExt, LittleEndian};

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
        x = kbuf[(0x12  + ((z >> 24) & 0xFF)) as usize];                 // S-box[0]
        x = kbuf[(0x112 + ((z >> 16) & 0xFF)) as usize].wrapping_add(x); // S-box[1]
        x = kbuf[(0x212 + ((z >> 8)  & 0xFF)) as usize] ^ x;             // S-box[2]
        x = kbuf[(0x312 + ((z >> 0)  & 0xFF)) as usize].wrapping_add(x); // S-box[3]
        x = y ^ x;
        y = z;
    }

    // Swap + P-array[16,17] XOR
    *v = ((y ^ kbuf[koff]) as u64) | (((x ^ kbuf[1 + koff]) as u64) << 32);
}

/* Applies a series of arbitrary manipulations on the P-array and S-boxes 
   depending on the title key. 
*/
pub fn apply_keycode(tk: &mut [u32; 3], kbuf: &mut [u32]) {
    // The two encrypt steps overlap each other
    let tk0ptr = unsafe { transmute::<&mut u32, &mut u64>(&mut tk[0]) };
    let tk1ptr = unsafe { transmute::<&mut u32, &mut u64>(&mut tk[1]) };
    let mut scratch: u64 = 0;

    blowfish_nds(tk1ptr, kbuf, true);
    blowfish_nds(tk0ptr, kbuf, true);

    for i in 0..12 {
        kbuf[i] = kbuf[i] ^ kbuf[i % 2].swap_bytes();
    }

    for i in (0..131).step_by(2) {
        blowfish_nds(&mut scratch, kbuf, true);
        kbuf[i]     = unsafe { *transmute::<*const u64, *const u32>(&scratch as *const u64).offset(1) }; 
        kbuf[i + 1] = unsafe { *transmute::<*const u64, *const u32>(&scratch as *const u64) };
    }
}

pub fn load_encr_data<R: Read + Seek>(encr_data: &mut R) -> Result<[u32; 1042], &'static str> {
    // let data_len = encr_data.seek(SeekFrom::End(0)).map_err(|_| { "Seek failed on encryption binary." })?;
    encr_data.seek(SeekFrom::Start(0)).map_err(|_| { "Seek failed on encryption binary." })?;
    
    let mut contents: [u32; 1042] = [0; 1042];
    for i in &mut contents {
        *i = encr_data.read_u32::<LittleEndian>().unwrap();
    }

    Ok(contents)
}

fn main() {
    let mut ndsfile = File::open("pokemon.nds").unwrap();
    let mut encr_data = File::open("encr_data.bin").unwrap();

    let mut encr = load_encr_data(&mut encr_data).unwrap();

    let ndshdr = NDSCartridgeHeader::parse_nds(&mut ndsfile);
    let titlestr: String = String::from_utf8_lossy(&ndshdr.gametitle).into_owned();
    let titlecode4: u32 = u32::from_le_bytes(ndshdr.gamecode);

    let mut keycode: [u32; 3] = [
        titlecode4,
        titlecode4 >> 1,
        titlecode4 << 1,
    ];

    apply_keycode(&mut keycode, &mut encr);

    println!("Game title: {}", titlestr);
    println!("Game code: {:#06x}", titlecode4);
}
