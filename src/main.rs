use std::io::{Read, Seek, SeekFrom};
use std::fs::File;
use std::default::Default;
use std::mem::{transmute, size_of};

use byteorder::{ReadBytesExt, LittleEndian};

// Represents the contents of the ARM9 bootcode, as well as
// information about its secure area.
struct ARM9Bootcode {
    raw_data: Vec<u64>,
    secure_area_present: bool, // Determined by start address (4000h..8000h)
    secure_area_encrypted: bool,
}

impl ARM9Bootcode {
    fn new<R: Read + Seek>(nds: &mut R, hdr: &NDSCartridgeHeader) -> ARM9Bootcode {
        // For now, assume arm9 boot address is exactly 0x4000. In reality, for secure area to be used, src
        // can be up to 0x7FFF.
        let arm9off: u64 = hdr.arm9off as u64;

        assert!(hdr.arm9off == 0x4000);
        nds.seek(SeekFrom::Start(arm9off)).map_err(|_| { "Seek failed on nds file." }).unwrap();

        let mut contents: Vec<u64> = vec![];
        for _ in 0..hdr.arm9size {
            contents.push(nds.read_u64::<LittleEndian>().unwrap());
        }

        let secure_area_encrypted = contents[0] != 0xE7FFDEFFE7FFDEFF;

        ARM9Bootcode { 
            raw_data: contents, 
            secure_area_present: hdr.arm9off >= 0x4000 && hdr.arm9off < 0x8000, 
            secure_area_encrypted
        }
    }
}

#[derive(Default)]
#[repr(C, packed(1))]
pub struct NDSCartridgeHeader {
    gametitle:   [u8; 12],
    gamecode:         u32,
    makercode:        u16,
    unitcode:    [u8;  1],
    encrseedsel: [u8;  1],
    devicecaps:  [u8;  1],
    res0:        [u8;  8],
    ndsregion:   [u8;  1],
    romversion:  [u8;  1],
    autostart:   [u8;  1],
    arm9off:          u32,
    arm9entry:        u32,
    arm9raddr:        u32,
    arm9size:         u32,
}

impl NDSCartridgeHeader {
    
    pub fn parse_nds<R: Read + Seek>(mut cart: R) -> Self {
        let mut hdr = Self::default();
        let hdrptr = unsafe { transmute::<&mut NDSCartridgeHeader, &mut [u8; size_of::<NDSCartridgeHeader>()]>(&mut hdr) };

        cart.seek(SeekFrom::Start(0)).unwrap();
        cart.read_exact(hdrptr).unwrap();

        hdr
    }
}

pub fn blowfish_nds(v: &mut u64, kbuf: &[u32], enc: bool) {
    let mut x: u32 = *v as u32;
    let mut y: u32 = (*v >> 32) as u32;
    let mut z: u32;

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
    if enc {
        y ^= kbuf[16];
        x ^= kbuf[17];
    } else {
        y ^= kbuf[1];
        x ^= kbuf[0];
    }
    *v = (y as u64) | ((x as u64) << 32);
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

    let mut arm9code = ARM9Bootcode::new(&mut ndsfile, &ndshdr);

    let mut keycode: [u32; 3] = [
        ndshdr.gamecode,
        ndshdr.gamecode >> 1,
        ndshdr.gamecode << 1,
    ];

    apply_keycode(&mut keycode, &mut encr);
    apply_keycode(&mut keycode, &mut encr);
    blowfish_nds(&mut arm9code.raw_data[0], &encr, true);
    apply_keycode(&mut keycode, &mut encr);
    blowfish_nds(&mut arm9code.raw_data[0], &encr, false);
    println!("{:#06x}", arm9code.raw_data[0]);

    // Local variables needed to store unaligned fields (from packed header)
    let gamecode = ndshdr.gamecode;
    let arm9off = ndshdr.arm9off;

    println!("Game title: {}", titlestr);
    println!("Game code: {:#06x}", gamecode);
    println!("ARM9 bootcode ROM offset: {:#06x}", arm9off);

    if !arm9code.secure_area_present {
        println!("NOTE: ROM has no ARM9 secure area.");
    } else {
        if arm9code.secure_area_encrypted {
            println!("NOTE: ARM9 secure area requires decryption.");
        } else {
            println!("NOTE: ARM9 secure area is already decrypted.");
        }
    }
}
