use rand_core::{Error, RngCore};

#[derive(Debug)]
pub struct OsRng {
    hash: [u8; 32],
}

impl OsRng {
    pub fn new() -> OsRng {
        //unimplemented!("Implement OsRng in halo2_proofs!")
        OsRng { hash: [0; 32] }
    }
}

impl RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        //1
        unimplemented!("Implement OsRng in halo2_proofs! 1")
    }

    fn next_u64(&mut self) -> u64 {
        //1
        unimplemented!("Implement OsRng in halo2_proofs! 2")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unimplemented!("Implement OsRng in halo2_proofs! 3")
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        unimplemented!("Implement OsRng in halo2_proofs! 4");
        Ok(())
    }
}
