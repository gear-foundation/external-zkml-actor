//use gstd::fmt;

// pub type Result<T> = gstd::Result<T, Error>;

// pub enum Error {}

// pub trait Write {
//     fn write(&mut self, buf: &[u8]) -> Result<usize>;
// }

// pub trait Read {
//     fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
// }

pub use no_std_io::io::*;

pub use no_std_io::error::*;
