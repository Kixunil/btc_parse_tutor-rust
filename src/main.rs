extern crate byteorder;

use byteorder::{LE, ReadBytesExt};
use std::io;
use std::io::{Read, ErrorKind};

/// Deserializes "varint" as defined by Bitcoin protocol.
fn deserialize_varint<R: Read>(reader: &mut R) -> io::Result<u64> {
    match reader.read_u8()? {
        253 => reader.read_u16::<LE>().map(Into::into),
        254 => reader.read_u32::<LE>().map(Into::into),
        255 => reader.read_u64::<LE>().map(Into::into),
        x   => Ok(x.into()),
    }
}

fn main() {
    println!("Hello, world!");
}
