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

/// Represent's Bitcoin script.
struct Script(Vec<u8>);

impl Script {
    /// Deserializes the script from a reader.
    fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let len = deserialize_varint(reader)?;
        // This is consensus rule, so theoretically no need to check it,
        // but serves as a protection against corrupted inputs.
        if len > 10_000 {
            return Err(ErrorKind::InvalidData.into());
        }

        let mut reader = reader.by_ref().take(len);
        let mut data = Vec::with_capacity(len as usize);

        io::copy(&mut reader, &mut data)?;
        Ok(Script(data))
    }
}

fn main() {
    println!("Hello, world!");
}
