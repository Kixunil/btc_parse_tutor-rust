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

/// Represents 256 bit hash. (SHA256)
struct Hash256([u8; 32]);

impl Hash256 {
    /// Deserializes the hash
    fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0; 32];
        reader.read_exact(&mut buf)?;

        Ok(Hash256(buf))
    }
}

/// Defines "outpoint" - output of previous transaction being consumed.
struct Outpoint {
    /// ID of previous transaction
    txid: Hash256,
    /// Which output of the previous transaction is being consumed.
    index: u32,
}

impl Outpoint {
    /// Deserializes the outpoint from the blockchain data
    fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let txid = Hash256::deserialize(reader)?;
        let index = reader.read_u32::<LE>()?;

        Ok(Outpoint {
            txid,
            index,
        })
    }
}

/// Contains data about single transaction input.
struct TxInput {
    outpoint: Outpoint,
    sig_script: Script,
    sequence: u32,
}

impl TxInput {
    /// Deserializes the input from the blockchain data
    fn deserialize<R: Read>(reader: &mut R) -> io::Result<Self> {
        let outpoint = Outpoint::deserialize(reader)?;
        let sig_script = Script::deserialize(reader)?;
        let sequence = reader.read_u32::<LE>()?;

        Ok(TxInput {
            outpoint,
            sig_script,
            sequence,
        })
    }
}

fn main() {
    println!("Hello, world!");
}
