use std::{time::Duration, io::ErrorKind, borrow::Cow};

use enum_map::EnumMap;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serialport::SerialPort;
use thiserror::Error;

#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive, enum_map::Enum)]
pub enum Cmd {
    Get = 0x00,
    GetId = 0x02,
    ReadMemory = 0x11,
    Go = 0x21,
    WriteMemory = 0x31,
    EraseMemory = 0x43,
    ExtendedEraseMemory = 0x44,
    GetChecksum = 0xA1,
}

pub struct Boot(Box<dyn SerialPort>);

impl Boot {
    pub fn new(port: Box<dyn SerialPort>) -> Self {
        Boot(port)
    }

    pub fn drain(&mut self) -> Result<(), Error> {
        let saved_timeout = self.0.timeout();

        self.0.set_timeout(Duration::from_millis(1))
            .context("reducing timeout for drain")?;

        let mut buffer = [0; 32];
        let mut cruft = 0_usize;
        loop {
            match self.0.read(&mut buffer) {
                Ok(n) => cruft += n,
                Err(e) if e.kind() == ErrorKind::TimedOut => {
                    break;
                }
                Err(e) => return Err(e)
                    .context("attempting to drain buffer"),
            }
        }
        self.0.set_timeout(saved_timeout)
            .context("restoring timeout after drain")?;

        if cruft > 0 {
            // TODO libraries should not println
            println!("note: {cruft} bytes of cruft drained from serial port");
        }

        Ok(())
    }

    pub fn poke(&mut self) -> Result<(), Error> {
        self.0.write_all(&[0x7F])?;

        let saved_timeout = self.0.timeout();
        self.0.set_timeout(Duration::from_millis(100))?;
        let mut response = 0;
        match self.0.read_exact(std::slice::from_mut(&mut response)) {
            Ok(()) => (),
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                // Chances are pretty good that it's already sitting in the
                // bootloader. In that case, it's one byte through its command
                // sequence. Unblock it.
                self.0.write_all(&[0x7F])?;
                // Treat a timeout here as an actual failure to communicate.
                self.0.read_exact(std::slice::from_mut(&mut response))?;
            }
            Err(e) => return Err(e.into()),
        };
        self.0.set_timeout(saved_timeout)?;
        if response == 0x79 {
            Ok(())
        } else if response == 0x1f {
            // it's already in command processing. This is a NACK. Tolerate it.
            Ok(())
        } else {
            Err(Error::BadAck(response))
        }
    }

    pub fn info(&mut self) -> Result<InfoResponse, Error> {
        let (version, commands) = self.do_get()?;
        let (major, minor) = (version >> 4, version & 0xF);
        
        let product_id;
        let mut bootloader_interfaces = None;
        let mut bootloader_version = None;
        if commands[Cmd::GetId] {
            let pid = self.do_get_id()?;
            if let Pid::Stm32(kind) = &pid {
                if commands[Cmd::ReadMemory] {
                    let blid_addr = kind.bootloader_id_address();
                    let mut blid = 0;
                    self.do_read_memory(blid_addr, std::slice::from_mut(&mut blid))?;
                    let (ifaces, bl_version) = decode_blid(blid);
                    bootloader_interfaces = Some(ifaces);
                    bootloader_version = Some(bl_version);
                }
            }
            product_id = Some(pid);
        } else {
            product_id = None;
        }

        Ok(InfoResponse {
            version: (major, minor),
            command_support: commands,
            product_id,
            bootloader_interfaces,
            bootloader_version,
        })
    }

    pub fn read(&mut self, address: u32, dest: &mut [u8]) -> Result<(), Error> {
        let mut addr = address;
        for chunk in dest.chunks_mut(256) {
            let n = chunk.len();
            self.do_read_memory(addr, chunk)
                .with_context(|| format!("can't read {n} bytes from {addr:#x}"))?;
            addr += 256;
        }
        Ok(())
    }

    pub fn do_get(&mut self) -> Result<(u8, EnumMap<Cmd, bool>), Error> {
        self.send_cmd(Cmd::Get)?;
        let mut byte_count = 0;
        self.0.read_exact(std::slice::from_mut(&mut byte_count))?;
        let byte_count = usize::from(byte_count) + 1;
        let mut buffer = [0; 256];
        self.0.read_exact(&mut buffer[..byte_count])?;
        self.get_ack()?;

        let version = buffer[0];

        let mut commands = EnumMap::default();
        for &cmd in &buffer[1..byte_count] {
            if let Some(known) = Cmd::from_u8(cmd) {
                commands[known] = true;
            }
        }

        Ok((version, commands))
    }

    pub fn do_get_id(&mut self) -> Result<Pid, Error> {
        self.send_cmd(Cmd::GetId)?;
        let mut byte_count = 0;
        self.0.read_exact(std::slice::from_mut(&mut byte_count))?;
        let byte_count = usize::from(byte_count) + 1;
        let mut buffer = [0; 257];
        self.0.read_exact(&mut buffer[..byte_count])?;

        if byte_count == 2 && buffer[0] == 0x04 {
            if let Some(kind) = Stm32Kind::from_u8(buffer[1]) {
                return Ok(Pid::Stm32(kind))
            }
        }

        Ok(Pid::Other(buffer[..byte_count].to_vec()))
    }

    pub fn do_read_memory(&mut self, address: u32, dest: &mut [u8]) -> Result<(), Error> {
        let count = dest.len();
        let count_m1 = count.checked_sub(1).expect("read size can't be 0");
        let count_m1 = u8::try_from(count_m1).expect("read size can't be > 256");

        context_scope(
            || {
                self.send_cmd(Cmd::ReadMemory)?;

                self.send_with_check_inv(&address.to_be_bytes())
                    .context("failed to send address to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept address")?;

                self.send_with_check(std::slice::from_ref(&count_m1))
                    .context("failed to send count to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept count")?;

                self.0.read_exact(dest)?;
                Ok(())
            },

            || format!("failed to read {count} bytes from address {address:#x}"),
        )
    }

    pub fn do_write_memory(&mut self, address: u32, src: &[u8]) -> Result<(), Error> {
        let count = src.len();
        assert!(count % 4 == 0, "must write in units of 4 bytes");
        let count_m1 = count.checked_sub(1).expect("can't read 0 bytes");
        let count_m1 = u8::try_from(count_m1).expect("can't read more than 256 bytes");

        context_scope(
            || {
                self.send_cmd(Cmd::WriteMemory)?;

                self.send_with_check_inv(&address.to_be_bytes())
                    .context("failed to send address to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept address")?;

                // Copy here is kind of lame but hey
                let mut buffer = vec![0; src.len() + 1];
                buffer[0] = count_m1;
                buffer[1..].copy_from_slice(src);
                self.send_with_check_inv(&buffer)
                    .context("failed to send count+data to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept count+data")?;
                Ok(())
            },
            || format!("failed to write {count} bytes to address {address:#x}"),
        )
    }

    pub fn do_erase_memory(&mut self, pages: &[u8]) -> Result<(), Error> {
        let count = pages.len();
        let count_m1 = count.checked_sub(1).expect("erase-memory size cannot be 0");
        let count_m1 = u8::try_from(count_m1).expect("can't erase more than 255 pages at a time");
        if count_m1 == 255 {
            panic!("can't erase more than 255 pages at a time");
        }

        context_scope(
            || {
                self.send_cmd(Cmd::EraseMemory)?;

                // Copy here is kind of lame but hey
                let mut buffer = vec![0; pages.len() + 1];
                buffer[0] = count_m1;
                buffer[1..].copy_from_slice(pages);
                self.send_with_check_inv(&buffer)
                    .context("failed to send page addresses to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept page addresses")?;
                Ok(())
            },
            || format!("failed to erase {count} pages"),
        )
    }

    pub fn do_erase_memory_global(&mut self) -> Result<(), Error> {
        context_scope(
            || {
                self.send_cmd(Cmd::EraseMemory)?;

                self.send_with_check_inv(&[0xFF])
                    .context("failed to send global erase signal to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept global erase signal")?;
                Ok(())
            },
            || "failed to execute global erase",
        )
    }

    pub fn do_extended_erase_memory(&mut self, pages: &[u16]) -> Result<(), Error> {
        let count = pages.len();
        let count_m1 = count.checked_sub(1).expect("erase-memory size cannot be 0");
        let count_m1 = u16::try_from(count_m1).expect("can't erase more than 0xFFF1 pages");
        if count_m1 >= 0xFFF0 {
            panic!("can't erase more than 0xFFF1 pages");
        }

        context_scope(
            || {
                self.send_cmd(Cmd::ExtendedEraseMemory)?;

                // Copy here is kind of lame but hey
                let mut buffer = vec![];
                buffer.extend(count_m1.to_be_bytes());
                for p in pages {
                    buffer.extend(p.to_be_bytes());
                }
                self.send_with_check_inv(&buffer)
                    .context("failed to send page addresses to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept page addresses")?;
                Ok(())
            },
            || format!("can't erase {count} pages"),
        )
    }

    pub fn do_extended_erase_memory_global(&mut self) -> Result<(), Error> {
        context_scope(
            || {
                self.send_cmd(Cmd::ExtendedEraseMemory)?;

                self.send_with_check_inv(&[0xFF, 0xFF])
                    .context("failed to send global erase signal to bootloader")?;
                self.get_ack()
                    .context("bootloader did not accept global erase signal")?;
                Ok(())
            },
            || "failed to execute global erase",
        )
    }

    pub fn do_get_checksum(&mut self, address: u32, words: u32, polynomial: u32, initial: u32) -> Result<u32, Error> {
        self.send_cmd(Cmd::GetChecksum)?;

        self.send_with_check_inv(&address.to_be_bytes())
            .context("failed to send base address to bootloader")?;
        self.get_ack()
            .context("bootloader did not accept base address")?;

        self.send_with_check_inv(&words.to_be_bytes())
            .context("failed to send word count to bootloader")?;
        self.get_ack()
            .context("bootloader did not accept word count")?;

        self.send_with_check_inv(&polynomial.to_be_bytes())
            .context("failed to send polynomial to bootloader")?;
        self.get_ack()
            .context("bootloader did not accept polynomial")?;

        self.send_with_check_inv(&initial.to_be_bytes())
            .context("failed to send initial value to bootloader")?;
        self.get_ack()
            .context("bootloader did not accept initial value")?;

        let mut crc = [0; 5];
        self.0.read_exact(&mut crc)
            .context("failed to read CRC result")?;
        let (crc32, checksum) = (u32::from_be_bytes(crc[..4].try_into().unwrap()), crc[4]);
        let rxcrc = crc[..4].iter().fold(0, |x, byte| x ^ *byte);
        if rxcrc != checksum {
            return Err(Error::Crc {
                expected: checksum,
                actual: rxcrc,
            });
        }

        Ok(crc32)
    }

    pub fn do_go(&mut self, address: u32) -> Result<(), Error> {
        context_scope(
            || {
                self.send_cmd(Cmd::Go)?;

                self.send_with_check_inv(&address.to_be_bytes())?;
                self.get_ack()?;

                Ok(())
            },
            || format!("failed to start program using table at address {address:#x}"),
        )
    }

    fn send_cmd(&mut self, cmd: Cmd) -> Result<(), Error> {
        self.send_with_check(&[cmd as u8])
            .with_context(|| format!("failed to transmit command {cmd:?}"))?;
        self.get_ack()
            .with_context(|| format!("failed to issue command {cmd:?}"))?;
        Ok(())
    }

    fn send_with_check(&mut self, data: &[u8]) -> Result<(), Error> {
        self.send_with_check_base(0xFF, data)
    }

    fn send_with_check_base(&mut self, base: u8, data: &[u8]) -> Result<(), Error> {
        let check = data.iter().fold(base, |x, byte| x ^ *byte);
        self.0.write_all(data)?;
        self.0.write_all(std::slice::from_ref(&check))?;
        Ok(())
    }

    fn send_with_check_inv(&mut self, data: &[u8]) -> Result<(), Error> {
        self.send_with_check_base(0, data)
    }

    fn get_ack(&mut self) -> Result<(), Error> {
        let mut response = 0;
        self.0.read_exact(std::slice::from_mut(&mut response))?;
        match response {
            0x79 => Ok(()),
            0x1F => Err(Error::Nack),
            _ => Err(Error::BadAck(response)),
        }
    }

    pub fn require_cmd(&mut self, cmd: Cmd) -> Result<(), Error> {
        let (_, commands) = self.do_get()
            .with_context(|| format!("can't determine if command {cmd:?} is supported"))?;
        if commands[cmd] {
            Ok(())
        } else {
            Err(Error::NotSupported(cmd))
        }
    }
}

#[derive(Clone, Debug)]
pub struct InfoResponse {
    pub version: (u8, u8),
    pub command_support: EnumMap<Cmd, bool>,
    pub product_id: Option<Pid>,
    pub bootloader_interfaces: Option<Ifaces>,
    pub bootloader_version: Option<u8>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("command {0:?} was required but is not supported by device")]
    NotSupported(Cmd),
    #[error("instead of ACK, got: {0:#x}")]
    BadAck(u8),
    #[error("device NACKed unexpectedly")]
    Nack,
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("serial port configuration error")]
    Ser(#[from] serialport::Error),
    #[error("protocol CRC error, expected {expected:#x} but got {actual:#x}")]
    Crc {
        expected: u8,
        actual: u8,
    },

    #[error("{0}")]
    Context(Cow<'static, str>, #[source] Box<Self>),
}

pub trait OurContext {
    type Ok;
    fn context(self, info: impl Into<Cow<'static, str>>) -> Result<Self::Ok, Error>;
    fn with_context<M>(self, f: impl FnOnce() -> M) -> Result<Self::Ok, Error>
        where M: Into<Cow<'static, str>>;
}

impl<T, E> OurContext for Result<T, E>
    where E: Into<Error>,
{
    type Ok = T;

    fn context(self, info: impl Into<Cow<'static, str>>) -> Result<T, Error> {
        self.map_err(|e| Error::Context(info.into(), Box::new(e.into())))
    }

    fn with_context<M>(self, f: impl FnOnce() -> M) -> Result<T, Error>
        where M: Into<Cow<'static, str>>
    {
        self.map_err(|e| Error::Context(f().into(), Box::new(e.into())))
    }
}

fn context_scope<T, C>(
    body: impl FnOnce() -> Result<T, Error>,
    context_provider: impl FnOnce() -> C,
) -> Result<T, Error>
    where C: Into<Cow<'static, str>>,
{
    body().with_context(context_provider)
}


#[derive(Clone, Debug)]
pub enum Pid {
    Stm32(Stm32Kind),
    Other(Vec<u8>),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive)]
#[allow(non_camel_case_types)]
pub enum Stm32Kind {
    C011xx = 0x43,
    C031xx = 0x53,

    G03xxx_G04xxx = 0x66,
    G05xxx_G061xx = 0x56,
    G07xxx_G08xxx = 0x60,
    G0B0xx_G0B1xx_G0C1xx = 0x67,

    G431xx_G441xx = 0x68,
    G47xxx_G48xxx = 0x69,
    G491xx_G4A1xx = 0x79,

    L01xxx_L02xxx = 0x57,
    L031xx_L041xx = 0x25,
    L05xxx_L06xxx = 0x17,
    L07xxx_L08xxx = 0x47,

    L412xx_L422xx = 0x64,
    L43xxx_L44xxx = 0x35,
    L45xxx_L46xxx = 0x62,
    L47xxx_L48xxx = 0x15,
    L496xx_L4A6xx = 0x61,
    L4Rxx_L4Sxx = 0x70,
    L4Pxx_L4Qxx = 0x90,
}

impl Stm32Kind {
    pub fn bootloader_id_address(self) -> u32 {
        use Stm32Kind::*;
        match self {
            C011xx | C031xx => 0x1FFF_17FE,
            G07xxx_G08xxx => 0x1FFF_6FFE,
            G03xxx_G04xxx | G05xxx_G061xx => 0x1FFF_1FFE,
            G0B0xx_G0B1xx_G0C1xx => 0x1FFF_9FFE,

            G431xx_G441xx | G47xxx_G48xxx | G491xx_G4A1xx => 0x1FFF_6FFE,

            L01xxx_L02xxx | L031xx_L041xx | L05xxx_L06xxx => 0x1FF0_0FFE,
            L07xxx_L08xxx => 0x1FF0_1FFE,

            L412xx_L422xx | L43xxx_L44xxx | L45xxx_L46xxx | L47xxx_L48xxx | L496xx_L4A6xx | L4Rxx_L4Sxx | L4Pxx_L4Qxx => 0x1FFF_6FFE,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive)]
#[allow(non_camel_case_types)]
pub enum Stm32PreciseKind {
    C011xx = 0x43,
    C031xx = 0x53,

    G03xxx_G04xxx = 0x66,
    G05xxx_G061xx = 0x56,
    G07xxx_G08xxx = 0x60,
    G0B0xx_G0B1xx_G0C1xx = 0x67,

    G431xx_G441xx = 0x68,
    G47xxx_G48xxx = 0x69,
    G491xx_G4A1xx = 0x79,

    L01xxx_L02xxx = 0x57,
    L031xx_L041xx = 0x25,
    L05xxx_L06xxx = 0x17,
    L07xxx_L08xxx = 0x47,

    L412xx_L422xx = 0x64,
    L43xxx_L44xxx = 0x35,
    L45xxx_L46xxx = 0x62,
    L47xxx_L48xxx = 0x15,
    L496xx_L4A6xx = 0x61,
    L4Rxx_L4Sxx = 0x70,
    L4Pxx_L4Qxx = 0x90,
}

fn decode_blid(blid: u8) -> (Ifaces, u8) {
    let ifaces = match blid >> 4 {
        1 => Ifaces::USART,
        2 => Ifaces::USART | Ifaces::SECOND_USART,
        3 => Ifaces::USART | Ifaces::CAN | Ifaces::DFU,
        4 => Ifaces::USART | Ifaces::DFU,
        5 => Ifaces::USART | Ifaces::I2C,
        6 => Ifaces::I2C,
        7 => Ifaces::USART | Ifaces::CAN | Ifaces::DFU | Ifaces::I2C,
        8 => Ifaces::I2C | Ifaces::SPI,
        9 => Ifaces::USART | Ifaces::CAN | Ifaces::DFU | Ifaces::I2C | Ifaces::SPI,
        10 => Ifaces::USART | Ifaces::DFU | Ifaces::I2C,
        11 => Ifaces::USART | Ifaces::I2C | Ifaces::SPI,
        12 => Ifaces::USART | Ifaces::SPI,
        13 => Ifaces::USART | Ifaces::DFU | Ifaces::I2C | Ifaces::SPI,
        14 => Ifaces::USART | Ifaces::DFU | Ifaces::I2C | Ifaces::I3C | Ifaces::CAN | Ifaces::SPI,
        _ => Ifaces::empty(),
    };
    (ifaces, blid & 0xF)
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct Ifaces: u32 {
        const USART = 1 << 0;
        const SECOND_USART = 1 << 1;
        const CAN = 1 << 2;
        const DFU = 1 << 3;
        const I2C = 1 << 4;
        const SPI = 1 << 5;
        const I3C = 1 << 6;
    }
}


