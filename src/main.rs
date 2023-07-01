//! A command-line tool for interacting with the built-in UART bootloader on
//! most STM32 parts.
//!
//! This tool provides two kinds of commands, low-level and high-level. Where it
//! makes sense to have both kinds of commands for a single concept, the
//! low-level one is typically prefixed with `raw-`.

use std::{time::Duration, io::{ErrorKind, Write}, path::PathBuf, fmt::Display};

use anyhow::{Context, Result, anyhow, bail};
use enum_map::{EnumMap, Enum};
use indicatif::ProgressBar;
use serialport::{SerialPort, Parity};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use clap::Parser;

/// A tool for interacting with the built-in UART bootloader on most STM32
/// parts.
///
/// For this to work, the chip must be booted into the bootloader. This will
/// happen by default on a factory-fresh chip; after it's been programmed, the
/// method for getting back into the bootloader depends on the chip and circuit.
#[derive(Debug, Parser)]
#[clap(version)]
struct BootTool {
    port: String,
    #[clap(long, short, global = true, default_value_t = 115_200)]
    baud_rate: u32,
    #[clap(long, short('v'), global = true)]
    verbose: bool,

    #[clap(subcommand)]
    cmd: SubCmd,
}

#[derive(Debug, Parser)]
enum SubCmd {
    /// Checks basic connectivity to the bootloader by sending a handshake
    /// message and verifying the response.
    Ping,
    /// Dumps as much info about a connected chip as we can easily determine.
    Info,
    /// Runs the GET low-level command, which reports which other commands the
    /// bootloader supports.
    Get,
    /// Runs the GET-ID low-level command, reporting chip ID only.
    GetId,
    /// Reads a block of memory from the chip and presents it in hex-dump form.
    DumpMemory {
        /// Source address to start reading.
        #[clap(value_parser = parse_int::parse::<u32>)]
        address: u32,
        /// Number of bytes to read.
        #[clap(value_parser = parse_int::parse::<u32>)]
        count: u32,
    },
    /// Reads a block of memory from the chip into a file.
    ReadMemory {
        /// Source address to start reading.
        #[clap(value_parser = parse_int::parse::<u32>)]
        address: u32,
        /// Number of bytes to read.
        #[clap(value_parser = parse_int::parse::<u32>)]
        count: u32,
        /// Output file.
        out_path: PathBuf,
    },
    /// Writes the contents of a file into memory on the chip.
    WriteMemory {
        /// Destination address to start writing.
        #[clap(value_parser = parse_int::parse::<u32>)]
        address: u32,
        /// Data to write -- length of this file determines the amount written.
        source: PathBuf,
        /// Optionally read the contents back to make sure it took.
        #[clap(long)]
        verify: bool,
    },
    /// Writes a repeating byte over a portion of memory in the chip.
    FillMemory {
        /// Address to start writing.
        #[clap(value_parser = parse_int::parse::<u32>)]
        address: u32,
        /// Number of bytes to write.
        #[clap(value_parser = parse_int::parse::<u32>)]
        count: u32,
        /// Byte value to write.
        #[clap(value_parser = parse_int::parse::<u8>)]
        byte: u8,
    },
    /// Reads out a block of memory from the chip and compares it to the
    /// contents of a file.
    VerifyMemory {
        /// Address to start reading.
        #[clap(value_parser = parse_int::parse::<u32>)]
        address: u32,
        /// File to compare against -- length of this file determines the amount
        /// read.
        source: PathBuf,
    },
    /// Leaves the bootloader and activates a program, given the address of its
    /// vector table.
    ///
    /// Note that the bootloader DOES NOT update the VTOR register when
    /// performing this command, so the program will have to set its own vector
    /// table if it wants to handle interrupts.
    Go {
        /// Address of a vector table; the most important parts are the first
        /// two words, which are the initial stack pointer and initial function
        /// pointer, respectively.
        #[clap(value_parser = parse_int::parse::<u32>)]
        vector_address: u32,
    },
    /// Issues a global erase command, which erases all of flash and may reset
    /// other things (like protection settings) depending on the chip.
    GlobalErase,
    /// Computes the CRC32 of a section of memory in the chip, if the chip
    /// supports this command -- many don't.
    GetChecksum {
        #[clap(value_parser = parse_int::parse::<u32>)]
        address: u32,
        #[clap(value_parser = parse_int::parse::<u32>)]
        words: u32,
        #[clap(value_parser = parse_int::parse::<u32>)]
        polynomial: u32,
        #[clap(value_parser = parse_int::parse::<u32>)]
        initial: u32,
    },
    RawWriteMemory {
        #[clap(value_parser = parse_int::parse::<u32>)]
        address: u32,
        source: PathBuf,
    },
    RawEraseMemory {
        #[clap(value_parser = parse_int::parse::<u8>)]
        pages: Vec<u8>,
    },
    RawExtendedEraseMemory {
        #[clap(value_parser = parse_int::parse::<u16>)]
        pages: Vec<u16>,
    },
}

fn main() -> Result<()> {
    let args = BootTool::parse();

    let mut boot = Boot(serialport::new(&args.port, args.baud_rate)
        .timeout(Duration::from_millis(500))
        .parity(Parity::Even)
        .open()
        .with_context(|| format!("opening serial port {}", args.port))?);

    boot.drain()
        .context("unable to drain serial port")?;
    boot.poke()
        .context("unable to contact bootloader (may not be running or on a different interface)")?;

    match args.cmd {
        SubCmd::Ping => {
            println!("successfully poked device");
        }
        SubCmd::Info => {
            let (version, commands) = boot.do_get()?;
            let (major, minor) = (version >> 4, version & 0xF);

            println!("Protocol version: {major}.{minor}");
            println!("Known commands supported:");
            for i in 0..Cmd::LENGTH {
                let c = <Cmd as Enum>::from_usize(i);
                let f = if commands[c] { "YES" } else { "no" };
                println!("{:24} {f}", format!("{c:?}"));
            }

            if commands[Cmd::GetId] {
                let pid = boot.do_get_id()?;
                match pid {
                    Pid::Stm32(kind) => {
                        println!("STM32: {kind:?}");
                        if commands[Cmd::ReadMemory] {
                            let blid_addr = kind.bootloader_id_address();
                            let mut blid = 0;
                            boot.do_read_memory(blid_addr, std::slice::from_mut(&mut blid))?;

                            let (ifaces, version) = decode_blid(blid);

                            println!("Bootloader ID: {blid:#x}");
                            print!(" - interfaces:");
                            for (i, _) in ifaces.iter_names() {
                                print!(" {i}");
                            }
                            println!();
                            println!(" - version: {version}");
                        } else {
                            println!("ReadMemory not supported, can't say more");
                        }
                    }
                    Pid::Other(bytes) => println!("unknown: {bytes:?}"),
                }
            } else {
                println!("GetId not supported, can't say more");
            }
        }
        SubCmd::Get => {
            let (version, commands) = boot.do_get()?;
            let (major, minor) = (version >> 4, version & 0xF);

            println!("Protocol version: {major}.{minor}");
            println!("Known commands supported:");
            for i in 0..Cmd::LENGTH {
                let c = <Cmd as Enum>::from_usize(i);
                let f = if commands[c] { "YES" } else { "no" };
                println!("{:24} {f}", format!("{c:?}"));
            }
        }
        SubCmd::GetId => {
            boot.require_cmd(Cmd::GetId)?;
            let pid = boot.do_get_id()?;

            match pid {
                Pid::Stm32(kind) => println!("STM32: {kind:?}"),
                Pid::Other(bytes) => println!("unknown: {bytes:?}"),
            }
        }
        SubCmd::DumpMemory { address, count } => {
            boot.require_cmd(Cmd::ReadMemory)?;

            let mut address = address;
            let bound = address + count;

            let mut buffer = vec![0; 256];
            while address < bound {
                let chunk_size = u32::min(bound - address, 256);
                let buffer = &mut buffer[..chunk_size as usize];
                boot.do_read_memory(address, buffer)?;
                for (i, row) in buffer.chunks(16).enumerate() {
                    let addr = address + 16 * i as u32;
                    print!("{addr:08x}");
                    for (b, byte) in row.iter().enumerate() {
                        if b % 8 == 0 {
                            print!("  ");
                        }
                        print!("{byte:02x} ");
                    }
                    println!();
                }

                address += chunk_size;
            }
        }
        SubCmd::ReadMemory { address, count, out_path } => {
            boot.require_cmd(Cmd::ReadMemory)?;

            let mut address = address;
            let bound = address + count;

            let mut data = Vec::with_capacity(count as usize);
            let mut buffer = vec![0; 256];
            println!("reading {count} bytes...");
            let bar = ProgressBar::new(u64::from(count));
            while address < bound {
                let chunk_size = u32::min(bound - address, 256);
                let buffer = &mut buffer[..chunk_size as usize];
                boot.do_read_memory(address, buffer)
                    .with_context(|| format!("can't read {chunk_size} bytes from address {address:#x}"))?;
                data.extend_from_slice(buffer);
                address += chunk_size;
                bar.inc(u64::from(chunk_size));
            }
            bar.finish();

            std::fs::write(&out_path, &data)
                .with_context(|| format!("can't write data to {}", out_path.display()))?;
        }
        SubCmd::WriteMemory { address, source, verify } => {
            boot.require_cmd(Cmd::WriteMemory)?;
            if verify {
                boot.require_cmd(Cmd::ReadMemory)?;
            }

            let data = std::fs::read(&source)
                .with_context(|| format!("reading {}", source.display()))?;
            if data.len() % 4 != 0 {
                bail!("must write in units of 4 bytes");
            }

            println!("writing {} bytes...", data.len());
            let bar = ProgressBar::new(data.len() as u64);
            for (i, chunk) in data.chunks(256).enumerate() {
                let chunk_addr = address + i as u32 * 256;
                boot.do_write_memory(chunk_addr, chunk)?;
                bar.inc(chunk.len() as u64);
            }
            bar.finish();

            if verify {
                do_verify(&mut boot, &data, address, args.verbose)?;
                println!("OK: matches what was intended");
            }
        }
        SubCmd::FillMemory { mut address, count, byte } => {
            boot.require_cmd(Cmd::WriteMemory)?;

            let buffer = [byte; 256];

            println!("filling {} bytes...", count);
            let bar = ProgressBar::new(count as u64);
            let end = address + count;
            while address < end {
                let chunk_size = (end - address).min(256);
                boot.do_write_memory(address, &buffer[..chunk_size as usize])?;
                address += chunk_size;
                bar.inc(chunk_size as u64);
            }
            bar.finish();
        }
        SubCmd::VerifyMemory { address, source } => {
            boot.require_cmd(Cmd::ReadMemory)?;

            let data = std::fs::read(&source)
                .with_context(|| format!("reading {}", source.display()))?;

            do_verify(&mut boot, &data, address, args.verbose)?;
            println!("OK: memory at address {address:#x} matches {}", source.display());
        }
        SubCmd::RawWriteMemory { address, source } => {
            boot.require_cmd(Cmd::WriteMemory)?;

            let data = std::fs::read(&source)
                .with_context(|| format!("reading {}", source.display()))?;
            if data.len() > 256 {
                bail!("count cannot be over 256");
            }
            if data.len() % 4 != 0 {
                bail!("must write in units of 4 bytes");
            }

            boot.do_write_memory(address, &data)?;
        }
        SubCmd::GlobalErase => {
            let (_, commands) = boot.do_get()
                .with_context(|| format!("checking command support"))?;

            if commands[Cmd::EraseMemory] {
                boot.do_erase_memory_global()?;
            } else if commands[Cmd::ExtendedEraseMemory] {
                boot.do_extended_erase_memory_global()?;
            } else {
                bail!("device does not report any supported erase memory commands");
            }

        }
        SubCmd::RawEraseMemory { pages } => {
            boot.require_cmd(Cmd::EraseMemory)?;

            boot.do_erase_memory(&pages)?;
        }
        SubCmd::RawExtendedEraseMemory { pages } => {
            boot.require_cmd(Cmd::ExtendedEraseMemory)?;

            boot.do_extended_erase_memory(&pages)?;
        }
        SubCmd::GetChecksum { address, words, polynomial, initial } => {
            boot.require_cmd(Cmd::GetChecksum)?;

            let crc32 = boot.do_get_checksum(address, words, polynomial, initial)?;
            println!("{crc32:#08x}");
        }
        SubCmd::Go { vector_address } => {
            boot.require_cmd(Cmd::Go)?;

            if args.verbose {
                println!("activating program from vector table at {vector_address:#x}");
                if boot.require_cmd(Cmd::ReadMemory).is_ok() {
                    let mut buffer = [0; 8];
                    match boot.do_read_memory(vector_address, &mut buffer) {
                        Ok(()) => {
                            let stack_pointer = u32::from_le_bytes(buffer[..4].try_into().unwrap());
                            let reset_vector = u32::from_le_bytes(buffer[4..].try_into().unwrap());
                            println!("- initial stack pointer: {stack_pointer:#x}");
                            println!("- initial entry point:   {reset_vector:#x}");
                        }
                        Err(e) => {
                            println!("failed to read vector table to print it:");
                            println!("{e:?}");
                        }
                    }
                } else {
                    println!("(can't read vector table to print it)");
                }
            }

            boot.do_go(vector_address)?;
            println!("program activated");
        }
    }

    Ok(())
}

fn do_verify(
    boot: &mut Boot,
    data: &[u8],
    address: u32,
    verbose: bool,
) -> Result<()> {
    println!("reading {} bytes to verify...", data.len());
    let bar = ProgressBar::new(data.len() as u64);
    let mut buf = [0; 256];
    let mut issues = 0_usize;
    for (i, chunk) in data.chunks(256).enumerate() {
        let chunk_addr = address + i as u32 * 256;
        let buf = &mut buf[..chunk.len()];
        boot.do_read_memory(chunk_addr, buf)?;
        for (o, (expected, got)) in chunk.iter().zip(buf).enumerate() {
            if expected != got {
                let byte_addr = chunk_addr + o as u32;
                issues += 1;
                if verbose {
                    println!("mismatch at {byte_addr:08x}: expected {expected:#x}, got {got:#x}");
                }
            }
        }
        bar.inc(chunk.len() as u64);
    }
    bar.finish();
    if issues != 0 {
        bail!("memory contents failed to match at {issues} addresses");
    }
    Ok(())
}

struct Boot(Box<dyn SerialPort>);

impl Boot {
    fn drain(&mut self) -> Result<()> {
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
            println!("note: {cruft} bytes of cruft drained from serial port");
        }

        Ok(())
    }

    fn poke(&mut self) -> Result<()> {
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
            Err(e) => return Err(e).context("reading poke response"),
        };
        self.0.set_timeout(saved_timeout)?;
        if response == 0x79 {
            Ok(())
        } else if response == 0x1f {
            // it's already in command processing. This is a NACK. Tolerate it.
            Ok(())
        } else {
            Err(anyhow!("bad ack: {response:#x}"))
        }
    }

    fn send_with_check_base(&mut self, base: u8, data: &[u8]) -> Result<()> {
        let check = data.iter().fold(base, |x, byte| x ^ *byte);
        self.0.write_all(data)?;
        self.0.write_all(std::slice::from_ref(&check))?;
        Ok(())
    }

    fn send_with_check(&mut self, data: &[u8]) -> Result<()> {
        self.send_with_check_base(0xFF, data)
    }

    fn send_with_check_inv(&mut self, data: &[u8]) -> Result<()> {
        self.send_with_check_base(0, data)
    }

    fn send_cmd(&mut self, cmd: Cmd) -> Result<()> {
        self.send_with_check(&[cmd as u8])
            .with_context(|| format!("failed to transmit command {cmd:?}"))?;
        self.get_ack()
            .with_context(|| format!("failed to issue command {cmd:?}"))?;
        Ok(())
    }

    fn get_ack(&mut self) -> Result<()> {
        let mut response = 0;
        self.0.read_exact(std::slice::from_mut(&mut response))?;
        match response {
            0x79 => Ok(()),
            0x1F => Err(anyhow!("received NACK")),
            _ => Err(anyhow!("expected ACK or NACK, got: {response:#x}")),
        }
    }

    fn do_get(&mut self) -> Result<(u8, EnumMap<Cmd, bool>)> {
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

    fn require_cmd(&mut self, cmd: Cmd) -> Result<()> {
        let (_, commands) = self.do_get()
            .with_context(|| format!("can't determine if command {cmd:?} is supported"))?;
        if commands[cmd] {
            Ok(())
        } else {
            bail!("command {cmd:?} not supported by device");
        }
    }

    fn do_get_id(&mut self) -> Result<Pid> {
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

    fn do_read_memory(&mut self, address: u32, dest: &mut [u8]) -> Result<()> {
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

    fn do_write_memory(&mut self, address: u32, src: &[u8]) -> Result<()> {
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

    fn do_erase_memory(&mut self, pages: &[u8]) -> Result<()> {
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

    fn do_erase_memory_global(&mut self) -> Result<()> {
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

    fn do_extended_erase_memory(&mut self, pages: &[u16]) -> Result<()> {
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

    fn do_extended_erase_memory_global(&mut self) -> Result<()> {
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

    fn do_get_checksum(&mut self, address: u32, words: u32, polynomial: u32, initial: u32) -> Result<u32> {
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
            bail!("computed checksum {rxcrc:#x} does not match {checksum:#x}");
        }

        Ok(crc32)
    }

    fn do_go(&mut self, address: u32) -> Result<()> {
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
}

fn context_scope<T, C>(
    body: impl FnOnce() -> Result<T>,
    context_provider: impl FnOnce() -> C,
) -> Result<T>
    where C: Display + Send + Sync + 'static,
{
    body().with_context(context_provider)
}

enum Pid {
    Stm32(Stm32Kind),
    Other(Vec<u8>),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive)]
#[allow(non_camel_case_types)]
enum Stm32Kind {
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
    fn bootloader_id_address(self) -> u32 {
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
enum Stm32PreciseKind {
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, FromPrimitive, enum_map::Enum)]
enum Cmd {
    Get = 0x00,
    GetId = 0x02,
    ReadMemory = 0x11,
    Go = 0x21,
    WriteMemory = 0x31,
    EraseMemory = 0x43,
    ExtendedEraseMemory = 0x44,
    GetChecksum = 0xA1,
}

bitflags::bitflags! {
    #[derive(Debug)]
    struct Ifaces: u32 {
        const USART = 1 << 0;
        const SECOND_USART = 1 << 1;
        const CAN = 1 << 2;
        const DFU = 1 << 3;
        const I2C = 1 << 4;
        const SPI = 1 << 5;
        const I3C = 1 << 6;
    }
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
