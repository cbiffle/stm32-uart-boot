//! A command-line tool for interacting with the built-in UART bootloader on
//! most STM32 parts.
//!
//! This tool provides two kinds of commands, low-level and high-level. Where it
//! makes sense to have both kinds of commands for a single concept, the
//! low-level one is typically prefixed with `raw-`.

use std::{time::Duration, path::PathBuf, collections::BTreeMap};

use anyhow::{Context, Result, bail, anyhow};
use enum_map::Enum;
use indicatif::ProgressBar;
use serialport::Parity;
use clap::Parser;
use stm32_uart_boot::{Boot, Cmd, Pid};

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
    /// High-level command for loading a chip from a variety of file formats.
    ///
    /// Currently this implies a global erase of the chip, for simplicity.
    Load {
        /// Input file in ELF or raw BIN format. This will be attempted as ELF
        /// first; if that fails, we'll assume it's BIN. To override this logic
        /// pass -f/--format explicitly.
        filename: PathBuf,

        /// Force interpretation of the input file in a particular file format.
        #[clap(short, long)]
        format: Option<FileFormat>,

        /// Provide a load address for the image. This is required for file
        /// formats that don't have address information (primarily .bin).
        /// If the file contains address information, providing this is an
        /// error because it's not clear what to do.
        #[clap(short, long, value_parser = parse_int::parse::<u32>)]
        address: Option<u32>,

        /// Verify contents after writing.
        #[clap(long)]
        verify: bool,
    },
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

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum FileFormat {
    Binary,
    Elf,
}

fn main() -> Result<()> {
    let args = BootTool::parse();

    let mut boot = Boot::new(serialport::new(&args.port, args.baud_rate)
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
            let info = boot.info()?;
            let (major, minor) = info.version;
            println!("Protocol version: {major}.{minor}");
            println!("Known commands supported:");
            for i in 0..Cmd::LENGTH {
                let c = <Cmd as Enum>::from_usize(i);
                let f = if info.command_support[c] { "YES" } else { "no" };
                println!("{:24} {f}", format!("{c:?}"));
            }

            if let Some(pid) = info.product_id {
                match pid {
                    Pid::Stm32(kind) => println!("STM32: {kind:?}"),
                    Pid::Other(bytes) => println!("unknown: {bytes:?}"),
                }
            } else {
                println!("Product ID unsupported.");
            }

            if let Some(ifaces) = info.bootloader_interfaces {
                print!("Bootloader interfaces: ");
                for (i, _) in ifaces.iter_names() {
                    print!(" {i}");
                }
                println!();
            }
            if let Some(v) = info.bootloader_version {
                println!("Bootloader version: {v}");
            }
        }
        SubCmd::Load { filename, format, address, verify } => {
            let image = std::fs::read(&filename)
                .with_context(|| format!("reading image file {}", filename.display()))?;
            let (segments, used_address) = match format {
                Some(FileFormat::Binary) => load_binary(&image, address)?,
                Some(FileFormat::Elf) => load_elf(&image)?,
                None => load_auto(&image, address)?,
            };
            if !used_address && address.is_some() {
                bail!("Flag -a/--address is not valid for this file format.");
            }

            let segments = merge_adjacent(segments);
            if args.verbose {
                println!("Segment map after merge:");
                for (address, segment) in &segments {
                    println!("  {address:08x}: {} bytes", segment.len());
                }
            }

            for (address, segment) in &segments {
                if segment.len() % 4 != 0 {
                    bail!("STM32 will only accept data written in units of \
                        4 bytes; segment at {address:#x} is {} bytes long",
                        segment.len());
                }
            }
            
            let info = boot.info()
                .context("checking command support")?;

            boot.drain()?;

            println!("Erasing...");
            if info.command_support[Cmd::EraseMemory] {
                boot.do_erase_memory_global()?;
            } else if info.command_support[Cmd::ExtendedEraseMemory] {
                boot.do_extended_erase_memory_global()?;
            } else {
                bail!("device does not report any supported erase memory commands");
            }

            if segments.len() != 1 {
                println!("Writing {} segments...", segments.len());
            }
            for (&address, segment) in &segments {
                do_write(&mut boot, &segment, address, verify, args.verbose)?;
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
            let mut buffer = [0u8; 256];
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

            do_write(&mut boot, &data, address, verify, args.verbose)?;
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
            let info = boot.info()
                .context("checking command support")?;

            if info.command_support[Cmd::EraseMemory] {
                boot.do_erase_memory_global()?;
            } else if info.command_support[Cmd::ExtendedEraseMemory] {
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

fn load_binary(
    image: &[u8],
    address: Option<u32>,
) -> Result<(BTreeMap<u32, Vec<u8>>, bool)> {
    let address = address.ok_or_else(|| anyhow!("Must provide -a/--address flag for .bin file"))?;
    Ok(([(address, image.to_vec())].into_iter().collect(), true))
}

fn load_elf(
    image: &[u8],
) -> Result<(BTreeMap<u32, Vec<u8>>, bool)> {
    use goblin::elf::Elf;
    let elf = Elf::parse(image)?;

    let mut segments = BTreeMap::new();
    for ph in &elf.program_headers {
        if ph.p_type == goblin::elf::program_header::PT_LOAD {
            // A thing that should actually be written!
            let fr = ph.file_range();
            if let Some(bytes) = image.get(fr.clone()) {
                if bytes.is_empty() {
                    // Skip empty ranges.
                    continue;
                }

                let loadaddr = u32::try_from(ph.p_paddr)
                    .with_context(|| format!("PhysAddr {:08x} won't fit in u32", ph.p_paddr))?;

                segments.insert(loadaddr, bytes.to_vec());
            } else {
                bail!("ELF PHDR references range {fr:?} but file is only {} bytes long",
                    image.len());
            }
        }
    }

    Ok((segments, false))
}

fn load_auto(
    image: &[u8],
    address: Option<u32>,
) -> Result<(BTreeMap<u32, Vec<u8>>, bool)> {
    let elf_err = match load_elf(&image) {
        Ok(s) => {
            println!("Detected ELF format.");
            return Ok(s);
        }
        Err(e) => e,
    };
    let bin_err = match load_binary(&image, address) {
        Ok(s) => {
            println!("Loaded as raw BIN file.");
            return Ok(s);
        }
        Err(e) => e,
    };

    bail!("Unable to load file as any format.\n\
            As ELF: {elf_err}\n\
            As BIN: {bin_err}")
}

fn merge_adjacent(segments: BTreeMap<u32, Vec<u8>>) -> BTreeMap<u32, Vec<u8>> {
    let mut output: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut last_end = None;
    for (address, data) in segments {
        let n = data.len();
        if last_end == Some(address) {
            output.last_entry().unwrap().get_mut().extend_from_slice(&data[..]);
        } else {
            output.insert(address, data);
        }
        last_end = Some(address + u32::try_from(n).unwrap());
    }
    output
}

fn do_write(
    boot: &mut Boot,
    data: &[u8],
    address: u32,
    verify: bool,
    verbose: bool,
) -> Result<()> {
    println!("writing {} bytes...", data.len());
    let bar = ProgressBar::new(data.len() as u64);
    for (i, chunk) in data.chunks(256).enumerate() {
        let chunk_addr = address + i as u32 * 256;
        boot.do_write_memory(chunk_addr, chunk)?;
        bar.inc(chunk.len() as u64);
    }
    bar.finish();

    if verify {
        do_verify(boot, &data, address, verbose)?;
        println!("OK: matches what was intended");
    }
    Ok(())
}
