use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{MapRefMut, PerfEventArray};
use aya::programs::{tc, Link, SchedClassifier, TcAttachType};
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;
use clap::{crate_authors, crate_description, crate_version, App, Arg, SubCommand};
use lazy_static::lazy_static;
use mio::unix::SourceFd;
use mio::{Events, Interest, Token};
use pnet::datalink::{Channel, NetworkInterface};
use slog::{crit, debug, o, warn, Drain, Logger};
use slog_term::TermDecorator;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

lazy_static! {
    static ref LOGGER: Logger = Logger::root(
        slog_async::Async::new(
            slog_term::FullFormat::new(TermDecorator::new().build())
                .build()
                .fuse(),
        )
        .build()
        .fuse(),
        o!()
    );
}

fn poll_buffers(buf: Vec<PerfEventArrayBuffer<MapRefMut>>) {
    let mut poll = mio::Poll::new().unwrap();

    let mut out_bufs = [BytesMut::with_capacity(1024)];

    let mut tokens: HashMap<Token, PerfEventArrayBuffer<MapRefMut>> = buf
        .into_iter()
        .map(
            |p| -> Result<(Token, PerfEventArrayBuffer<MapRefMut>), Box<dyn Error>> {
                let token = Token(p.as_raw_fd() as usize);
                poll.registry().register(
                    &mut SourceFd(&p.as_raw_fd()),
                    token,
                    Interest::READABLE,
                )?;
                Ok((token, p))
            },
        )
        .collect::<Result<HashMap<Token, PerfEventArrayBuffer<MapRefMut>>, Box<dyn Error>>>()
        .unwrap();

    let mut events = Events::with_capacity(1024);
    loop {
        match poll.poll(&mut events, Some(Duration::from_millis(100))) {
            Ok(_) => {
                let token_list: Vec<Token> = events
                    .iter()
                    .filter(|event| event.is_readable())
                    .map(|e| e.token())
                    .collect();
                token_list.into_iter().for_each(|t| {
                    let buf = tokens.get_mut(&t).unwrap();
                    buf.read_events(&mut out_bufs).unwrap();
                    debug!(LOGGER, "buf: {:?}", out_bufs.get(0).unwrap());
                });
            }
            Err(e) => {
                crit!(LOGGER, "critical error: {:?}", e);
                panic!()
            }
        }
    }
}

fn load_filter(interface_name: &str) -> Result<(), Box<dyn Error>> {
    let mut bpf = Bpf::load_file("bpf/filter_program_x86_64")?;
    if let Err(e) = tc::qdisc_add_clsact(interface_name) {
        warn!(LOGGER, "Interface already configured: {:?}", e);
    }

    let prog: &mut SchedClassifier = bpf.program_mut("dns_apply_message")?.try_into()?;
    prog.load()?;
    let mut linkref = prog.attach(interface_name, TcAttachType::Egress)?;
    debug!(LOGGER, "DNS filter loaded and attached.");

    let mut perf_array = PerfEventArray::try_from(bpf.map_mut("dns_filter_events")?)?;

    let mut perf_buffers = Vec::new();
    for cpuid in online_cpus()? {
        perf_buffers.push(perf_array.open(cpuid, None)?);
    }

    // poll the buffers to know when they have queued events
    poll_buffers(perf_buffers);

    linkref.detach()?;

    debug!(LOGGER, "DNS filter detached.");

    Ok(())
}

fn run_client(interface: &str) {
    let mut pnet_iface: NetworkInterface = NetworkInterface {
        name: "none".to_string(),
        description: "".to_string(),
        index: 0,
        mac: None,
        ips: vec![],
        flags: 0,
    };

    for iface in pnet::datalink::interfaces() {
        if iface.name.eq(interface) {
            pnet_iface = iface;
            break;
        }
    }

    if pnet_iface.name.eq("nonexistent") {
        panic!("could not find interface: {}", interface);
    }

    let (_tx, mut rx) = match pnet::datalink::channel(&pnet_iface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type"),
        Err(e) => panic!("err: {}", e),
    };

    println!("Listening on {}", pnet_iface.name);

    loop {
        let packet = rx.next().unwrap();
        let eth = pnet::packet::ethernet::EthernetPacket::new(packet).unwrap();
        if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
            continue;
        }
        let udp_packet = match pnet::packet::udp::UdpPacket::new(
            &packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..],
        ) {
            Some(pkt) => pkt,
            None => continue,
        };

        if udp_packet.get_destination() == 53 {
            let payload = &packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN)..];
            let mut msg = String::new();
            for b in payload[13..].iter() {
                match char::from_u32(*b as u32) {
                    Some(ch) => {
                        if ch >= 8 as char {
                            msg.push(ch);
                        } else {
                            break;
                        }
                    }
                    None => break,
                }
            }
            let msg = String::from_utf8(base64::decode(msg).unwrap()).unwrap();
            print!("{}", msg.trim_end_matches('\n'));
        }
        std::io::stdout().flush().unwrap();
    }
}

fn main() {
    let matches = App::new("dnpf")
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .subcommand(
            SubCommand::with_name("client")
                .about("receive information from the server")
                .arg(
                    Arg::with_name("interface")
                        .short("i")
                        .long("interface")
                        .help("the interface to intercept and modify communications on")
                        .takes_value(true)
                        .required(true)
                        .value_name("INTERFACE NAME"),
                ),
        )
        .subcommand(
            SubCommand::with_name("server")
                .about("send information to the client")
                .arg(
                    Arg::with_name("interface")
                        .short("i")
                        .long("interface")
                        .help("the interface to intercept and modify communications on")
                        .takes_value(true)
                        .required(true)
                        .value_name("INTERFACE NAME"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("server") {
        debug!(LOGGER, "Starting dnpf server.");
        let interface = matches.value_of("interface").unwrap();
        load_filter(interface).unwrap();
    } else if let Some(matches) = matches.subcommand_matches("client") {
        let interface = matches.value_of("interface").unwrap();
        run_client(interface);
    } else {
        println!("Please specify `client` or `server`.");
    }
}
