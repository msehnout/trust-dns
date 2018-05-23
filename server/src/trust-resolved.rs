extern crate clap;
extern crate futures;
#[macro_use]
extern crate log;
extern crate tokio;
extern crate tokio_tcp;
extern crate tokio_udp;
extern crate trust_dns;
extern crate trust_dns_server;
extern crate trust_dns_resolver;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

use clap::{App, Arg, ArgMatches};
use futures::{Future, future};
use tokio::runtime::current_thread::Runtime;
use tokio_tcp::TcpListener;
use tokio_udp::UdpSocket;

use trust_dns_server::authority::{Authority, Catalog, Journal, ZoneType};
use trust_dns_server::logger;
use trust_dns_server::server::ServerFuture;
use trust_dns_server::resolver::Resolver;

fn main() {
    let matches = App::new("Trust-DNS Resolver")
        .version("0.1")
        .author("Foo Bar <FooBar@gmail.com>")
        .about("Resolve your DNS queries")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("FILE")
            .help("Sets a custom config file")
            .takes_value(true))
        .arg(Arg::with_name("address")
            .short("a")
            .long("address")
            .value_name("ADDR")
            .help("Sets the interface to listen on")
            .takes_value(true))
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .get_matches();

    logger::debug();
    let addr = matches.value_of("address").unwrap_or("127.0.0.1");
    let sockaddrs: Vec<SocketAddr> = (addr, 53535).to_socket_addrs().unwrap().collect();
    println!("Listen on: {:?}", sockaddrs);
    let udp_sockets: Vec<UdpSocket> = sockaddrs
        .iter()
        .map(|x| {
            UdpSocket::bind(x).expect(&format!("could not bind to udp: {}", x))
        })
        .collect();
    let tcp_listeners: Vec<TcpListener> = sockaddrs
        .iter()
        .map(|x| {
            TcpListener::bind(x).expect(&format!("could not bind to tcp: {}", x))
        })
        .collect();

    let tcp_request_timeout = std::time::Duration::from_secs(5);
    let mut io_loop = Runtime::new().expect("error when creating tokio Runtime");

    let resolver = Resolver::new();
    // now, run the server, based on the config
    let mut server = ServerFuture::new(resolver);

    let server_future : Box<Future<Item=(), Error=()> + Send> = Box::new(future::lazy(move ||{
        // load all the listeners
        for udp_socket in udp_sockets {
            info!("listening for UDP on {:?}", udp_socket);
            server.register_socket(udp_socket);
        }

        // and TCP as necessary
        for tcp_listener in tcp_listeners {
            info!("listening for TCP on {:?}", tcp_listener);
            server
                .register_listener(tcp_listener, tcp_request_timeout)
                .expect("could not register TCP listener");
        }

        // config complete, starting!
        info!("awaiting connections...");

        /// TODO: how to do threads? should we do a bunch of listener threads and then query threads?
        /// Ideally the processing would be n-threads for recieving, which hand off to m-threads for
        ///  request handling. It would generally be the case that n <= m.
        info!("Server starting up");
        future::empty()
    }));

    if let Err(e) = io_loop.block_on(server_future.map_err(|_| io::Error::new(
        io::ErrorKind::Interrupted,
        "Server stopping due to interruption",
    ))) {
        error!("failed to listen: {}", e);
    }


    // we're exiting for some reason...
    info!("Trust-DNS {} stopping", trust_dns::version());

}