mod client;
mod server;
mod protocol;
mod config;

use std::env;
use log::error;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 2 {
        error!("Usege: {} [client | server]", args[0]);
    }

    match args[1].as_str() {
        "client" => client::run(),
        "server" => server::run(),
        _ => error!("Invalid option. Use 'client' or 'server'"),
    }
}
