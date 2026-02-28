use clap::Parser;
use env_logger::Env;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use vlangame_server::server::{AppInfo, NetServer};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// bind address
    #[clap(short, long)]
    address: Option<SocketAddr>,
    /// --net  10.25.0.0/16
    /// default 10.25.0.0/16
    #[clap(short, long)]
    net: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let net = args.net.unwrap_or("10.25.0.0/16".to_string());
    let mut split = net.split('/');
    let network = Ipv4Addr::from_str(split.next().expect("--local error")).expect("--local error");
    let mask = u8::from_str(split.next().expect("--local error")).expect("--local error");
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let bind_addr = args
        .address
        .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 12345)));
    log::info!("Listening on: {}", bind_addr);
    let app_info = AppInfo { network, mask };
    NetServer::new(app_info).start(bind_addr).await.unwrap();
}
