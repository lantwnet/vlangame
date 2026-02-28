use clap::Parser;
use env_logger::Env;
use vlangame_client::client::{ClientConfig, start};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// 地址和掩码，不指定则服务端生成
    /// example: --local 10.26.0.2/24
    #[arg(short, long)]
    local: Option<String>,
    /// 虚拟网卡名称
    #[arg(short, long)]
    tun_name: Option<String>,
    /// 服务器地址
    #[arg(short, long)]
    server: String,
    /// 转发服务器地址，不填时使用--server的值
    #[arg(long)]
    turn_server: Vec<String>,
    /// 是否开启打洞
    #[arg(short, long, default_value_t = false)]
    enable_nat_punch: bool,
    /// 使用windivert
    #[arg(short, long, default_value_t = false)]
    #[cfg(windows)]
    use_windivert: bool,
}

fn main() {
    main0();
}

#[tokio::main]
async fn main0() {
    let args = Args::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = ClientConfig {
        local: args.local,
        tun_name: args.tun_name,
        server: args.server,
        turn_server: args.turn_server,
        enable_nat_punch: args.enable_nat_punch,
        #[cfg(windows)]
        use_windivert: args.use_windivert,
    };
    let handle = match start(config).await {
        Ok(h) => h,
        Err(e) => {
            log::error!("start failed: {e:?}");
            return;
        }
    };
    tokio::signal::ctrl_c().await.unwrap();
    log::info!("shutting down");
    handle.shutdown();
}
