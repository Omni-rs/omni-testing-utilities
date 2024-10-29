pub fn get_bitcoin_instance() -> Result<bitcoind::BitcoinD, Box<dyn std::error::Error>> {
    if let Ok(exe_path) = bitcoind::exe_path() {
        let bitcoind = bitcoind::BitcoinD::new(exe_path).unwrap();
        assert_eq!(0, bitcoind.client.get_blockchain_info().unwrap().blocks);
        Ok(bitcoind)
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "BitcoinD executable not found",
        )))
    }
}

mod btc_context;

pub use btc_context::*;

// TODO: FIX THIS

// fn setup_bitcoin_testnet() -> Result<bitcoind::BitcoinD> {
//     if std::env::var("CI_ENVIRONMENT").is_ok() {
//         let curr_dir_path = std::env::current_dir().unwrap();

//         let bitcoind_path = if cfg!(target_os = "macos") {
//             curr_dir_path.join("tests/bin").join("bitcoind-mac")
//         } else if cfg!(target_os = "linux") {
//             curr_dir_path.join("tests/bin").join("bitcoind-linux")
//         } else {
//             return Err(
//                 std::io::Error::new(std::io::ErrorKind::Other, "Unsupported platform").into(),
//             );
//         };

//         let temp_dir = TempDir::new().expect("Failed to create temp dir");

//         let mut conf = bitcoind::Conf::default();
//         conf.tmpdir = Some(temp_dir.path().to_path_buf());
//         let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_path, &conf).unwrap();
//         Ok(bitcoind)
//     } else {
//         let bitcoind = bitcoind::BitcoinD::from_downloaded().unwrap();
//         Ok(bitcoind)
//     }
// }
