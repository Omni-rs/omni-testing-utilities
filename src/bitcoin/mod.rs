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
