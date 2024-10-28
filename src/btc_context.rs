use bitcoin::bip32::DerivationPath;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{bip32::Xpriv, Address, Network, ScriptBuf};
use bitcoin::{CompressedPublicKey, PublicKey as BitcoinPublicKey, WPubkeyHash};
use bitcoind::AddressType;
use serde_json::{json, Value};
use std::str::FromStr as _;

pub struct UserInfo {
    pub address: Address,
    pub script_pubkey: ScriptBuf,
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub compressed_public_key: CompressedPublicKey,
    pub bitcoin_public_key: BitcoinPublicKey,
    pub wpkh: WPubkeyHash,
}

pub struct BTCTestContext<'a> {
    client: &'a bitcoind::Client,
    master_key_p2pkh: Xpriv,
    master_key_p2wpkh: Xpriv,
}

impl<'a> BTCTestContext<'a> {
    pub fn new(client: &'a bitcoind::Client) -> Result<Self, Box<dyn std::error::Error>> {
        let master_key_p2pkh = Self::get_master_key_of_regtest_node_p2pkh(client)?;
        let master_key_p2wpkh = Self::get_master_key_of_regtest_node_p2wpkh(client)?;

        Ok(BTCTestContext {
            client,
            master_key_p2pkh,
            master_key_p2wpkh,
        })
    }

    pub fn setup_account(
        &self,
        address_type: AddressType,
    ) -> Result<UserInfo, Box<dyn std::error::Error>> {
        let address = self
            .client
            .get_new_address_with_type(address_type.clone())
            .unwrap()
            .address()
            .unwrap();

        let address = address.require_network(Network::Regtest).unwrap();

        // Get address info for Account
        let address_info: Value = self
            .client
            .call("getaddressinfo", &[address.to_string().into()])?;

        // Extract the pubkey from the address info
        let pubkey_hex = address_info["pubkey"]
            .as_str()
            .expect("pubkey should be a string");

        let compressed_pub_key =
            CompressedPublicKey::from_str(pubkey_hex).expect("Failed to parse pubkey");

        // Extract the scriptPubKey from the address info
        let script_pubkey_hex = address_info["scriptPubKey"]
            .as_str()
            .expect("scriptPubKey should be a string");

        let script_pubkey =
            ScriptBuf::from_hex(script_pubkey_hex).expect("Failed to parse scriptPubKey");

        // Initialize secp256k1 context
        let secp = Secp256k1::new();

        // Derive child private key using path m/44h/1h/0h
        let hd_key_path = address_info["hdkeypath"].as_str().unwrap();
        let path = DerivationPath::from_str(hd_key_path).unwrap();

        let child = if address_type == AddressType::Bech32 {
            self.master_key_p2wpkh.derive_priv(&secp, &path).unwrap()
        } else {
            self.master_key_p2pkh.derive_priv(&secp, &path).unwrap()
        };

        let private_key = child.private_key;
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        let bitcoin_public_key = BitcoinPublicKey::new(public_key);

        let derived_address = if address_type == AddressType::Bech32 {
            Address::p2wpkh(&compressed_pub_key, Network::Regtest)
        } else {
            Address::p2pkh(compressed_pub_key, Network::Regtest)
        };

        assert_eq!(
            bitcoin_public_key.to_string(),
            pubkey_hex,
            "Derived public key does not match the one provided by the node"
        );
        // Verify that the address is the same as the one generated by the client
        assert_eq!(address, derived_address);

        let wpkh: WPubkeyHash = bitcoin_public_key
            .wpubkey_hash()
            .expect("Failed to compute WPubkeyHash: ensure the key is compressed");

        Ok(UserInfo {
            address,
            script_pubkey,
            private_key,
            public_key,
            bitcoin_public_key,
            wpkh,
            compressed_public_key: compressed_pub_key,
        })
    }

    fn get_master_key_of_regtest_node_p2pkh(
        client: &bitcoind::Client,
    ) -> Result<Xpriv, Box<dyn std::error::Error>> {
        let descriptors: Value = client.call("listdescriptors", &[true.into()])?;

        let p2pkh_descriptor = descriptors["descriptors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|descriptor| descriptor["desc"].as_str().unwrap().contains("pkh"))
            .expect("No P2PKH descriptor found");

        let desc = p2pkh_descriptor["desc"].as_str().unwrap();
        let parts: Vec<&str> = desc.split('/').collect();
        let master_key_str = parts[0].replace("pkh(", "").replace(")", "");

        let master_key = Xpriv::from_str(&master_key_str).unwrap();

        Ok(master_key)
    }

    fn get_master_key_of_regtest_node_p2wpkh(
        client: &bitcoind::Client,
    ) -> Result<Xpriv, Box<dyn std::error::Error>> {
        let descriptors: Value = client.call("listdescriptors", &[true.into()])?;

        let p2wpkh_descriptor = descriptors["descriptors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|descriptor| {
                let desc = descriptor["desc"].as_str().unwrap();
                desc.contains("wpkh") && !desc.starts_with("tr(") // Exclude descriptors for taproot
            })
            .expect("No P2WPKH or nested P2WPKH descriptor found");

        let desc = p2wpkh_descriptor["desc"].as_str().unwrap();

        // Extract the xpriv part from the descriptor
        let xpriv_part = desc
            .split("wpkh(")
            .nth(1)
            .unwrap()
            .split(')')
            .next()
            .unwrap();
        let parts: Vec<&str> = xpriv_part.split('/').collect();
        let master_key_str = parts[0];

        // Ensure the key starts with "tprv" for testnet/regtest
        let master_key_str = if !master_key_str.starts_with("tprv") {
            format!("tprv{}", master_key_str)
        } else {
            master_key_str.to_string()
        };

        let master_key = Xpriv::from_str(&master_key_str)?;

        Ok(master_key)
    }

    pub fn get_utxo_for_address(
        &self,
        address: &Address,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let min_conf = 1;
        let max_conf = 9999999;
        let include_unsafe = true;
        let query_options = json!({});

        let unspent_utxos: Vec<serde_json::Value> = self.client.call(
            "listunspent",
            &[
                json!(min_conf),
                json!(max_conf),
                json!(vec![address.to_string()]),
                json!(include_unsafe),
                query_options,
            ],
        )?;

        // Verify UTXO belongs to the address and has the correct amount
        for utxo in unspent_utxos.iter() {
            assert_eq!(
                utxo["address"].as_str().unwrap(),
                address.to_string(),
                "UTXO doesn't belong to the address"
            );
        }

        Ok(unspent_utxos)
    }
}
