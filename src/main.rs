use std::fs;
use std::io;
use std::str;
use std::env;
use std::io::Write;
use std::path::Path;
use aes::Aes128;
use serde_json::{ Value };
use block_modes::{ BlockMode, Cbc };
use block_modes::block_padding::Pkcs7;
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

/**
* println!("Ciphertext: {:?}", hex::encode(encrypt(cipher.clone(), "Hello world!".as_bytes().to_vec()).expect("Encryption error")));
*/
fn encrypt(cipher: Aes128Cbc, plaintext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let pos = plaintext.len();
    let mut buffer = [0u8; 128];
    buffer[..pos].copy_from_slice(&plaintext);
    let ciphertext = cipher.encrypt(&mut buffer, pos).map_err(|_| "Encryption failed")?;
    Ok(ciphertext.to_vec())
}

/*
* println!("Decrypted Text: {:?}", String::from_utf8(decrypt(cipher.clone(), encrypt(cipher.clone(), "Hello world!".as_bytes().to_vec()).expect("Encryption error")).expect("Decryption error")).map_err(|_| "Invalid UTF-8"));
*/
fn decrypt(cipher: Aes128Cbc, ciphertext: Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let mut buffer = ciphertext;
    let decrypted = cipher.decrypt(&mut buffer).map_err(|_| "Decryption failed")?;
    Ok(decrypted.to_vec())
}

fn main() {
    let mut iv_str = String::from("00000000000000000000000000000000");
    let mut key_str = String::from("babb4a9f774ab853c96c2d653dfe544a");

    let args: Vec<String> = env::args().collect();
    let mut config_path = String::new();
    let mut interaction = false;

    if args.len() < 2 || args[1].is_empty() {
        interaction = true;
        println!("One-liner: DBeaverPasswordViewer path_of_credentials-config.json[#name_of_connection] [iv] [key]");
        print!("Please typing the full path of the credentials-config.json file: ");
        io::stdout().flush().unwrap();
        io::stdin().read_line(&mut config_path).unwrap();
        config_path = config_path.trim().to_string();
    } else {
        config_path = args[1].clone();
    }

    let config_path_extension_pos = config_path.rfind(".json").unwrap_or_else(|| {
        panic!("No '.json' extension found in the path string.");
    });

    let hash_pos = config_path[config_path_extension_pos..].find('#').map(|p| p + config_path_extension_pos).unwrap_or_else(|| {
        config_path.len()
    });

    let file_path = &config_path[..hash_pos];
    let fragment = if hash_pos < config_path.len() {
        Some(&config_path[hash_pos + 1..])
    } else {
        None
    };

    if args.len() > 2 {
        iv_str = args[2].clone();
    }
    if args.len() > 3 {
        key_str = args[3].clone();
    }

    let credentials_config_path = Path::new(&file_path);
    let iv = hex::decode(iv_str).expect("Decoding failed");
    let key = hex::decode(key_str).expect("Decoding failed");
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).expect("Invalid key or IV size");
    let credentials_json_value: Value = serde_json::from_str(&String::from_utf8_lossy(&(decrypt(cipher.clone(), fs::read(credentials_config_path).unwrap()).expect("Decryption error"))[16..])).unwrap();

    let data_sources_path = credentials_config_path.parent().unwrap().join("data-sources.json");
    if !(data_sources_path.exists()) {
        println!("{}", serde_json::to_string_pretty(&credentials_json_value).unwrap());
    } else {
        let mut data_sources_json_value: Value = serde_json::from_slice(&(fs::read(data_sources_path).unwrap())[..]).unwrap();
        if let Some(connections_value) = data_sources_json_value.get_mut("connections") {
            if let Some(connections_object) = connections_value.as_object_mut() {
                for (key, value) in connections_object.iter_mut() {
                    if let Some(password_value) = credentials_json_value.get(key) {
                        value.as_object_mut().unwrap().insert("credential".to_string(), password_value.clone());
                    }
                    if let Some(name_value) = value.get("name") {
                        if let Some(fragment_value) = fragment {
                            if name_value == fragment_value {
                                println!("{}", serde_json::to_string_pretty(&value).unwrap());
                                break;
                            }
                        }
                    }
                }
                if let None = fragment {
                    println!("{}", serde_json::to_string_pretty(&connections_object).unwrap());
                }
            }
        }
    }

    if interaction {
        print!("\nPress any key to exit...");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
    }
}
