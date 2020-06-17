extern crate electrum_client;
extern crate bitcoin;
extern crate hex;

use electrum_client::{Client, GetMerkleRes};
use bitcoin::blockdata::constants::{genesis_block, DIFFCHANGE_INTERVAL, DIFFCHANGE_TIMESPAN, max_target};
use bitcoin::{Network, BitcoinHash, BlockHeader};
use bitcoin::util::uint::Uint256;
use std::path::PathBuf;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Write, Cursor, Seek, SeekFrom, Read};
use bitcoin::consensus::{serialize, deserialize};
use bitcoin::network::message::NetworkMessage::Block;
use bitcoin::consensus::{Decodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::hashes::{sha256d, sha256};
use bitcoin::Txid;

#[derive(Debug)]
struct HeadersChain {
    path: PathBuf,
    height: u32,
    last: BlockHeader,
}

impl HeadersChain {
    fn new(path: PathBuf, network: Network) -> HeadersChain {
        if !path.exists() {
            let last= genesis_block(network).header;
            let mut file = File::create(&path).unwrap();
            file.write_all(&serialize(&last));
            let height = 0;

            HeadersChain {
                path, height, last,
            }
        } else {
            let file_size = fs::metadata(&path).unwrap().len();
            let mut file = File::open(&path).unwrap();
            file.seek(SeekFrom::Start(file_size-80)).unwrap();
            let mut buf = [0u8;80];
            file.read_exact(&mut buf).unwrap();
            let mut height = (file_size as u32 / 80) - 1;
            let last : BlockHeader = deserialize(&buf).unwrap();

            HeadersChain {
                path, height, last,
            }
        }
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn get(&self, height: u32) -> BlockHeader {
        println!("get {} file len:{}", height, fs::metadata(&self.path).unwrap().len());
        let mut file = File::open(&self.path).unwrap();
        file.seek(SeekFrom::Start(height as u64 * 80)).unwrap();
        let mut buf = [0u8;80];
        file.read_exact(&mut buf).unwrap();
        let header: BlockHeader = deserialize(&buf).unwrap();
        header
    }

    pub fn push(&mut self, new_headers: Vec<BlockHeader>) {
        let mut serialized = vec![];
        for new_header in new_headers {
            let new_height = self.height + 1;
            assert_eq!(self.last.bitcoin_hash(), new_header.prev_blockhash);
            assert!(new_header.validate_pow(&new_header.target()).is_ok());

            if new_height % DIFFCHANGE_INTERVAL == 0 {
                self.flush(&mut serialized);
                let first = self.get(new_height - DIFFCHANGE_INTERVAL);

                let timespan = self.last.time - first.time;
                let timespan = timespan.min(DIFFCHANGE_TIMESPAN * 4);
                let timespan = timespan.max(DIFFCHANGE_TIMESPAN / 4);

                let new_target = self.last.target() * Uint256::from_u64(timespan as u64).unwrap() / Uint256::from_u64(DIFFCHANGE_TIMESPAN as u64).unwrap();
                let new_target = new_target.min(max_target(Network::Bitcoin));

                assert_eq!(new_header.bits, BlockHeader::compact_target_from_u256(&new_target));
            }
            serialized.extend(serialize(&new_header));
            self.last = new_header;
            self.height = new_height;

        }
        self.flush(&mut serialized);
    }

    fn verify_tx_proof(&self, txid: &Txid, height: u32, merkle: GetMerkleRes) {
        println!("{:?}", &merkle);
        let mut pos = merkle.pos;
        let mut current = txid.into_inner();

        for mut hash in merkle.merkle {
            let mut engine = sha256d::Hash::engine();
            hash.reverse();
            if pos % 2 == 0 {
                engine.write(&current);
                engine.write(&hash);
            } else {
                engine.write(&hash);
                engine.write(&current);
            }
            current = sha256d::Hash::from_engine(engine).into_inner();
            pos/=2;
        }

        let calculated_merkle_root = bitcoin::TxMerkleNode::from_slice(&current).unwrap();
        let header = self.get(height);
        assert_eq!(header.merkle_root, calculated_merkle_root);
    }

    fn flush(&mut self, serialized: &mut Vec<u8>) {
        if !serialized.is_empty() {
            let mut file = OpenOptions::new().append(true).open(&self.path).unwrap();
            file.write_all(&serialized).unwrap();
            file.flush();
            serialized.clear();
        }
    }
}



fn main() {
    let mut client = Client::new("blockstream.info:110").unwrap();
    let mut chain = HeadersChain::new("./test".into(), Network::Bitcoin);
    println!("{:?}", chain);
    let txid = bitcoin::Txid::from_hex("89878bfd69fba52876e5217faec126fc6a20b1845865d4038c12f03200793f48").unwrap();
    let merkle = client.transaction_get_merkle(&txid, 100_008).unwrap();
    chain.verify_tx_proof(&txid, 100_008, merkle);

    let txid = bitcoin::Txid::from_hex("fdb70e2d36e51263ab6085ba70ae030e73d47cd571f2323ab775160589ba5365").unwrap();
    let merkle = client.transaction_get_merkle(&txid, 634_836).unwrap();
    chain.verify_tx_proof(&txid, 634_836, merkle);


    let txid = bitcoin::Txid::from_hex("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16").unwrap();
    let merkle = client.transaction_get_merkle(&txid, 170).unwrap();
    chain.verify_tx_proof(&txid, 170, merkle);

    let txid = bitcoin::Txid::from_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();
    let merkle = client.transaction_get_merkle(&txid, 0).unwrap();
    chain.verify_tx_proof(&txid, 0, merkle);

}

/*
fn main() {
    let mut client = Client::new("blockstream.info:110").unwrap();
    let mut chain = HeadersChain::new("./test".into(), Network::Bitcoin);
    let mut chunk_size = DIFFCHANGE_INTERVAL as usize;

    println!("{:?}", chain);
    loop {
        let get_headers = match client.block_headers(chain.height() as usize + 1, chunk_size) {
            Ok(get_headers) => get_headers,
            Err(e) => {
                // TODO detect client failure and recreate client in that case
                println!("height:{} chunk_size:{} error:{:?}", chain.height(), chunk_size, e);
                if chunk_size != 1 {
                    chunk_size /= 2;
                } else {
                    println!("going to sleep a minute");
                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
                continue;
            }
        };
        chain.push(get_headers.headers);
    }
    println!("{:?}", chain);

}
*/

/*
fn main() {
    let genesis = genesis_block(Network::Bitcoin);
    let mut client = Client::new("blockstream.info:110").unwrap();
    let mut headers = vec![genesis.header.clone()];
    let mut chunk_size = DIFFCHANGE_INTERVAL as usize;

    let mut chain = HeadersChain::new("./test".into(), Network::Bitcoin);

    loop {
        let get_headers = match client.block_headers(headers.len(), chunk_size) {
            Ok(get_headers) => get_headers,
            Err(e) => {
                // TODO detect client failure and recreate client in that case
                println!("height:{} chunk_size:{} error:{:?}", headers.len(), chunk_size, e);
                if chunk_size != 1 {
                    chunk_size /= 2;
                } else {
                    println!("going to sleep a minute");
                    std::thread::sleep(std::time::Duration::from_secs(60));
                }
                continue;
            }
        };
        let mut prev_hash = headers.last().unwrap().bitcoin_hash();  // safe to unwrap since starting with a least one element in the array (genesis)

        for header in get_headers.headers.iter() {
            chain.push(header.clone());
            assert_eq!(prev_hash, header.prev_blockhash);
            prev_hash = header.bitcoin_hash();
            assert!(header.validate_pow(&header.target()).is_ok());

            if headers.len() % DIFFCHANGE_INTERVAL as usize == 0 {
                let first = headers[headers.len()-DIFFCHANGE_INTERVAL as usize];
                let last = headers.last().unwrap();

                let timespan = last.time-first.time;
                let timespan = timespan.min(DIFFCHANGE_TIMESPAN * 4);
                let timespan = timespan.max(DIFFCHANGE_TIMESPAN / 4);

                let new_target = last.target() * Uint256::from_u64(timespan as u64).unwrap() / Uint256::from_u64(DIFFCHANGE_TIMESPAN as u64).unwrap();
                let new_target = new_target.min(max_target(Network::Bitcoin));

                assert_eq!(header.bits, BlockHeader::compact_target_from_u256(&new_target));
                println!("{}", headers.len());
            }

            headers.push(header.clone());
        }
    }
}

 */