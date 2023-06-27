use crate::sha_256;
use crate::transaction::{PermitSignature, PubKeyValue, SignedTx};
use bech32::FromBase32;
use cosmwasm_std::{to_binary, Api, Binary, CanonicalAddr, StdError, StdResult, Uint128};
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// NOTE: Struct order is very important for signatures

// Signature idea taken from https://github.com/scrtlabs/secret-toolkit/blob/token-permits/packages/permit/src/funcs.rs

/// Where the information will be stored
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Permit<T: Clone + Serialize> {
    pub params: T,
    pub signature: PermitSignature,
    pub account_number: Option<Uint128>,
    pub chain_id: Option<String>,
    pub sequence: Option<Uint128>,
    pub memo: Option<String>,
}

pub fn bech32_to_canonical(addr: &str) -> CanonicalAddr {
    let (_, data, _) = bech32::decode(addr).unwrap();
    CanonicalAddr(Binary(Vec::<u8>::from_base32(&data).unwrap()))
}

impl<T: Clone + Serialize> Permit<T> {
    pub fn create_signed_tx(&self, msg_type: Option<String>) -> SignedTx<T> {
        SignedTx::from_permit(self, msg_type)
    }

    /// Returns the permit signer
    pub fn validate<A: Api>(&self, api: &A, msg_type: Option<String>) -> StdResult<PubKeyValue> {
        Permit::validate_signed_tx(api, &self.signature, &self.create_signed_tx(msg_type))
    }

    pub fn validate_signed_tx<A: Api>(
        api: &A,
        signature: &PermitSignature,
        signed_tx: &SignedTx<T>,
    ) -> StdResult<PubKeyValue> {
        let pubkey = &signature.pub_key.value;

        // Try validating Cosmos signature

        let signed_bytes = to_binary(signed_tx)?;
        let signed_bytes_hash = sha_256(signed_bytes.as_slice());

        let verified = api
            .secp256k1_verify(&signed_bytes_hash, &signature.signature.0, &pubkey.0)
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        if verified {
            return Ok(PubKeyValue(pubkey.clone()));
        }

        // Try validating Ethereum signature

        let mut signed_bytes = vec![];
        signed_bytes.extend_from_slice(b"\x19Ethereum Signed Message:\n");

        // TODO: figure out how to serialize signed_tx as a JSON with an indent of 4
        let signed_tx_pretty_amino_json = to_binary_pretty(signed_tx)?;

        signed_bytes.extend_from_slice(signed_tx_pretty_amino_json.len().to_string().as_bytes());
        signed_bytes.extend_from_slice(signed_tx_pretty_amino_json.as_slice());

        let mut hasher = Sha3::keccak256();

        hasher.input(&signed_bytes);

        let mut signed_bytes_hash = [0u8; 32];
        hasher.result(&mut signed_bytes_hash);

        let verified = api
            .secp256k1_verify(&signed_bytes_hash, &signature.signature.0, &pubkey.0)
            .map_err(|err| StdError::generic_err(err.to_string()))?;

        if verified {
            return Ok(PubKeyValue(pubkey.clone()));
        }

        return Err(StdError::generic_err("Signature verification failed"));
    }
}

fn to_binary_pretty<T>(data: &T) -> StdResult<Binary>
where
    T: Serialize + ?Sized,
{
    todo!();
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::transaction::PubKey;
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{HumanAddr, Uint128};

    #[remain::sorted]
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    struct TestPermitMsg {
        pub address: String,
        pub some_number: Uint128,
    }

    type TestPermit = Permit<TestPermitMsg>;

    const ADDRESS: &str = "secret102nasmxnxvwp5agc4lp3flc6s23335xm8g7gn9";
    const PUBKEY: &str = "A0qzJ3s16OKUfn1KFyh533vBnBOQIT0jm+R/FBobJCfa";
    const SIGNED_TX: &str =
        "4pZtghyHKHHmwiGNC5JD8JxCJiO+44j6GqaLPc19Q7lt85tr0IRZHYcnc0pkokIds8otxU9rcuvPXb0+etLyVA==";

    // Use secretcli tx sign-doc file --from account
    //{
    //  "account_number": "0",
    //  "chain_id": "pulsar-1",
    //  "fee": {
    //      "amount": [{
    //          "amount": "0",
    //          "denom": "uscrt"
    //      }],
    //      "gas": "1"
    //  },
    //  "memo": "",
    //  "msgs": [{
    //      "type": "signature_proof",
    //      "value": {
    //          "address": "secret102nasmxnxvwp5agc4lp3flc6s23335xm8g7gn9",
    //          "some_number": "10"
    //      }
    //  }],
    //  "sequence": "0"
    // }

    #[test]
    fn test_signed_tx() {
        let mut permit = TestPermit {
            params: TestPermitMsg {
                address: ADDRESS.to_string(),
                some_number: Uint128(10),
            },
            chain_id: Some("pulsar-1".to_string()),
            sequence: None,
            signature: PermitSignature {
                pub_key: PubKey::new(Binary::from_base64(PUBKEY).unwrap()),
                signature: Binary::from_base64(SIGNED_TX).unwrap(),
            },
            account_number: None,
            memo: None,
        };

        let deps = mock_dependencies(20, &[]);
        let addr = permit.validate(&deps.api, None).unwrap();
        assert_eq!(
            addr.as_humanaddr(None).unwrap(),
            HumanAddr(ADDRESS.to_string())
        );
        assert_eq!(addr.as_canonical(), bech32_to_canonical(ADDRESS));

        permit.params.some_number = Uint128(100);
        // NOTE: SN mock deps dont have a valid working implementation of the dep functons for some reason
        //assert!(permit.validate(&deps.api, None).is_err());
    }

    const FILLERPERMITNAME: &str = "wasm/MsgExecuteContract";

    type MemoPermit = Permit<FillerPermit>;

    #[remain::sorted]
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    struct FillerPermit {
        pub coins: Vec<String>,
        pub contract: String,
        pub execute_msg: EmptyMsg,
        pub sender: String,
    }

    #[remain::sorted]
    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    #[serde(rename_all = "snake_case")]
    struct EmptyMsg {}

    #[test]
    fn memo_signature() {
        let mut permit = MemoPermit {
            params: FillerPermit {
                coins: vec![],
                sender: "".to_string(),
                contract: "".to_string(),
                execute_msg: EmptyMsg {}
            },
            chain_id: Some("bombay-12".to_string()),
            sequence: Some(Uint128(0)),
            signature: PermitSignature {
                pub_key: PubKey::new(Binary::from_base64(
                    "A50CTeVnMYyZGh7K4x4NtdfG1H1oicog6lEoPMi65IK2").unwrap()),
                signature: Binary::from_base64(
                    "75RcVHa/SW1WyjcFMkhZ63+D4ccxffchLvJPyURmtaskA8CPj+y6JSrpuRhxMC+1hdjSJC3c0IeJVbDIRapxPg==").unwrap(),
            },
            account_number: Some(Uint128(203289)),
            memo: Some("b64Encoded".to_string())
        };

        let deps = mock_dependencies(20, &[]);

        let addr = permit
            .validate(&deps.api, Some(FILLERPERMITNAME.to_string()))
            .unwrap();
        assert_eq!(
            addr.as_canonical(),
            bech32_to_canonical("terra1m79yd3jh97vz4tqu0m8g49gfl7qmknhh23kac5")
        );
        assert_ne!(
            addr.as_canonical(),
            bech32_to_canonical("secret102nasmxnxvwp5agc4lp3flc6s23335xm8g7gn9")
        );

        permit.memo = Some("OtherMemo".to_string());

        // NOTE: SN mock deps doesnt have a valid working implementation of the dep functons for some reason
        //assert!(permit.validate(&deps.api, Some(FILLERPERMITNAME.to_string())).is_err())
    }
}
