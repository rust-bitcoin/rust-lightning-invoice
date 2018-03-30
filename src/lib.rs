extern crate bech32;
extern crate chrono;
extern crate num_traits;
extern crate regex;
extern crate secp256k1;

#[cfg(test)]
#[macro_use]
extern crate binary_macros;

use std::str::FromStr;

use bech32::Bech32;

use chrono::{DateTime, Utc, Duration};

use secp256k1::key::PublicKey;
use secp256k1::RecoverableSignature;

mod parsers;

// TODO: ensure Information loss guarantee by introducing a unknown tagged field variant
/// Represents an syntactically correct Invoice for a payment on the lightning network as defined in
/// [BOLT #11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md).
/// De- and encoding should not lead to information loss.
#[derive(Eq, PartialEq, Debug)]
pub struct RawInvoice {
	/// The currency deferred from the 3rd and 4th character of the bech32 transaction
	pub currency: Currency,

	/// The amount to pay in pico-satoshis
	pub amount: Option<u64>,

	pub timestamp: DateTime<Utc>,

	/// tagged fields of the payment request
	pub tagged: Vec<TaggedField>,

	pub signature: RecoverableSignature,
}

#[derive(Eq, PartialEq, Debug)]
pub enum Currency {
	Bitcoin,
	BitcoinTestnet,
}

#[derive(Eq, PartialEq, Debug)]
pub enum TaggedField {
	PaymentHash([u8; 32]),
	Description(String),
	PayeePubKey(PublicKey),
	DescriptionHash([u8; 32]),
	ExpiryTime(Duration),
	MinFinalCltvExpiry(u64),
	Fallback(Fallback),
	Route(Vec<RouteHop>),
}

#[derive(Eq, PartialEq, Debug)]
pub struct RouteHop {
	pub pubkey: PublicKey,
	pub short_channel_id: [u8; 8],
	pub fee_base_msat: u32,
	pub fee_proportional_millionths: u32,
	pub cltv_expiry_delta: u16,
}

impl TaggedField {
	const TAG_PAYMENT_HASH: u8 = 1;
	const TAG_DESCRIPTION: u8 = 13;
	const TAG_PAYEE_PUB_KEY: u8 = 19;
	const TAG_DESCRIPTION_HASH: u8 = 23;
	const TAG_EXPIRY_TIME: u8 = 6;
	const TAG_MIN_FINAL_CLTV_EXPIRY: u8 = 24;
	const TAG_FALLBACK: u8 = 9;
	const TAG_ROUTE: u8 = 3;
}

// TODO: better types instead onf byte arrays
#[derive(Eq, PartialEq, Debug)]
pub enum Fallback {
	SegWitProgram {
		version: u8,
		program: Vec<u8>,
	},
	PubKeyHash([u8; 20]),
	ScriptHash([u8; 20]),
}

impl FromStr for RawInvoice {
	type Err = parsers::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let (hrp, data) = Bech32::from_str_lenient(s)?.into_parts();

		let (currency, amount) = parsers::parse_hrp(&hrp)?;
		let (timestamp, tagged, signature) = parsers::parse_data(&data)?;

		Ok(RawInvoice {
			currency,
			amount,
			timestamp,
			tagged,
			signature,
		})
	}
}


impl Currency {
	pub fn get_currency_prefix(&self) -> &'static str {
		match self {
			&Currency::Bitcoin => "bc",
			&Currency::BitcoinTestnet => "tb",
		}
	}

	pub fn from_prefix(prefix: &str) -> Result<Currency, parsers::Error> {
		match prefix {
			"bc" => Ok(Currency::Bitcoin),
			"tb" => Ok(Currency::BitcoinTestnet),
			_ => Err(parsers::Error::UnknownCurrency)
		}
	}
}

impl FromStr for Currency {
	type Err = parsers::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Currency::from_prefix(s)
	}
}


#[cfg(test)]
mod test {
	#[test]
	fn test_currency_code() {
		use super::Currency;
		assert_eq!("bc", Currency::Bitcoin.get_currency_prefix());
		assert_eq!("tb", Currency::BitcoinTestnet.get_currency_prefix());
	}

	#[test]
	fn test_raw_invoice_deserialization() {
		use super::*;
		use super::TaggedField::*;
		use secp256k1::{RecoveryId, RecoverableSignature, Secp256k1};
		use chrono::{Utc, TimeZone};

		assert_eq!(
			"lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmw\
			wd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9\
			ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w".parse(),
			Ok(
				RawInvoice {
					currency: Currency::Bitcoin,
					amount: None,
					timestamp: Utc.timestamp(1496314658, 0),
					tagged: vec![
						PaymentHash(*base16!("0001020304050607080900010203040506070809000102030405060708090102")),
						Description("Please consider supporting this project".into()),
					],
					signature: RecoverableSignature::from_compact(
						&Secp256k1::without_caps(),
						base16!(
							"38EC6891345E204145BE8A3A99DE38E98A39D6A569434E1845C8AF7205AFCFCC7F425FCD1463E93C32881EAD0D6E356D467EC8C02553F9AAB15E5738B11F127F"
						),
						RecoveryId::from_i32(0).unwrap()
					).unwrap(),
				}
			)
		)
	}
}