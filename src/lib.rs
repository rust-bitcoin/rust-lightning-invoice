extern crate bech32;
extern crate chrono;
extern crate regex;
extern crate secp256k1;

#[cfg(test)]
extern crate hex;

use std::str::FromStr;

use bech32::Bech32;

use chrono::{DateTime, Utc, Duration};

use secp256k1::key::PublicKey;
use secp256k1::{Signature, Secp256k1};

mod parsers;

/// An Invoice for a payment on the lightning network as defined in
/// [BOLT #11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md).
#[derive(Eq, PartialEq, Debug)]
pub struct Invoice {
	/// The currency deferred from the 3rd and 4th character of the bech32 transaction
	pub currency: Currency,

	/// The amount to pay in pico-satoshis
	pub amount: Option<u64>,

	pub timestamp: DateTime<Utc>,

	/// tagged fields of the payment request
	pub tagged: Vec<TaggedField>,

	pub signature: Signature,
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
	Route {
		pubkey: PublicKey,
		short_channel_id: u64,
		fee_base_msat: i32,
		fee_proportional_millionths: i32,
		cltv_expiry_delta: u16,
	},
}

// TODO: better types instead onf byte arrays
#[derive(Eq, PartialEq, Debug)]
pub enum Fallback {
	SegWitScript {
		version: u8,
		script: Vec<u8>,
	},
	PubKeyHash([u8; 20]),
	ScriptHash([u8; 20]),
}

impl FromStr for Invoice {
	type Err = parsers::Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let Bech32 { hrp, data } = s.parse()?;

		let (currency, amount) = parsers::parse_hrp(&hrp)?;

		Ok(Invoice {
			currency,
			amount,
			timestamp: Utc::now(),
			tagged: vec![],
			signature: Signature::from_der(&Secp256k1::new(), &[0; 65])?,
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
}