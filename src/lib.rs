extern crate bech32;
extern crate chrono;
extern crate num_traits;
extern crate regex;
extern crate secp256k1;

#[cfg(test)]
#[macro_use]
extern crate binary_macros;

use chrono::{DateTime, Utc, Duration};

use secp256k1::key::PublicKey;
use secp256k1::RecoverableSignature;

mod de;
mod ser;

// TODO: ensure Information loss guarantee by introducing a unknown tagged field variant
/// Represents an syntactically correct Invoice for a payment on the lightning network as defined in
/// [BOLT #11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md).
/// De- and encoding should not lead to information loss.
#[derive(Eq, PartialEq, Debug)]
pub struct RawInvoice {
	/// human readable part
	pub hrp: RawHrp,

	/// data part
	pub data: RawDataPart,
}

/// Data of the `RawInvoice` that is encoded in the human readable part
#[derive(Eq, PartialEq, Debug)]
pub struct RawHrp {
	/// The currency deferred from the 3rd and 4th character of the bech32 transaction
	pub currency: Currency,

	/// The amount that, multiplied by the SI prefix, has to be payed
	pub raw_amount: Option<u64>,

	/// SI prefix that gets multiplied with the `raw_amount`
	pub si_prefix: Option<SiPrefix>,
}

/// Data of the `RawInvoice` that is encoded in the data part
#[derive(Eq, PartialEq, Debug)]
pub struct RawDataPart {
	/// generation time of the invoice
	pub timestamp: DateTime<Utc>,

	/// tagged fields of the payment request
	pub tagged_fields: Vec<TaggedField>,

	/// signature of the payment request
	pub signature: RecoverableSignature,
}

/// SI prefixes for the human readable part
#[derive(Eq, PartialEq, Debug)]
pub enum SiPrefix {
	/// 10^-3
	Milli,
	/// 10^-6
	Micro,
	/// 10^-9
	Nano,
	/// 10^-12
	Pico,
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
