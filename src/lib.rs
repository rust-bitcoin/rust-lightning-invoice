extern crate bech32;
extern crate num_traits;
extern crate regex;
extern crate secp256k1;

use bech32::u5;

use secp256k1::key::PublicKey;
use secp256k1::RecoverableSignature;
use std::ops::Deref;

mod de;
mod ser;

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
	// TODO: find better fitting type that only allows positive timestamps to avoid checks for negative timestamps when encoding
	/// generation time of the invoice as UNIX timestamp
	pub timestamp: u64,

	/// tagged fields of the payment request
	pub tagged_fields: Vec<RawTaggedField>,

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

/// Tagged field which may have an unknown tag
#[derive(Eq, PartialEq, Debug)]
pub enum RawTaggedField {
	/// Parsed tagged field with known tag
	KnownSemantics(TaggedField),
	/// tagged field which was not parsed due to an unknown tag or undefined field semantics
	UnknownSemantics(Vec<u5>),
}

/// Tagged field with known tag
#[derive(Eq, PartialEq, Debug)]
pub enum TaggedField {
	PaymentHash(Sha256),
	Description(Description),
	PayeePubKey(PayeePubKey),
	DescriptionHash(Sha256),
	ExpiryTime(ExpiryTime),
	MinFinalCltvExpiry(MinFinalCltvExpiry),
	Fallback(Fallback),
	Route(Route),
}

/// SHA-256 hash
#[derive(Eq, PartialEq, Debug)]
pub struct Sha256(pub [u8; 32]);

/// Description string
///
/// # Invariants
/// The description can be at most 639 __bytes__ long
#[derive(Eq, PartialEq, Debug)]
pub struct Description(String);

/// Payee public key
#[derive(Eq, PartialEq, Debug)]
pub struct PayeePubKey(pub PublicKey);

/// Positive duration that defines when (relatively to the timestamp) in the future the invoice expires
#[derive(Eq, PartialEq, Debug)]
pub struct ExpiryTime {
	pub seconds: u64
}

/// `min_final_cltv_expiry` to use for the last HTLC in the route
#[derive(Eq, PartialEq, Debug)]
pub struct MinFinalCltvExpiry(pub u64);

// TODO: better types instead onf byte arrays
/// Fallback address in case no LN payment is possible
#[derive(Eq, PartialEq, Debug)]
pub enum Fallback {
	SegWitProgram {
		version: u5,
		program: Vec<u8>,
	},
	PubKeyHash([u8; 20]),
	ScriptHash([u8; 20]),
}

/// Private routing information
///
/// # Invariants
/// The encoded route has to be <1024 5bit characters long (<=639 bytes or <=12 hops)
///
#[derive(Eq, PartialEq, Debug)]
pub struct Route(Vec<RouteHop>);

#[derive(Eq, PartialEq, Debug)]
pub struct RouteHop {
	pub pubkey: PublicKey,
	pub short_channel_id: [u8; 8],
	pub fee_base_msat: u32,
	pub fee_proportional_millionths: u32,
	pub cltv_expiry_delta: u16,
}

pub mod constants {
	pub const TAG_PAYMENT_HASH: u8 = 1;
	pub const TAG_DESCRIPTION: u8 = 13;
	pub const TAG_PAYEE_PUB_KEY: u8 = 19;
	pub const TAG_DESCRIPTION_HASH: u8 = 23;
	pub const TAG_EXPIRY_TIME: u8 = 6;
	pub const TAG_MIN_FINAL_CLTV_EXPIRY: u8 = 24;
	pub const TAG_FALLBACK: u8 = 9;
	pub const TAG_ROUTE: u8 = 3;
}

impl From<TaggedField> for RawTaggedField {
	fn from(tf: TaggedField) -> Self {
		RawTaggedField::KnownSemantics(tf)
	}
}

impl TaggedField {
	pub fn tag(&self) -> u5 {
		let tag = match *self {
			TaggedField::PaymentHash(_) => constants::TAG_PAYMENT_HASH,
			TaggedField::Description(_) => constants::TAG_DESCRIPTION,
			TaggedField::PayeePubKey(_) => constants::TAG_PAYEE_PUB_KEY,
			TaggedField::DescriptionHash(_) => constants::TAG_DESCRIPTION_HASH,
			TaggedField::ExpiryTime(_) => constants::TAG_EXPIRY_TIME,
			TaggedField::MinFinalCltvExpiry(_) => constants::TAG_MIN_FINAL_CLTV_EXPIRY,
			TaggedField::Fallback(_) => constants::TAG_FALLBACK,
			TaggedField::Route(_) => constants::TAG_ROUTE,
		};

		u5::try_from_u8(tag).expect("all tags defined are <32")
	}
}

impl Description {

	/// Creates a new `Description` if `description` is at most 1023 __bytes__ long,
	/// returns `CreationError::DescriptionTooLong` otherwise
	///
	/// Please note that single characters may use more than one byte due to UTF8 encoding.
	pub fn new(description: String) -> Result<Description, CreationError> {
		if description.len() > 639 {
			Err(CreationError::DescriptionTooLong)
		} else {
			Ok(Description(description))
		}
	}

	pub fn into_inner(self) -> String {
		self.0
	}
}

impl Into<String> for Description {
	fn into(self) -> String {
		self.into_inner()
	}
}

impl Deref for Description {
	type Target = str;

	fn deref(&self) -> &str {
		&self.0
	}
}

impl From<PublicKey> for PayeePubKey {
	fn from(pk: PublicKey) -> Self {
		PayeePubKey(pk)
	}
}

impl Deref for PayeePubKey {
	type Target = PublicKey;

	fn deref(&self) -> &PublicKey {
		&self.0
	}
}

impl Route {
	pub fn new(hops: Vec<RouteHop>) -> Result<Route, CreationError> {
		if hops.len() <= 12 {
			Ok(Route(hops))
		} else {
			Err(CreationError::RouteTooLong)
		}
	}

	fn into_inner(self) -> Vec<RouteHop> {
		self.0
	}
}

impl Into<Vec<RouteHop>> for Route {
	fn into(self) -> Vec<RouteHop> {
		self.into_inner()
	}
}

impl Deref for Route {
	type Target = Vec<RouteHop>;

	fn deref(&self) -> &Vec<RouteHop> {
		&self.0
	}
}

/// Errors that may occur when constructing a new `RawInvoice` or `Invoice`
#[derive(Eq, PartialEq, Debug)]
pub enum CreationError {
	/// The supplied description string was longer than 639 __bytes__ (see [`Description::new(…)`](./struct.Description.html#method.new))
	DescriptionTooLong,

	/// The specified route has too many hops and can't be encoded
	RouteTooLong,
}