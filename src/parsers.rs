use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::str;

use bech32;
use bech32::convert_bits;

use chrono::{DateTime, Utc, TimeZone, Duration};

use num_traits::{CheckedAdd, CheckedMul};

use regex::Regex;

use secp256k1;
use secp256k1::{RecoveryId, RecoverableSignature, Secp256k1};
use secp256k1::key::PublicKey;

use super::{Currency, TaggedField, Fallback, RouteHop};

pub(super) fn parse_hrp(hrp: &str) -> Result<(Currency, Option<u64>), Error> {
	let re = Regex::new(r"^ln([^0-9]*)([0-9]*)([munp]?)$").unwrap();
	let parts = match re.captures(&hrp) {
		Some(capture_group) => capture_group,
		None => return Err(Error::MalformedHRP)
	};

	let currency = parts[1].parse::<Currency>()?;

	let amount = if !parts[2].is_empty() {
		Some(parts[2].parse::<u64>()?)
	} else {
		None
	};

	// `get_multiplier(x)` will only return `None` if `x` is not "m", "u", "n" or "p", which
	// due to the above regex ensures that `get_multiplier(x)` iif `x == ""`, so it's ok to
	// convert a none to 1BTC aka 10^12pBTC.
	let multiplier = parts[3].chars().next().and_then(|suffix| {
		get_multiplier(&suffix)
	}).unwrap_or(1_000_000_000_000);

	Ok((currency, amount.map(|amount| amount * multiplier)))
}

fn get_multiplier(multiplier: &char) -> Option<u64> {
	match multiplier {
		&'m' => Some(1_000_000_000),
		&'u' => Some(1_000_000),
		&'n' => Some(1_000),
		&'p' => Some(1),
		_ => None
	}
}

// why &[u8] instead of Vec<u8>?: split_off reallocs => wouldn't save much cloning,
// instead split_at is used, which doesn't need ownership of the data
pub(super) fn parse_data(data: &[u8]) -> Result<(DateTime<Utc>, Vec<TaggedField>, RecoverableSignature), Error> {
	if data.len() < 104 + 7 { // signature + timestamp
		return Err(Error::TooShortDataPart);
	}

	let time = &data[0..7];
	let tagged= &data[7..(data.len()-104)];
	let recoverable_signature = &data[(data.len()-104)..];
	assert_eq!(time.len(), 7);
	assert_eq!(recoverable_signature.len(), 104);

	let recoverable_signature_bytes = convert_bits(recoverable_signature, 5, 8, false)?;
	let signature = &recoverable_signature_bytes[0..64];
	let recovery_id = RecoveryId::from_i32(recoverable_signature_bytes[64] as i32)?;


	let unix_time: i64 = parse_int_be(time, 32).expect("7*5bit < 63bit, no overflow possible");
	let time = Utc.timestamp(unix_time, 0);
	let signature = RecoverableSignature::from_compact(
		&Secp256k1::without_caps(),
		signature,
		recovery_id
	)?;
	let tagged = parse_tagged_parts(tagged)?;

	Ok((time, tagged, signature))
}

fn parse_int_be<T: CheckedAdd + CheckedMul + From<u8> + Default>(digits: &[u8], base: T) -> Option<T> {
	digits.iter().fold(Some(Default::default()), |acc, b|
		acc
			.and_then(|x| x.checked_mul(&base))
			.and_then(|x| x.checked_add(&(*b).into()))
	)
}

fn parse_tagged_parts(data: &[u8]) -> Result<Vec<TaggedField>, Error> {
	let mut parts = Vec::<TaggedField>::new();
	let mut data = data;

	while !data.is_empty() {
		if data.len() < 3 {
			return Err(Error::UnexpectedEndOfTaggedFields);
		}
		let (meta, remaining_data) = data.split_at(3);
		let (tag, len) = meta.split_at(1);

		let len: usize = parse_int_be(len, 32).expect("can't overflow");
		let tag = tag[0];

		if remaining_data.len() < len {
			return Err(Error::UnexpectedEndOfTaggedFields);
		}
		let (field_data, remaining_data) = remaining_data.split_at(len);

		data = remaining_data;

		let field = parse_field(tag, field_data)?;

		field.map(|f| parts.push(f));
	}
	Ok(parts)
}

type ParseFieldResult = Result<Option<TaggedField>, Error>;

fn parse_field(tag: u8, field_data: &[u8]) -> ParseFieldResult {
	match tag {
		TaggedField::TAG_PAYMENT_HASH => parse_payment_hash(field_data),
		TaggedField::TAG_DESCRIPTION => parse_description(field_data),
		TaggedField::TAG_PAYEE_PUB_KEY => parse_payee_pub_key(field_data),
		TaggedField::TAG_DESCRIPTION_HASH => parse_description_hash(field_data),
		TaggedField::TAG_EXPIRY_TIME => parse_expiry_time(field_data),
		TaggedField::TAG_MIN_FINAL_CLTV_EXPIRY => parse_min_final_cltv_expiry(field_data),
		TaggedField::TAG_FALLBACK => parse_fallback(field_data),
		TaggedField::TAG_ROUTE => parse_route(field_data),
		_ => {
			// "A reader MUST skip over unknown fields"
			Ok(None)
		}
	}
}

fn parse_payment_hash(field_data: &[u8]) -> ParseFieldResult {
	if field_data.len() != 52 {
		// "A reader MUST skip over […] a p […] field that does not have data_length 52 […]."
		Ok(None)
	} else {
		let mut hash: [u8; 32] = Default::default();
		hash.copy_from_slice(&convert_bits(field_data, 5, 8, false)?);
		Ok(Some(TaggedField::PaymentHash(hash)))
	}
}

fn parse_description(field_data: &[u8]) -> ParseFieldResult {
	let bytes = convert_bits(field_data, 5, 8, false)?;
	let description = String::from(str::from_utf8(&bytes)?);
	Ok(Some(TaggedField::Description(description)))
}

fn parse_payee_pub_key(field_data: &[u8]) -> ParseFieldResult {
	if field_data.len() != 53 {
		// "A reader MUST skip over […] a n […] field that does not have data_length 53 […]."
		Ok(None)
	} else {
		let data_bytes = convert_bits(field_data, 5, 8, false)?;
		let pub_key = PublicKey::from_slice(&Secp256k1::without_caps(), &data_bytes)?;
		Ok(Some(TaggedField::PayeePubKey(pub_key)))
	}
}

fn parse_description_hash(field_data: &[u8]) -> ParseFieldResult {
	if field_data.len() != 52 {
		// "A reader MUST skip over […] a h […] field that does not have data_length 52 […]."
		Ok(None)
	} else {
		let mut hash: [u8; 32] = Default::default();
		hash.copy_from_slice(&convert_bits(field_data, 5, 8, false)?);
		Ok(Some(TaggedField::DescriptionHash(hash)))
	}
}

fn parse_expiry_time(field_data: &[u8]) -> ParseFieldResult {
	let expiry = parse_int_be::<i64>(field_data, 32);
	if let Some(expiry) = expiry {
		Ok(Some(TaggedField::ExpiryTime(Duration::seconds(expiry))))
	} else {
		Err(Error::IntegerOverflowError)
	}
}

fn parse_min_final_cltv_expiry(field_data: &[u8]) -> ParseFieldResult {
	let expiry = parse_int_be::<u64>(field_data, 32);
	if let Some(expiry) = expiry {
		Ok(Some(TaggedField::MinFinalCltvExpiry(expiry)))
	} else {
		Err(Error::IntegerOverflowError)
	}
}

fn parse_fallback(field_data: &[u8]) -> ParseFieldResult {
	if field_data.len() < 1 {
		return Err(Error::UnexpectedEndOfTaggedFields);
	}

	let version = field_data[0];
	let bytes = convert_bits(&field_data[1..], 5, 8, false)?;

	let fallback_address = match version {
		v @ 0...16 => {
			if bytes.len() < 2 || bytes.len() > 40 {
				return Err(Error::InvalidSegWitProgramLength);
			}

			Some(Fallback::SegWitProgram {
				version: v,
				program: bytes
			})
		},
		17 => {
			if bytes.len() != 20 {
				return Err(Error::InvalidPubKeyHashLength);
			}
			//TODO: refactor once const generics are available
			let mut pkh = [0u8; 20];
			pkh.copy_from_slice(&bytes);
			Some(Fallback::PubKeyHash(pkh))
		}
		18 => {
			if bytes.len() != 20 {
				return Err(Error::InvalidScriptHashLength);
			}
			let mut sh = [0u8; 20];
			sh.copy_from_slice(&bytes);
			Some(Fallback::ScriptHash(sh))
		}
		_ => None
	};

	Ok(fallback_address.map(|addr| TaggedField::Fallback(addr)))
}

fn parse_route(field_data: &[u8]) -> ParseFieldResult {
	let bytes = convert_bits(field_data, 5, 8, false)?;

	if bytes.len() % 51 != 0 {
		return Err(Error::UnexpectedEndOfTaggedFields);
	}

	let mut route_hops = Vec::<RouteHop>::new();

	let mut bytes = bytes.as_slice();
	while !bytes.is_empty() {
		let hop_bytes = &bytes[0..51];
		bytes = &bytes[51..];

		let mut channel_id: [u8; 8] = Default::default();
		channel_id.copy_from_slice(&hop_bytes[33..41]);

		let hop = RouteHop {
			pubkey: PublicKey::from_slice(&Secp256k1::without_caps(), &hop_bytes[0..33])?,
			short_channel_id: channel_id,
			fee_base_msat: parse_int_be(&hop_bytes[41..45], 256).expect("slice too big?"),
			fee_proportional_millionths: parse_int_be(&hop_bytes[45..49], 256).expect("slice too big?"),
			cltv_expiry_delta: parse_int_be(&hop_bytes[49..51], 256).expect("slice too big?")
		};

		route_hops.push(hop);
	}

	Ok(Some(TaggedField::Route(route_hops)))
}

#[derive(PartialEq, Debug)]
pub enum Error {
	Bech32Error(bech32::Error),
	ParseAmountError(ParseIntError),
	MalformedSignature(secp256k1::Error),
	BadPrefix,
	UnknownCurrency,
	MalformedHRP,
	TooShortDataPart,
	UnexpectedEndOfTaggedFields,
	DescriptionDecodeError(str::Utf8Error),
	PaddingError(bech32::Error),
	IntegerOverflowError,
	InvalidSegWitProgramLength,
	InvalidPubKeyHashLength,
	InvalidScriptHashLength,
	InvalidRecoveryId,
}

impl Display for Error {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		use self::Error::*;
		use std::error::Error;
		match *self {
			// TODO: find a way to combine the first three arms (e as error::Error?)
			Bech32Error(ref e) => {
				write!(f, "{} ({})", self.description(), e)
			}
			ParseAmountError(ref e) => {
				write!(f, "{} ({})", self.description(), e)
			}
			MalformedSignature(ref e) => {
				write!(f, "{} ({})", self.description(), e)
			}
			DescriptionDecodeError(ref e) => {
				write!(f, "{} ({})", self.description(), e)
			}
			PaddingError(ref e) => {
				write!(f, "{} ({})", self.description(), e)
			},
			_ => {
				write!(f, "{}", self.description())
			}
		}
	}
}

impl error::Error for Error {
	fn description(&self) -> &str {
		use self::Error::*;
		match *self {
			Bech32Error(_) => "invalid bech32",
			ParseAmountError(_) => "invalid amount in hrp",
			MalformedSignature(_) => "invalid secp256k1 signature",
			BadPrefix => "did not begin with 'ln'",
			UnknownCurrency => "currency code unknown",
			MalformedHRP => "malformed human readable part",
			TooShortDataPart => "data part too short (should be at least 111 bech32 chars long)",
			UnexpectedEndOfTaggedFields => "tagged fields part ended unexpectedly",
			DescriptionDecodeError(_) => "description is no valid utf-8 string",
			PaddingError(_) => "some data field had bad padding",
			IntegerOverflowError => "parsed integer doesn't fit into receiving type",
			InvalidSegWitProgramLength => "fallback SegWit program is too long or too short",
			InvalidPubKeyHashLength => "fallback public key hash has a length unequal 20 bytes",
			InvalidScriptHashLength => "fallback script hash has a length unequal 32 bytes",
			InvalidRecoveryId => "recovery id is out of range (should be in [0,3])",
		}
	}
}

macro_rules! from_error {
    ($my_error:expr, $extern_error:ty) => {
        impl From<$extern_error> for Error {
            fn from(e: $extern_error) -> Self {
                $my_error(e)
            }
        }
    }
}

from_error!(Error::MalformedSignature, secp256k1::Error);
from_error!(Error::ParseAmountError, ParseIntError);
from_error!(Error::DescriptionDecodeError, str::Utf8Error);

impl From<bech32::Error> for Error {
	fn from(e: bech32::Error) -> Self {
		match e {
			bech32::Error::InvalidPadding => Error::PaddingError(e),
			_ => Error::Bech32Error(e)
		}
	}
}

#[cfg(test)]
mod test {
	use TaggedField;
	use super::*;

	const CHARSET_REV: [i8; 128] = [
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
		1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
		1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1
	];

	fn from_bech32(bytes_5b: &[u8]) -> Vec<u8> {
		bytes_5b.iter().map(|c| CHARSET_REV[*c as usize] as u8).collect()
	}

	#[test]
	fn test_parse_int_from_bytes_be() {
		assert_eq!(parse_int_be::<u32>(&[1, 2, 3, 4], 256), Some(16909060));
		assert_eq!(parse_int_be::<u32>(&[1, 3], 32), Some(35));
		assert_eq!(parse_int_be::<u32>(&[1, 2, 3, 4, 5], 256), None);
	}

	//TODO: test error conditions

	#[test]
	fn test_parse_payment_hash() {
		let input = from_bech32(
			"qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq".as_bytes()
		);

		let hash = base16!("0001020304050607080900010203040506070809000102030405060708090102");
		let expected = Ok(Some(TaggedField::PaymentHash(*hash)));

		assert_eq!(parse_payment_hash(&input), expected);
	}

	#[test]
	fn test_parse_description() {
		let input = from_bech32("xysxxatsyp3k7enxv4js".as_bytes());
		let expected = Ok(Some(TaggedField::Description("1 cup coffee".into())));
		assert_eq!(parse_description(&input), expected);
	}

	#[test]
	fn test_parse_payee_pub_key() {
		let input = from_bech32("q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66".as_bytes());
		let pk_bytes = base16!("03E7156AE33B0A208D0744199163177E909E80176E55D97A2F221EDE0F934DD9AD");
		let expected = Ok(Some(TaggedField::PayeePubKey(
			PublicKey::from_slice(&Secp256k1::without_caps(), &pk_bytes[..]).unwrap()
		)));

		assert_eq!(parse_payee_pub_key(&input), expected);
	}

	#[test]
	fn test_parse_description_hash() {
		let input = from_bech32(
			"8yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs".as_bytes()
		);
		let expected = Ok(Some(TaggedField::DescriptionHash(
			*base16!("3925B6F67E2C340036ED12093DD44E0368DF1B6EA26C53DBE4811F58FD5DB8C1")
		)));

		assert_eq!(parse_description_hash(&input), expected);
	}

	#[test]
	fn test_parse_expiry_time() {
		let input = from_bech32("pu".as_bytes());
		let expected = Ok(Some(TaggedField::ExpiryTime(
			Duration::seconds(60)
		)));

		assert_eq!(parse_expiry_time(&input), expected);

	}

	#[test]
	fn test_parse_min_final_cltv_expiry() {
		let input = from_bech32("pr".as_bytes());
		let expected = Ok(Some(TaggedField::MinFinalCltvExpiry(35)));

		assert_eq!(parse_min_final_cltv_expiry(&input), expected);
	}

	#[test]
	fn test_parse_fallback() {
		let cases = vec![
			(
				from_bech32("3x9et2e20v6pu37c5d9vax37wxq72un98".as_bytes()),
				Fallback::PubKeyHash(*base16!("3172B5654F6683C8FB146959D347CE303CAE4CA7"))
			),
			(
				from_bech32("j3a24vwu6r8ejrss3axul8rxldph2q7z9".as_bytes()),
				Fallback::ScriptHash(*base16!("8F55563B9A19F321C211E9B9F38CDF686EA07845"))
			),
			(
				from_bech32("qw508d6qejxtdg4y5r3zarvary0c5xw7k".as_bytes()),
				Fallback::SegWitProgram {
					version: 0,
					program: Vec::from(&base16!("751E76E8199196D454941C45D1B3A323F1433BD6")[..])
				}
			)
		];

		for (input, expected) in cases.into_iter() {
			assert_eq!(parse_fallback(&input), Ok(Some(TaggedField::Fallback(expected))));
		}
	}

	#[test]
	fn test_parse_route() {
		let input = from_bech32(
			"q20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqa\
			fqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq".as_bytes()
		);

		let mut expected = Vec::<RouteHop>::new();
		expected.push(RouteHop {
			pubkey: PublicKey::from_slice(
				&Secp256k1::without_caps(),
				&base16!("029E03A901B85534FF1E92C43C74431F7CE72046060FCF7A95C37E148F78C77255")[..]
			).unwrap(),
			short_channel_id: *base16!("0102030405060708"),
			fee_base_msat: 1,
			fee_proportional_millionths: 20,
			cltv_expiry_delta: 3
		});
		expected.push(RouteHop {
			pubkey: PublicKey::from_slice(
				&Secp256k1::without_caps(),
				&base16!("039E03A901B85534FF1E92C43C74431F7CE72046060FCF7A95C37E148F78C77255")[..]
			).unwrap(),
			short_channel_id: *base16!("030405060708090A"),
			fee_base_msat: 2,
			fee_proportional_millionths: 30,
			cltv_expiry_delta: 4
		});

		assert_eq!(parse_route(&input), Ok(Some(TaggedField::Route(expected))));
	}
}