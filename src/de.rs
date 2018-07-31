use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::str;
use std::str::FromStr;

use bech32;
use bech32::{Bech32, u5, FromBase32};

use num_traits::{CheckedAdd, CheckedMul};

use regex::Regex;

use secp256k1;
use secp256k1::{RecoveryId, RecoverableSignature, Secp256k1};
use secp256k1::key::PublicKey;

use super::*;
impl FromStr for super::Currency {
	type Err = ParseError;

	fn from_str(currency_prefix: &str) -> Result<Self, ParseError> {
		match currency_prefix {
			"bc" => Ok(Currency::Bitcoin),
			"tb" => Ok(Currency::BitcoinTestnet),
			_ => Err(ParseError::UnknownCurrency)
		}
	}
}

impl FromStr for SiPrefix {
	type Err = ParseError;

	fn from_str(currency_prefix: &str) -> Result<Self, ParseError> {
		use SiPrefix::*;
		match currency_prefix {
			"m" => Ok(Milli),
			"u" => Ok(Micro),
			"n" => Ok(Nano),
			"p" => Ok(Pico),
			_ => Err(ParseError::UnknownSiPrefix)
		}
	}
}

impl FromStr for RawInvoice {
	type Err = ParseError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let (hrp, data) = Bech32::from_str_lenient(s)?.into_parts();

		let hrp: RawHrp = hrp.parse()?;
		let data_part = RawDataPart::from_base32(&data)?;

		Ok(RawInvoice {
			hrp: hrp,
			data: data_part,
		})
	}
}

impl FromStr for RawHrp {
	type Err = ParseError;

	fn from_str(hrp: &str) -> Result<Self, <Self as FromStr>::Err> {
		let re = Regex::new(r"^ln([^0-9]*)([0-9]*)([munp]?)$").unwrap();
		let parts = match re.captures(&hrp) {
			Some(capture_group) => capture_group,
			None => return Err(ParseError::MalformedHRP)
		};

		let currency = parts[1].parse::<Currency>()?;

		let amount = if !parts[2].is_empty() {
			Some(parts[2].parse::<u64>()?)
		} else {
			None
		};

		let si_prefix = &parts[3];
		let si_prefix: Option<SiPrefix> = if si_prefix.is_empty() {
			None
		} else {
			Some(si_prefix.parse()?)
		};

		Ok(RawHrp {
			currency: currency,
			raw_amount: amount,
			si_prefix: si_prefix,
		})
	}
}

impl FromBase32 for RawDataPart {
	type Err = ParseError;

	fn from_base32(data: &[u5]) -> Result<Self, Self::Err> {
		if data.len() < 104 + 7 { // signature + timestamp
			return Err(ParseError::TooShortDataPart);
		}

		let time = &data[0..7];
		let tagged= &data[7..(data.len()-104)];
		let recoverable_signature = &data[(data.len()-104)..];
		assert_eq!(time.len(), 7);
		assert_eq!(recoverable_signature.len(), 104);

		let recoverable_signature_bytes = Vec::<u8>::from_base32(recoverable_signature)?;
		let signature = &recoverable_signature_bytes[0..64];
		let recovery_id = RecoveryId::from_i32(recoverable_signature_bytes[64] as i32)?;


		let timestamp: u64 = parse_int_be(time, 32).expect("7*5bit < 64bit, no overflow possible");
		let signature = RecoverableSignature::from_compact(
			&Secp256k1::without_caps(),
			signature,
			recovery_id
		)?;
		let tagged = parse_tagged_parts(tagged)?;

		Ok(RawDataPart {
			timestamp: timestamp,
			tagged_fields: tagged,
			signature: signature,
		})
	}
}

fn parse_int_be<T, U>(digits: &[U], base: T) -> Option<T>
	where T: CheckedAdd + CheckedMul + From<u8> + Default,
	      U: Into<u8> + Copy
{
	digits.iter().fold(Some(Default::default()), |acc, b|
		acc
			.and_then(|x| x.checked_mul(&base))
			.and_then(|x| x.checked_add(&(Into::<u8>::into(*b)).into()))
	)
}

fn parse_tagged_parts(data: &[u5]) -> Result<Vec<RawTaggedField>, ParseError> {
	let mut parts = Vec::<RawTaggedField>::new();
	let mut data = data;

	while !data.is_empty() {
		if data.len() < 3 {
			return Err(ParseError::UnexpectedEndOfTaggedFields);
		}

		// Ignore tag at data[0], it will be handled in the TaggedField parsers and
		// parse the length to find the end of the tagged field's data
		let len = parse_int_be(&data[1..3], 32).expect("can't overflow");
		let last_element = 3 + len;

		if data.len() < last_element {
			return Err(ParseError::UnexpectedEndOfTaggedFields);
		}

		// Get the tagged field's data slice
		let field = &data[0..last_element];

		// Set data slice to remaining data
		data = &data[last_element..];

		match TaggedField::from_base32(field) {
			Ok(field) => {
				parts.push(RawTaggedField::KnownSemantics(field))
			},
			Err(ParseError::Skip) => {
				parts.push(RawTaggedField::UnknownSemantics(field.into()))
			},
			Err(e) => {return Err(e)}
		}
	}
	Ok(parts)
}

impl FromBase32 for TaggedField {
	type Err = ParseError;

	fn from_base32(field: &[u5]) -> Result<TaggedField, ParseError> {
		if field.len() < 3 {
			return Err(ParseError::UnexpectedEndOfTaggedFields);
		}

		let tag = field[0];
		let field_data =  &field[3..];

		match tag.to_u8() {
			constants::TAG_PAYMENT_HASH =>
				Ok(TaggedField::PaymentHash(Sha256::from_base32(field_data)?)),
			constants::TAG_DESCRIPTION =>
				Ok(TaggedField::Description(Description::from_base32(field_data)?)),
			constants::TAG_PAYEE_PUB_KEY =>
				Ok(TaggedField::PayeePubKey(PayeePubKey::from_base32(field_data)?)),
			constants::TAG_DESCRIPTION_HASH =>
				Ok(TaggedField::DescriptionHash(Sha256::from_base32(field_data)?)),
			constants::TAG_EXPIRY_TIME =>
				Ok(TaggedField::ExpiryTime(ExpiryTime::from_base32(field_data)?)),
			constants::TAG_MIN_FINAL_CLTV_EXPIRY =>
				Ok(TaggedField::MinFinalCltvExpiry(MinFinalCltvExpiry::from_base32(field_data)?)),
			constants::TAG_FALLBACK =>
				Ok(TaggedField::Fallback(Fallback::from_base32(field_data)?)),
			constants::TAG_ROUTE =>
				Ok(TaggedField::Route(Route::from_base32(field_data)?)),
			_ => {
				// "A reader MUST skip over unknown fields"
				Err(ParseError::Skip)
			}
		}
	}
}

impl FromBase32 for Sha256 {
	type Err = ParseError;

	fn from_base32(field_data: &[u5]) -> Result<Sha256, ParseError> {
		if field_data.len() != 52 {
			// "A reader MUST skip over […] a p, [or] h […] field that does not have data_length 52 […]."
			Err(ParseError::Skip)
		} else {
			let mut hash: [u8; 32] = Default::default();
			hash.copy_from_slice(&Vec::<u8>::from_base32(field_data)?);
			Ok(Sha256(hash))
		}
	}
}

impl FromBase32 for Description {
	type Err = ParseError;

	fn from_base32(field_data: &[u5]) -> Result<Description, ParseError> {
		let bytes = Vec::<u8>::from_base32(field_data)?;
		let description = String::from(str::from_utf8(&bytes)?);
		Ok(Description::new(description).expect(
			"Max len is 639=floor(1023*5/8) since the len field is only 10bits long"
		))
	}
}

impl FromBase32 for PayeePubKey {
	type Err = ParseError;

	fn from_base32(field_data: &[u5]) -> Result<PayeePubKey, ParseError> {
		if field_data.len() != 53 {
			// "A reader MUST skip over […] a n […] field that does not have data_length 53 […]."
			Err(ParseError::Skip)
		} else {
			let data_bytes = Vec::<u8>::from_base32(field_data)?;
			let pub_key = PublicKey::from_slice(&Secp256k1::without_caps(), &data_bytes)?;
			Ok(pub_key.into())
		}
	}
}

impl FromBase32 for ExpiryTime {
	type Err = ParseError;

	fn from_base32(field_data: &[u5]) -> Result<ExpiryTime, ParseError> {
		let expiry = parse_int_be::<u64, u5>(field_data, 32);
		if let Some(expiry) = expiry {
			Ok(ExpiryTime{seconds: expiry})
		} else {
			Err(ParseError::IntegerOverflowError)
		}
	}
}

impl FromBase32 for MinFinalCltvExpiry {
	type Err = ParseError;

	fn from_base32(field_data: &[u5]) -> Result<MinFinalCltvExpiry, ParseError> {
		let expiry = parse_int_be::<u64, u5>(field_data, 32);
		if let Some(expiry) = expiry {
			Ok(MinFinalCltvExpiry(expiry))
		} else {
			Err(ParseError::IntegerOverflowError)
		}
	}
}

impl FromBase32 for Fallback {
	type Err = ParseError;

	fn from_base32(field_data: &[u5]) -> Result<Fallback, ParseError> {
		if field_data.len() < 1 {
			return Err(ParseError::UnexpectedEndOfTaggedFields);
		}

		let version = field_data[0];
		let bytes = Vec::<u8>::from_base32(&field_data[1..])?;

		match version.to_u8() {
			0...16 => {
				if bytes.len() < 2 || bytes.len() > 40 {
					return Err(ParseError::InvalidSegWitProgramLength);
				}

				Ok(Fallback::SegWitProgram {
					version: version,
					program: bytes
				})
			},
			17 => {
				if bytes.len() != 20 {
					return Err(ParseError::InvalidPubKeyHashLength);
				}
				//TODO: refactor once const generics are available
				let mut pkh = [0u8; 20];
				pkh.copy_from_slice(&bytes);
				Ok(Fallback::PubKeyHash(pkh))
			}
			18 => {
				if bytes.len() != 20 {
					return Err(ParseError::InvalidScriptHashLength);
				}
				let mut sh = [0u8; 20];
				sh.copy_from_slice(&bytes);
				Ok(Fallback::ScriptHash(sh))
			}
			_ => Err(ParseError::Skip)
		}
	}
}

impl FromBase32 for Route {
	type Err = ParseError;

	fn from_base32(field_data: &[u5]) -> Result<Route, ParseError> {
		let bytes = Vec::<u8>::from_base32(field_data)?;

		if bytes.len() % 51 != 0 {
			return Err(ParseError::UnexpectedEndOfTaggedFields);
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

		Ok(Route(route_hops))
	}
}

#[derive(PartialEq, Debug)]
pub enum ParseError {
	Bech32Error(bech32::Error),
	ParseAmountError(ParseIntError),
	MalformedSignature(secp256k1::Error),
	BadPrefix,
	UnknownCurrency,
	UnknownSiPrefix,
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
	Skip
}

impl Display for ParseError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		use self::ParseError::*;
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

impl error::Error for ParseError {
	fn description(&self) -> &str {
		use self::ParseError::*;
		match *self {
			Bech32Error(_) => "invalid bech32",
			ParseAmountError(_) => "invalid amount in hrp",
			MalformedSignature(_) => "invalid secp256k1 signature",
			BadPrefix => "did not begin with 'ln'",
			UnknownCurrency => "currency code unknown",
			UnknownSiPrefix => "unknown SI prefix",
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
			Skip => "the tagged field has to be skipped because of an unexpected, but allowed property",
		}
	}
}

macro_rules! from_error {
    ($my_error:expr, $extern_error:ty) => {
        impl From<$extern_error> for ParseError {
            fn from(e: $extern_error) -> Self {
                $my_error(e)
            }
        }
    }
}

from_error!(ParseError::MalformedSignature, secp256k1::Error);
from_error!(ParseError::ParseAmountError, ParseIntError);
from_error!(ParseError::DescriptionDecodeError, str::Utf8Error);

impl From<bech32::Error> for ParseError {
	fn from(e: bech32::Error) -> Self {
		match e {
			bech32::Error::InvalidPadding => ParseError::PaddingError(e),
			_ => ParseError::Bech32Error(e)
		}
	}
}

#[cfg(test)]
mod test {
	use de::ParseError;
	use secp256k1::{PublicKey, Secp256k1};
	use bech32::u5;

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

	fn from_bech32(bytes_5b: &[u8]) -> Vec<u5> {
		bytes_5b
			.iter()
			.map(|c| u5::try_from_u8(CHARSET_REV[*c as usize] as u8).unwrap())
			.collect()
	}

	#[test]
	fn test_parse_currency_prefix() {
		use Currency;

		assert_eq!("bc".parse::<Currency>(), Ok(Currency::Bitcoin));
		assert_eq!("tb".parse::<Currency>(), Ok(Currency::BitcoinTestnet));
		assert_eq!("something_else".parse::<Currency>(), Err(ParseError::UnknownCurrency))
	}

	#[test]
	fn test_parse_int_from_bytes_be() {
		use de::parse_int_be;

		assert_eq!(parse_int_be::<u32, u8>(&[1, 2, 3, 4], 256), Some(16909060));
		assert_eq!(parse_int_be::<u32, u8>(&[1, 3], 32), Some(35));
		assert_eq!(parse_int_be::<u32, u8>(&[1, 2, 3, 4, 5], 256), None);
	}

	//TODO: test error conditions

	#[test]
	fn test_parse_sha256_hash() {
		use Sha256;
		use bech32::FromBase32;

		let input = from_bech32(
			"qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq".as_bytes()
		);

		let hash = [
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03,
			0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x01, 0x02
		];
		let expected = Ok(Sha256(hash));

		assert_eq!(Sha256::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_description() {
		use ::Description;
		use bech32::FromBase32;

		let input = from_bech32("xysxxatsyp3k7enxv4js".as_bytes());
		let expected = Ok(Description::new("1 cup coffee".to_owned()).unwrap());
		assert_eq!(Description::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_payee_pub_key() {
		use ::PayeePubKey;
		use bech32::FromBase32;

		let input = from_bech32("q0n326hr8v9zprg8gsvezcch06gfaqqhde2aj730yg0durunfhv66".as_bytes());
		let pk_bytes = [
			0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63,
			0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde,
			0x0f, 0x93, 0x4d, 0xd9, 0xad
		];
		let expected = Ok(PayeePubKey(
			PublicKey::from_slice(&Secp256k1::without_caps(), &pk_bytes[..]).unwrap()
		));

		assert_eq!(PayeePubKey::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_expiry_time() {
		use ::ExpiryTime;
		use bech32::FromBase32;

		let input = from_bech32("pu".as_bytes());
		let expected = Ok(ExpiryTime{seconds: 60});

		assert_eq!(ExpiryTime::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_min_final_cltv_expiry() {
		use ::MinFinalCltvExpiry;
		use bech32::FromBase32;

		let input = from_bech32("pr".as_bytes());
		let expected = Ok(MinFinalCltvExpiry(35));

		assert_eq!(MinFinalCltvExpiry::from_base32(&input), expected);
	}

	#[test]
	fn test_parse_fallback() {
		use Fallback;
		use bech32::FromBase32;

		let cases = vec![
			(
				from_bech32("3x9et2e20v6pu37c5d9vax37wxq72un98".as_bytes()),
				Fallback::PubKeyHash([
					0x31, 0x72, 0xb5, 0x65, 0x4f, 0x66, 0x83, 0xc8, 0xfb, 0x14, 0x69, 0x59, 0xd3,
					0x47, 0xce, 0x30, 0x3c, 0xae, 0x4c, 0xa7
				])
			),
			(
				from_bech32("j3a24vwu6r8ejrss3axul8rxldph2q7z9".as_bytes()),
				Fallback::ScriptHash([
					0x8f, 0x55, 0x56, 0x3b, 0x9a, 0x19, 0xf3, 0x21, 0xc2, 0x11, 0xe9, 0xb9, 0xf3,
					0x8c, 0xdf, 0x68, 0x6e, 0xa0, 0x78, 0x45
				])
			),
			(
				from_bech32("qw508d6qejxtdg4y5r3zarvary0c5xw7k".as_bytes()),
				Fallback::SegWitProgram {
					version: u5::try_from_u8(0).unwrap(),
					program: Vec::from(&[
						0x75u8, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
						0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
					][..])
				}
			)
		];

		for (input, expected) in cases.into_iter() {
			assert_eq!(Fallback::from_base32(&input), Ok(expected));
		}
	}

	#[test]
	fn test_parse_route() {
		use RouteHop;
		use ::Route;
		use bech32::FromBase32;

		let input = from_bech32(
			"q20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqa\
			fqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq".as_bytes()
		);

		let mut expected = Vec::<RouteHop>::new();
		expected.push(RouteHop {
			pubkey: PublicKey::from_slice(
				&Secp256k1::without_caps(),
				&[
					0x02u8, 0x9e, 0x03, 0xa9, 0x01, 0xb8, 0x55, 0x34, 0xff, 0x1e, 0x92, 0xc4, 0x3c,
					0x74, 0x43, 0x1f, 0x7c, 0xe7, 0x20, 0x46, 0x06, 0x0f, 0xcf, 0x7a, 0x95, 0xc3,
					0x7e, 0x14, 0x8f, 0x78, 0xc7, 0x72, 0x55
				][..]
			).unwrap(),
			short_channel_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
			fee_base_msat: 1,
			fee_proportional_millionths: 20,
			cltv_expiry_delta: 3
		});
		expected.push(RouteHop {
			pubkey: PublicKey::from_slice(
				&Secp256k1::without_caps(),
				&[
					0x03u8, 0x9e, 0x03, 0xa9, 0x01, 0xb8, 0x55, 0x34, 0xff, 0x1e, 0x92, 0xc4, 0x3c,
					0x74, 0x43, 0x1f, 0x7c, 0xe7, 0x20, 0x46, 0x06, 0x0f, 0xcf, 0x7a, 0x95, 0xc3,
					0x7e, 0x14, 0x8f, 0x78, 0xc7, 0x72, 0x55
				][..]
			).unwrap(),
			short_channel_id: [0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a],
			fee_base_msat: 2,
			fee_proportional_millionths: 30,
			cltv_expiry_delta: 4
		});

		assert_eq!(Route::from_base32(&input), Ok(Route(expected)));
	}

	#[test]
	fn test_raw_invoice_deserialization() {
		use TaggedField::*;
		use secp256k1::{RecoveryId, RecoverableSignature, Secp256k1};
		use {RawInvoice, RawHrp, RawDataPart, Currency, Sha256};

		assert_eq!(
			"lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmw\
			wd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9\
			ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w".parse(),
			Ok(
				RawInvoice {
					hrp: RawHrp {
						currency: Currency::Bitcoin,
						raw_amount: None,
						si_prefix: None,
					},
					data: RawDataPart {
						timestamp: 1496314658,
						tagged_fields: vec![
							PaymentHash(Sha256([
								0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00,
								0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01,
								0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02
							])).into(),
							Description(::Description::new("Please consider supporting this project".to_owned()).unwrap()).into(),
						],
						signature: RecoverableSignature::from_compact(
							&Secp256k1::without_caps(),
							&[
								0x38u8, 0xec, 0x68, 0x91, 0x34, 0x5e, 0x20, 0x41, 0x45, 0xbe, 0x8a,
								0x3a, 0x99, 0xde, 0x38, 0xe9, 0x8a, 0x39, 0xd6, 0xa5, 0x69, 0x43,
								0x4e, 0x18, 0x45, 0xc8, 0xaf, 0x72, 0x05, 0xaf, 0xcf, 0xcc, 0x7f,
								0x42, 0x5f, 0xcd, 0x14, 0x63, 0xe9, 0x3c, 0x32, 0x88, 0x1e, 0xad,
								0x0d, 0x6e, 0x35, 0x6d, 0x46, 0x7e, 0xc8, 0xc0, 0x25, 0x53, 0xf9,
								0xaa, 0xb1, 0x5e, 0x57, 0x38, 0xb1, 0x1f, 0x12, 0x7f
							],
							RecoveryId::from_i32(0).unwrap()
						).unwrap(),
					},
				}
			)
		)
	}
}