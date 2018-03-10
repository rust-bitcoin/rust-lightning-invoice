use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;
use std::str;

use bech32;
use bech32::convert_bits;

use chrono::{DateTime, Utc, TimeZone};

use regex::Regex;

use secp256k1;
use secp256k1::{Signature, Secp256k1};

use super::{Currency, TaggedField};

pub(super) fn parse_hrp(hrp: &str) -> Result<(Currency, Option<u64>), Error> {
	let re = Regex::new(r"^ln([^0-9]*)([0-9]*)([munp]?)$").unwrap();
	let parts = match re.captures(&hrp) {
		Some(capture_group) => capture_group,
		None => return Err(Error::MalformedHRP)
	};

	let currency = parts[0].parse::<Currency>()?;

	let amount = if !parts[1].is_empty() {
		Some(parts[1].parse::<u64>()?)
	} else {
		None
	};

	// `get_multiplier(x)` will only return `None` if `x` is not "m", "u", "n" or "p", which
	// due to the above regex ensures that `get_multiplier(x)` iif `x == ""`, so it's ok to
	// convert a none to 1BTC aka 10^12pBTC.
	let multiplier = parts[2].chars().next().and_then(|suffix| {
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
pub(super) fn parse_data(data: &[u8]) -> Result<(DateTime<Utc>, Vec<TaggedField>, Signature), Error> {
	if data.len() < 104 + 7 { // signature + timestamp
		return Err(Error::TooShortDataPart);
	}

	let (time, data) = data.split_at(8);
	let (tagged, signature) = data.split_at(data.len() - 32);
	assert_eq!(time.len(), 7);
	assert_eq!(signature.len(), 104);

	let time = Utc.timestamp(be_u64(time) as i64, 0);
	let signature = Signature::from_compact(&Secp256k1::without_caps(), signature)?;
	let tagged = parse_tagged_parts(tagged)?;

	Ok((time, tagged, signature))
}

// interpret 5bit bech32 characters as big endian u64
fn be_u64(bytes_5b: &[u8]) -> u64 {
	bytes_5b.iter().fold(0, |acc, b| acc * 32 + (*b as u64))
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

		let len = be_u64(len) as usize;
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

fn parse_field(tag: u8, field_data: &[u8]) -> Result<Option<TaggedField>, Error> {
	match tag {
		TaggedField::TAG_PAYMENT_HASH => parse_payment_hash(field_data),
		_ => {
			// "A reader MUST skip over unknown fields"
			Ok(None)
		}
	}
}

fn parse_payment_hash(field_data: &[u8]) -> Result<Option<TaggedField>, Error> {
	if field_data.len() != 52 {
		// "A reader MUST skip over […] a p […] field that does not have data_length 52 […]."
		Ok(None)
	} else {
		let mut hash: [u8; 32] = Default::default();
		hash.copy_from_slice(&convert_bits(field_data, 5, 8, false)?);
		Ok(Some(TaggedField::PaymentHash(hash)))
	}
}

fn parse_description(field_data: &[u8]) -> Result<Option<TaggedField>, Error> {
	let bytes = convert_bits(field_data, 5, 8, false)?;
	let description = String::from(str::from_utf8(&bytes)?);
	Ok(Some(TaggedField::Description(description)))
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
			},
			DescriptionDecodeError(ref e) => {
				write!(f, "{} ({})", self.description(), e)
			},
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
		15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
		1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
		-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
		1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
	];

	fn from_bech32(bytes_5b: &[u8]) -> Vec<u8> {
		bytes_5b.iter().map(|c| CHARSET_REV[*c as usize] as u8).collect()
	}

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
}