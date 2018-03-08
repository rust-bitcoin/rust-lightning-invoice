use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;

use bech32;

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
	unimplemented!()
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
			TooShortDataPart => "data part too short (should be at least 111 bech32 chars long)"
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

from_error!(Error::Bech32Error, bech32::Error);
from_error!(Error::MalformedSignature, secp256k1::Error);
from_error!(Error::ParseAmountError, ParseIntError);