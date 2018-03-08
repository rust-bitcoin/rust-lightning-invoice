use std::error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::ParseIntError;

use bech32;

use regex::Regex;
use secp256k1;

use super::Currency;

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

#[derive(PartialEq, Debug)]
pub enum Error {
    Bech32Error(bech32::Error),
    ParseAmountError(ParseIntError),
    MalformedSignature(secp256k1::Error),
    BadPrefix,
    UnknownCurrency,
    MalformedHRP
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        use self::Error::*;
        use std::error::Error;
        match *self {
            // TODO: find a way to combine the first three arms (e as error::Error?)
            Bech32Error(ref e) => {
                write!(f, "{} ({})", self.description(), e)
            },
            ParseAmountError(ref e) => {
                write!(f, "{} ({})", self.description(), e)
            },
            MalformedSignature(ref e) => {
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
            MalformedHRP => "malformed human readable part"
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