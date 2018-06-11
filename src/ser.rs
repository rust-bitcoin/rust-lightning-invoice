use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::{Rem, Div, Sub};

use bech32::{Bech32, ToBase32, u5};

use num_traits::checked_pow;

use ::*;
use num_traits::real::Real;


trait TryIntoInt<T> {
	type Error;
	fn try_into(self) -> Result<T, Self::Error>;
}

impl TryIntoInt<u8> for u64 {
	type Error = ();

	fn try_into(self) -> Result<u8, Self::Error> {
		if self <= u8::max_value().into() {
			Ok(self as u8)
		} else {
			Err(())
		}
	}
}

impl Display for RawInvoice {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let hrp = self.hrp.to_string();
		let data  = self.data.to_base32();

		Bech32::new(hrp, data).expect("hrp len > 0").fmt(f)
	}
}

impl Display for RawHrp {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let amount = match self.raw_amount {
			Some(ref amt) => amt.to_string(),
			None => String::new(),
		};

		let si_prefix = match self.si_prefix {
			Some(ref si) => si.to_string(),
			None => String::new(),
		};

		write!(
			f,
			"ln{}{}{}",
			self.currency,
			amount,
			si_prefix
		)
	}
}

impl Display for Currency {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let currency_code = match self {
			&Currency::Bitcoin => "bc",
			&Currency::BitcoinTestnet => "tb",
		};
		write!(f, "{}", currency_code)
	}
}

impl Display for SiPrefix {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		write!(f, "{}",
			match *self {
				SiPrefix::Milli => "m",
				SiPrefix::Micro => "u",
				SiPrefix::Nano => "n",
				SiPrefix::Pico => "p",
			}
		)
	}
}

fn encode_int_be_base32(int: u64) -> Vec<u5> {
	let base = 32u64;

	let mut out_vec = Vec::<u5>::new();

	let mut rem_int = int;
	while rem_int != 0 {
		out_vec.push(u5::try_from_u8((rem_int % base) as u8).expect("always <32"));
		rem_int /= base;
	}

	out_vec.reverse();
	out_vec
}

fn encode_int_be_base256(int: u64) -> Vec<u8> {
	let base = 256u64;

	let mut out_vec = Vec::<u8>::new();

	let mut rem_int = int;
	while rem_int != 0 {
		out_vec.push((rem_int % base) as u8);
		rem_int /= base;
	}

	out_vec.reverse();
	out_vec
}

fn try_stretch<T>(mut in_vec: Vec<T>, target_len: usize) -> Option<Vec<T>>
	where T: Default + Copy
{
	if in_vec.len() > target_len {
		None
	} else if in_vec.len() == target_len {
		Some(in_vec)
	} else {
		let mut out_vec = Vec::<T>::with_capacity(target_len);
		out_vec.append(&mut vec![T::default(); target_len - in_vec.len()]);
		out_vec.append(&mut in_vec);
		Some(out_vec)
	}
}

impl ToBase32<Vec<u5>> for RawDataPart {
	fn to_base32(&self) -> Vec<u5> {
		//TODO: continue here
		unimplemented!()
	}
}

#[cfg(test)]
mod test {
	use ::*;
	use super::*;
	use bech32::CheckBase32;

	#[test]
	fn test_currency_code() {
		assert_eq!("bc", Currency::Bitcoin.to_string());
		assert_eq!("tb", Currency::BitcoinTestnet.to_string());
	}

	#[test]
	fn test_raw_hrp() {
		let hrp = RawHrp {
			currency: Currency::Bitcoin,
			raw_amount: Some(100),
			si_prefix: Some(SiPrefix::Micro),
		};

		assert_eq!(hrp.to_string(), "lnbc100u");
	}

	#[test]
	fn test_encode_int_be_base32() {
		let input: u64 = 33764;
		let expected_out = CheckBase32::check_base32(&[1, 0, 31, 4]).unwrap();

		assert_eq!(expected_out, encode_int_be_base32(input));
	}

	#[test]
	fn test_encode_int_be_base256() {
		let input: u64 = 16842530;
		let expected_out = vec![1, 0, 255, 34];

		assert_eq!(expected_out, encode_int_be_base256(input));
	}
}