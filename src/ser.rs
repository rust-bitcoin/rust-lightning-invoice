use std::fmt;
use std::fmt::{Display, Formatter};
use bech32::{Bech32, ToBase32, u5};

use secp256k1::Secp256k1;

use ::*;


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

fn encode_int_be_base256<T: Into<u64>>(int: T) -> Vec<u8> {
	let base = 256u64;

	let mut out_vec = Vec::<u8>::new();

	let mut rem_int: u64 = int.into();
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
		let mut encoded = Vec::<u5>::new();

		// encode timestamp
		encoded.extend(&encode_int_be_base32(self.timestamp));

		// encode tagged fields
		for tagged_field in self.tagged_fields.iter() {
			encoded.extend(tagged_field.to_base32().iter());
		}

		// TODO: refactor to avoid copying (maybe using iterable byte array builder?)
		// encode signature
		let (recovery_id, signature) = self.signature.serialize_compact(&Secp256k1::without_caps());
		let mut signature_bytes = Vec::<u8>::with_capacity(65);
		signature_bytes.extend_from_slice(&signature[..]);
		signature_bytes.push(recovery_id.to_i32() as u8); // can only be in range 0..4
		encoded.extend(signature_bytes.to_base32());

		encoded
	}
}

impl<'f> ToBase32<Vec<u5>> for RawTaggedField {
	fn to_base32(&self) -> Vec<u5> {
		match *self {
			RawTaggedField::UnknownTag(tag, ref content) => {
				let mut encoded = Vec::<u5>::with_capacity(content.len() + 1);
				encoded.push(tag);
				encoded.extend_from_slice(content);
				encoded
			},
			RawTaggedField::KnownTag(ref tagged_field) => {
				tagged_field.to_base32()
			}
		}
	}
}

impl ToBase32<Vec<u5>> for TaggedField {
	fn to_base32(&self) -> Vec<u5> {
		let (tag, data) = match *self {
			TaggedField::PaymentHash(ref hash) => {
				(constants::TAG_PAYMENT_HASH, hash.to_base32())
			},
			TaggedField::Description(ref description) => {
				let data = description.as_bytes().to_base32();
				// FIXME: ensure string length by type (newtype)
				assert!(data.len() < 1024);
				(constants::TAG_DESCRIPTION, data)
			},
			TaggedField::PayeePubKey(ref pub_key) => {
				(constants::TAG_PAYEE_PUB_KEY, (&pub_key.serialize()[..]).to_base32())
			},
			TaggedField::DescriptionHash(ref hash) => {
				(constants::TAG_DESCRIPTION_HASH, hash.to_base32())
			},
			TaggedField::ExpiryTime(duration) => {
				// FIXME: ensure duration range by type
				let data = encode_int_be_base32(duration.as_secs());
				(constants::TAG_EXPIRY_TIME, data)
			},
			TaggedField::MinFinalCltvExpiry(expiry) => {
				(constants::TAG_MIN_FINAL_CLTV_EXPIRY, encode_int_be_base32(expiry))
			},
			TaggedField::Fallback(ref fallback_address) => {
				let data = match *fallback_address {
					Fallback::SegWitProgram {version: v, program: ref p} => {
						let mut data = Vec::<u5>::with_capacity(1);
						data.push(v);
						data.extend_from_slice(&p.to_base32());
						data
					},
					Fallback::PubKeyHash(ref hash) => {
						let mut data = Vec::<u5>::with_capacity(1);
						data.push(u5::try_from_u8(17).unwrap());
						data.extend_from_slice(&hash.to_base32());
						data
					},
					Fallback::ScriptHash(ref hash) => {
						let mut data = Vec::<u5>::with_capacity(1);
						data.push(u5::try_from_u8(18).unwrap());
						data.extend_from_slice(&hash.to_base32());
						data
					}
				};
				(constants::TAG_FALLBACK, data)
			},
			TaggedField::Route(ref route_hops) => {
				let mut bytes = Vec::<u8>::new();
				for hop in route_hops.iter() {
					bytes.extend_from_slice(&hop.pubkey.serialize()[..]);
					bytes.extend_from_slice(&hop.short_channel_id[..]);

					let fee_base_msat = try_stretch(
						encode_int_be_base256(hop.fee_base_msat),
						4
					).expect("sizeof(u32) == 4");
					bytes.extend_from_slice(&fee_base_msat);

					let fee_proportional_millionths = try_stretch(
						encode_int_be_base256(hop.fee_proportional_millionths),
						4
					).expect("sizeof(u32) == 4");
					bytes.extend_from_slice(&fee_proportional_millionths);

					let cltv_expiry_delta = try_stretch(
						encode_int_be_base256(hop.cltv_expiry_delta),
						2
					).expect("sizeof(u16) == 2");
					bytes.extend_from_slice(&cltv_expiry_delta);
				}

				assert_eq!(
					bytes.len() % 51,
					0,
					"One hop is 51 bytes long, so all hops should be a multiple of that long."
				);

				let data = bytes.to_base32();

				// FIXME: ensure max len by type
				assert!(data.len() < 1024);

				(constants::TAG_ROUTE, data)
			},
		};

		assert!(data.len() < 1024, "Every tagged field data can be at most 1023 bytes long.");

		let mut sized_data = Vec::<u5>::with_capacity(data.len() + 3);
		// TODO: think about saving tag constants as u5c
		sized_data.push(u5::try_from_u8(tag).expect("Tags should be <32."));
		sized_data.extend_from_slice(
			&try_stretch(
				encode_int_be_base32(data.len() as u64),
				2
			).expect("Can't be longer than 2, see assert above.")
		);
		sized_data.extend_from_slice(&data);

		sized_data
	}
}

#[cfg(test)]
mod test {
	use bech32::CheckBase32;

	#[test]
	fn test_currency_code() {
		use Currency;

		assert_eq!("bc", Currency::Bitcoin.to_string());
		assert_eq!("tb", Currency::BitcoinTestnet.to_string());
	}

	#[test]
	fn test_raw_hrp() {
		use ::{Currency, RawHrp, SiPrefix};

		let hrp = RawHrp {
			currency: Currency::Bitcoin,
			raw_amount: Some(100),
			si_prefix: Some(SiPrefix::Micro),
		};

		assert_eq!(hrp.to_string(), "lnbc100u");
	}

	#[test]
	fn test_encode_int_be_base32() {
		use ser::encode_int_be_base32;

		let input: u64 = 33764;
		let expected_out = CheckBase32::check_base32(&[1, 0, 31, 4]).unwrap();

		assert_eq!(expected_out, encode_int_be_base32(input));
	}

	#[test]
	fn test_encode_int_be_base256() {
		use ser::encode_int_be_base256;

		let input: u64 = 16842530;
		let expected_out = vec![1, 0, 255, 34];

		assert_eq!(expected_out, encode_int_be_base256(input));
	}
}
