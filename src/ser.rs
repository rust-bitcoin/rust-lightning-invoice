use std::fmt;
use std::fmt::{Display, Formatter};
use bech32::{Bech32, ToBase32, WriteBase32, u5};

use ::*;

impl Display for Invoice {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		self.signed_invoice.fmt(f)
	}
}

impl Display for SignedRawInvoice {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let hrp = self.raw_invoice.hrp.to_string();
		let mut data  = self.raw_invoice.data.to_base32();
		data.extend_from_slice(&self.signature.to_base32());

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
		let currency_code = match *self {
			Currency::Bitcoin => "bc",
			Currency::BitcoinTestnet => "tb",
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

/// Appends the default value of `T` to the front of the `in_vec` till it reaches the length
/// `target_length`. If `in_vec` already is too lang `None` is returned.
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

impl ToBase32 for RawDataPart {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		buffer.write_all(&self.timestamp.to_base32());

		// encode tagged fields
		for tagged_field in self.tagged_fields.iter() {
			tagged_field.write_base32(buffer);
		}
	}

	fn serialized_length(&self) -> usize {
		let a = self.timestamp.serialized_length();
		let b: usize = self.tagged_fields.iter().map(|tf| tf.serialized_length()).sum();
		a + b
	}
}

impl ToBase32 for PositiveTimestamp {
	fn to_base32(&self) -> Vec<u5> {
		try_stretch(encode_int_be_base32(self.as_unix_timestamp()), 7)
			.expect("Can't be longer than 7 u5s due to timestamp bounds")
	}

	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		buffer.write_all(&self.to_base32())
	}

	fn serialized_length(&self) -> usize {
		7
	}
}

impl ToBase32 for RawTaggedField {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		match *self {
			RawTaggedField::UnknownSemantics(ref content) => {
				buffer.write_all(&content);
			},
			RawTaggedField::KnownSemantics(ref tagged_field) => {
				tagged_field.write_base32(buffer);
			}
		}
	}

	fn serialized_length(&self) -> usize {
		match *self {
			RawTaggedField::UnknownSemantics(ref content) => content.len(),
			RawTaggedField::KnownSemantics(ref tf) => tf.serialized_length(),
		}
	}
}

impl ToBase32 for Sha256 {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		(&self.0[..]).write_base32(buffer);
	}

	fn serialized_length(&self) -> usize {
		(&self.0[..]).serialized_length()
	}
}

impl ToBase32 for Description {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		self.0.as_bytes().write_base32(buffer);
	}

	fn serialized_length(&self) -> usize {
		self.0.as_bytes().serialized_length()
	}
}

impl ToBase32 for PayeePubKey {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		(&self.0.serialize()[..]).write_base32(buffer);
	}

	fn serialized_length(&self) -> usize {
		(&self.0.serialize()[..]).serialized_length()
	}
}

impl ToBase32 for ExpiryTime {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		buffer.write_all(&encode_int_be_base32(self.as_seconds()));
	}

	fn serialized_length(&self) -> usize {
		var_int_u5s(self.as_seconds())
	}
}

impl ToBase32 for MinFinalCltvExpiry {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		buffer.write_all(&encode_int_be_base32(self.0));
	}

	fn serialized_length(&self) -> usize {
		var_int_u5s(self.0)
	}
}

impl ToBase32 for Fallback {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		match *self {
			Fallback::SegWitProgram {version: v, program: ref p} => {
				buffer.write_all(&[v]);
				p.write_base32(buffer);
			},
			Fallback::PubKeyHash(ref hash) => {
				buffer.write_all(&[u5::try_from_u8(17).unwrap()]);
				(&hash[..]).write_base32(buffer);
			},
			Fallback::ScriptHash(ref hash) => {
				buffer.write_all(&[u5::try_from_u8(18).unwrap()]);
				(&hash[..]).write_base32(buffer);
			}
		}
	}

	fn serialized_length(&self) -> usize {
		1 + match *self {
			Fallback::SegWitProgram {version: _, program: ref p} => {
				p.serialized_length()
			},
			Fallback::PubKeyHash(ref hash) => {
				(&hash[..]).serialized_length()
			},
			Fallback::ScriptHash(ref hash) => {
				(&hash[..]).serialized_length()
			},
		}
	}
}

impl ToBase32 for Route {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		let mut bytes = Vec::<u8>::new();
		for hop in self.iter() {
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

		bytes.write_base32(buffer);
	}

	fn serialized_length(&self) -> usize {
		let bytes = self.len() * 51;
		let bits = bytes * 8;
		if bits % 5 == 0 {
			bits / 5
		} else {
			bits / 5 + 1
		}
	}
}

impl ToBase32 for TaggedField {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		// Serialize a tagged filed to a buffer
		fn write_tagged_field<T: ToBase32, WI: WriteBase32>(buffer: &mut WI, tag: u8, data: &T) {
			buffer.write_all(&[u5::try_from_u8(tag).expect("tag has to be <32")]);

			// Write payload length
			buffer.write_all(
				&try_stretch(encode_int_be_base32(data.serialized_length() as u64), 2)
					.expect("length of tagged fields is max. 1023")
			);

			// Write payload
			data.write_base32(buffer);
		}

		match *self {
			TaggedField::PaymentHash(ref hash) => {
				write_tagged_field(buffer, constants::TAG_PAYMENT_HASH, hash);
			},
			TaggedField::Description(ref description) => {
				write_tagged_field(buffer, constants::TAG_DESCRIPTION, description);
			},
			TaggedField::PayeePubKey(ref pub_key) => {
				write_tagged_field(buffer, constants::TAG_PAYEE_PUB_KEY, pub_key);
			},
			TaggedField::DescriptionHash(ref hash) => {
				write_tagged_field(buffer, constants::TAG_DESCRIPTION_HASH, hash);
			},
			TaggedField::ExpiryTime(ref duration) => {
				write_tagged_field(buffer, constants::TAG_EXPIRY_TIME, duration);
			},
			TaggedField::MinFinalCltvExpiry(ref expiry) => {
				write_tagged_field(buffer, constants::TAG_MIN_FINAL_CLTV_EXPIRY, expiry);
			},
			TaggedField::Fallback(ref fallback_address) => {
				write_tagged_field(buffer, constants::TAG_FALLBACK, fallback_address);
			},
			TaggedField::Route(ref route_hops) => {
				write_tagged_field(buffer, constants::TAG_ROUTE, route_hops)
			},
		};
	}

	fn serialized_length(&self) -> usize {
		// TODO: write trait object getter to avoid redundant matches
		3 + match *self {
			TaggedField::PaymentHash(ref hash) => hash.serialized_length(),
			TaggedField::Description(ref description) => description.serialized_length(),
			TaggedField::PayeePubKey(ref pub_key) => pub_key.serialized_length(),
			TaggedField::DescriptionHash(ref hash) => hash.serialized_length(),
			TaggedField::ExpiryTime(ref duration) => duration.serialized_length(),
			TaggedField::MinFinalCltvExpiry(ref expiry) => expiry.serialized_length(),
			TaggedField::Fallback(ref fallback_address) => fallback_address.serialized_length(),
			TaggedField::Route(ref route_hops) => route_hops.serialized_length(),
		}
	}
}

impl ToBase32 for Signature {
	fn write_base32<W: WriteBase32>(&self, buffer: &mut W) {
		let (recovery_id, signature) = self.serialize_compact();

		let mut signature_bytes = [0u8; 65];
		signature_bytes[..64].clone_from_slice(&signature[..]);
		signature_bytes[64] = recovery_id.to_i32() as u8; // can only be in range 0..4

		(&signature_bytes[..]).write_base32(buffer)
	}

	fn serialized_length(&self) -> usize {
		104
	}
}

/// Find the highest set bit (ceil(log(num))), `num` may not be zero.
///
/// # Panics
/// If `num` is zero.
fn max_set_bit(num: u64) -> u8 {
	debug_assert_ne!(num, 0);

	let mut bitmask = 0x80_00_00_00__00_00_00_00;
	let mut bit_num = 64;

	while num & bitmask == 0 {
		bitmask >>= 1;
		bit_num -= 1;
	}

	bit_num
}

fn var_int_u5s(num: u64) -> usize {
	if num == 0 {
		return 1;
	}

	let bits = max_set_bit(num) as usize;
	if bits % 5 == 0 {
		bits / 5
	} else {
		bits / 5 + 1
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

	#[test]
	fn test_highest_bit() {
		let test_vectors = &[
			(123u64, 7usize),
			(456, 9),
			(8, 4),
			(1, 1),
			(2, 2),
			(3, 2),
			(4, 3),
		];

		for (num, bits) in test_vectors {
			assert_eq!(super::max_set_bit(*num) as usize, *bits);
		}
	}

	#[test]
	fn test_int_encode_length() {
		let test_vectors = &[
			(25u64, 1usize),
			(40, 2),
			(1023, 2),
			(1024, 3),
			(0, 1),
		];

		for (num, u5s) in test_vectors {
			assert_eq!(super::var_int_u5s(*num), *u5s);
		}
	}
}