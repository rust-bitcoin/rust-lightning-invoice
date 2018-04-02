use std::fmt;
use std::fmt::{Display, Formatter};

pub use super::Currency;

impl Display for Currency {
	fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
		let currency_code = match self {
			&Currency::Bitcoin => "bc",
			&Currency::BitcoinTestnet => "tb",
		};
		write!(f, "{}", currency_code)
	}
}

#[cfg(test)]
mod test {
	#[test]
	fn test_currency_code() {
		use super::Currency;
		assert_eq!("bc", Currency::Bitcoin.to_string());
		assert_eq!("tb", Currency::BitcoinTestnet.to_string());
	}
}