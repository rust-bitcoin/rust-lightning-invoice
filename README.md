# lightning-invoice (WIP)
[![Build Status](https://travis-ci.org/rust-bitcoin/rust-lightning-invoice.svg?branch=master)](https://travis-ci.org/rust-bitcoin/rust-lightning-invoice)
[Coverage Report](https://rust-bitcoin.github.io/rust-lightning-invoice/target/kcov/merged/)

This repo provides datastructures for BOLT 11 lightning invoices.
It provides functions to parse and serialize invoices from and to bech32.

**Please be sure to run the test suite since we need to check assumptions
regarding `SystemTime`'s bounds on your platform. You can also call `check_platform`
on startup or in your test suite to do so.**

## Contributing
* same coding style standard as [rust-bitcoin/rust-lightning](https://github.com/rust-bitcoin/rust-lightning)
* use tabs and spaces (appropriately)
* no unnecessary dependencies