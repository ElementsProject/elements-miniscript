# 0.5.0 - Sep 20, 2026

- Update rust-elements to 0.27.0 and simplicity-lang to 0.9.0.
- Raise MSRV to Rust 1.74.0.
- Adapt hash, hex, witness, asset and PSET handling to the updated Elements APIs.
- Report Simplicity leaves as unsatisfiable until their descriptor integration is rewritten.

# 0.4.0 - Oct 8, 2024

- Use rust-bitcoin 0.32.0 and rust-elements 0.25.0 [#90](https://github.com/ElementsProject/elements-miniscript/pull/90)
- Check input charset [#92](https://github.com/ElementsProject/elements-miniscript/pull/92)
- Fix a bunch of clippy lints and get CI working again [#89](https://github.com/ElementsProject/elements-miniscript/pull/89)
- avoid setting {BITCOIND,ELEMENTSD}\_EXE in setup [#88](https://github.com/ElementsProject/elements-miniscript/pull/88)
- [Removed `to_string_no_chksum`](https://github.com/ElementsProject/elements-miniscript/pull/86). This method was poorly-named and broken. Use the alternate display `{:#}` formatter instead to format descriptors without a checksum.
- Implement federation descriptor tweak with claiming script to match elements core getpeginaddress [#87](https://github.com/ElementsProject/elements-miniscript/pull/87)
- elip151: multisig test vectors [#84](https://github.com/ElementsProject/elements-miniscript/pull/84)

# 0.3.1 - May 10, 2024

- [Fixed](https://github.com/ElementsProject/elements-miniscript/pull/81) ELIP-151 hash calculation

# 0.3.0 - Jan 30, 2024

- Add simplicity
- Use rust-bitcoin 0.31.0
- [elip150](https://github.com/ElementsProject/ELIPs/blob/main/elip-0150.mediawiki)
- [elip151](https://github.com/ElementsProject/ELIPs/blob/main/elip-0151.mediawiki)

# 0.2.0 - June 15, 2023

- Still rapid iteration, very unstable.
