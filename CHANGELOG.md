# 0.5.0 - Aug 26, 2025

- bump rust elements dep to 0.26.0
- get CI up to date; pin nightly rust version; fix some clippy lints [#98](https://github.com/ElementsProject/elements-miniscript/pull/98)
- Pegin desc wildcard [#96](https://github.com/ElementsProject/elements-miniscript/pull/96)
- Remove inner checksum in pegin descriptor [#95](https://github.com/ElementsProject/elements-miniscript/pull/95)
- simplicity: swap program and witness data in satisfaction [#94](https://github.com/ElementsProject/elements-miniscript/pull/94)

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

