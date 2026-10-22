# Unreleased

- Reject a legacy-pegin miniscript outside `or_d(multi,and_v(v:older,multi))` with `Error::BadDescriptor`.
- Remove the unused `Error::MultiAt`, `Error::MissingHash`, `Error::TaprootSpendInfoUnavialable` and `Error::TrNoExplicitScript` variants.
- Parse expressions with the rust-miniscript `expression` module instead of a local parser. `expression::Tree`, `expression::TreeIterItem` and `expression::Parens` are the rust-miniscript types. `Tree` no longer has public `name` and `args` fields, a `Display` implementation or a `from_slice` method, and `Tree::from_str` returns a rust-miniscript `Error`.
- `FromTree::from_tree`, `expression::{terminal, unary, binary}`, `SortedMultiVec::from_tree` and `Extension::from_name_tree` take `TreeIterItem` nodes instead of `&Tree` references.
- Malformed expressions are reported as rust-miniscript parse errors in `Error::BtcError`. `Error::ExpectedChar` is removed. The expression parser accepts up to 402 nested brackets across the whole expression, including the `eltr` wrapper, script tree branches and the Miniscript in each leaf, and rejects deeper expressions with a rust-miniscript `MaxRecursionDepthExceeded` parse error. The previous limit was 401, and each Taproot leaf had its own separate limit. `Error::MaxRecursiveDepthExceeded` now only reports a Taproot script tree deeper than the 128-level Taproot limit.
- In Elements expressions, curly braces are only accepted for the branches of an `eltr` script tree, which must be nameless and have exactly two children. Keys can no longer contain curly braces. The Bitcoin federation descriptor in `pegin()` follows rust-miniscript rules, which accept curly braces in `tr` script trees.
- Only `,`, `)` or `}` may follow a closing bracket, so key text such as `musig(A,B)/0`, which key types like `String` previously accepted, is rejected.
- A `sortedmulti` now contains a check that threshold must be a number without arguments.
- An empty script tree argument, as in `eltr(A,)`, is rejected. It was previously read as part of the internal key.
- `eltr` accepts a `musig(...)` internal key for key types that parse `musig(...)` text, such as `String`.
- `ct()` descriptors accept `eltr` with script leaves that contain no extension fragments.
- Miniscript and policy strings accept a trailing descriptor checksum, which is verified. The text after the last `#` is read as the checksum, so a key containing `#` is only accepted when a valid checksum follows.
- `pegin()` and `legacy_pegin()` descriptors can be parsed from strings. `LegacyPegin` displays its inner descriptor without the inner checksum. A successful parse does not check the restrictions that pegin spending places on the descriptor. Unsupported forms, such as an `eltr` Elements descriptor, still parse and can panic in the unchanged Bitcoin-side methods, including `bitcoin_address`, `bitcoin_witness_script` and `get_bitcoin_satisfaction`.

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
