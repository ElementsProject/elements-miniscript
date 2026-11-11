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
- Breaking: `DescriptorKeyParseError` is a `#[non_exhaustive]` enum instead of a struct holding a string, and no longer derives `Copy`. The new `MalformedKeyDataKind` enum describes malformed key data. Messages start with a lowercase letter and follow rust-miniscript. The Elements-only `HexPrivateKey` variant reports a bad hex view key in a `ct()` descriptor. Ported from rust-miniscript 497c5a3 and bd5db6a.
- Breaking: `ConversionError` is replaced by the `#[non_exhaustive]` `NonDefiniteKeyError`, with `Wildcard`, `Multipath`, `HardenedStep` and `MaximumDepthExceeded` variants. It is returned by `DefiniteDescriptorKey::new`, `DescriptorPublicKey::at_derivation_index`, `Descriptor::at_derivation_index`, `Descriptor::derived_descriptor`, `Descriptor::find_derivation_index_for_spk`, `confidential::Descriptor::at_derivation_index` and the PSET `update_with_descriptor_unchecked` methods, and held by `UtxoUpdateError::DerivationError` and `OutputUpdateError::DerivationError`. `Error::Conversion` becomes `Error::NonDefiniteKey`. Ported from rust-miniscript 258873f, dad3532, 7b3b3a8, 4930ccb and 613ed0d.
- Breaking: `DefiniteDescriptorKey::new` is public and returns `Result<Self, NonDefiniteKeyError>`. Keys with a wildcard were already rejected. It now also rejects a hardened derivation step after an xpub (`HardenedStep`), several derivation paths (`Multipath`), and a derivation deeper than BIP32's maximum depth of 255 (`MaximumDepthExceeded`), checked in the order wildcard, hardened step, multipath, depth. `DescriptorPublicKey::at_derivation_index`, and the descriptor methods built on it, return the same errors. `DefiniteDescriptorKey::from_str` wraps them in `DescriptorKeyParseError::NonDefiniteKey`, so `Descriptor::<DefiniteDescriptorKey>::from_str` now rejects hardened and multipath keys, which previously parsed and panicked when derived, for example in `script_pubkey`. A `ct()` descriptor whose bare blinding key has a hardened wildcard now fails in `at_derivation_index` instead of `address`. Ported from rust-miniscript dad3532, 7b3b3a8, 97c948d and 613ed0d.
- Parsing an xpub or xprv whose derivation goes deeper than BIP32's maximum depth of 255 fails with `DescriptorKeyParseError::MalformedKeyData(MalformedKeyDataKind::MaximumDepthExceeded)`, so such a string never reaches the constructor. A wildcard or multipath step counts as one step, and origin steps don't count. The constructor's `NonDefiniteKeyError::MaximumDepthExceeded` is only returned for keys built in code. Ported from rust-miniscript f2862f7.
- Breaking: `DefiniteDescriptorKey::derive_public_key` returns a `bitcoin::PublicKey` and `Descriptor::<DefiniteDescriptorKey>::derived_descriptor` returns a descriptor, instead of a `Result`. Ported from rust-miniscript c169af0.
- Breaking: the deprecated `DescriptorPublicKey::is_deriveable`, `DescriptorPublicKey::derive`, `Descriptor::is_deriveable` and `Descriptor::derive` are removed. Use `has_wildcard` and `at_derivation_index`. Ported from rust-miniscript 77ed78b.
- Breaking: `UtxoUpdateError` and `OutputUpdateError` derive only `Debug`, `PartialEq`, `Eq` and `Clone`. `NonDefiniteKeyError`, `MalformedKeyDataKind` and `DescriptorKeyParseError` derive `Eq`. Ported from rust-miniscript 627d963.
- Add `DescriptorPublicKey::has_hardened_step`. Ported from rust-miniscript 7b3b3a8 and, for its doc line, 4906bed (partial).
- `DescriptorSecretKey::to_public` converts a multi-xpriv into a multi-xpub when all hardened derivation steps are shared among its paths, instead of always failing. Ported from rust-miniscript 7d3e1e8.

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
