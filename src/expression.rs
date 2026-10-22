// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! # Function-like Expression Language
//!
//! Expression strings are parsed into trees by the rust-miniscript
//! [expression module](bitcoin_miniscript::expression), whose tree types are
//! re-exported here. This module provides the helpers used to convert the
//! nodes of such a tree into Elements Miniscript types.

use std::str::FromStr;

pub use bitcoin_miniscript::expression::{Parens, Tree, TreeIterItem};
use bitcoin_miniscript::ParseTreeError;

use crate::{errstr, Error};

/// A trait for extracting a structure from a Tree representation in token form
pub trait FromTree: Sized {
    /// Extract a structure from Tree representation
    fn from_tree(root: TreeIterItem<'_>) -> Result<Self, Error>;
}

/// Writes a `musig(...)` key expression node back into its string form.
fn write_key_expression(node: TreeIterItem<'_>, s: &mut String) -> Result<(), Error> {
    verify_round_parens(node)?;
    s.push_str(node.name());
    if node.n_children() > 0 {
        s.push('(');
        for (n, child) in node.children().enumerate() {
            if n > 0 {
                s.push(',');
            }
            write_key_expression(child, s)?;
        }
        s.push(')');
    }
    Ok(())
}

/// Checks that the children of a node, if it has any, are enclosed in round brackets.
///
/// Curly braces are only allowed in the script tree of a Taproot descriptor.
pub(crate) fn verify_round_parens(node: TreeIterItem<'_>) -> Result<(), Error> {
    if node.parens() == Parens::Curly {
        Err(Error::from(ParseTreeError::IllegalCurlyBrace {
            pos: node.children_pos(),
        }))
    } else {
        Ok(())
    }
}

/// Parse a string as a number, for timelocks, thresholds, indices or values
///
/// Unlike the rust-miniscript function of the same name, which only returns
/// `u32`, this parses any integer type, including signed ones.
pub fn parse_num<T: FromStr>(s: &str) -> Result<T, Error> {
    if s.len() > 1 {
        let ch = s.chars().next().unwrap();
        let ch = if ch == '-' {
            s.chars().nth(1).ok_or(Error::Unexpected(
                "Negative number must follow dash sign".to_string(),
            ))?
        } else {
            ch
        };
        if !('1'..='9').contains(&ch) {
            return Err(Error::Unexpected(
                "Number must start with a digit 1-9".to_string(),
            ));
        }
    }
    T::from_str(s).map_err(|_| errstr(s))
}

/// Attempts to parse a terminal expression
///
/// A `musig(...)` key expression is converted as a whole, including its children.
pub fn terminal<T, F, Err>(term: TreeIterItem<'_>, convert: F) -> Result<T, Error>
where
    F: FnOnce(&str) -> Result<T, Err>,
    Err: ToString,
{
    if term.n_children() == 0 {
        convert(term.name()).map_err(|e| Error::Unexpected(e.to_string()))
    } else if term.name() == "musig" {
        let mut key = String::new();
        write_key_expression(term, &mut key)?;
        convert(&key).map_err(|e| Error::Unexpected(e.to_string()))
    } else {
        Err(errstr(term.name()))
    }
}

/// Attempts to parse an expression with exactly one child
///
/// This checks the number of children of `term`, not the type of its brackets.
pub fn unary<L, T, F>(term: TreeIterItem<'_>, convert: F) -> Result<T, Error>
where
    L: FromTree,
    F: FnOnce(L) -> T,
{
    match (term.n_children(), term.first_child()) {
        (1, Some(child)) => {
            let left = FromTree::from_tree(child)?;
            Ok(convert(left))
        }
        _ => Err(errstr(term.name())),
    }
}

/// Attempts to parse an expression with exactly two children
///
/// This checks the number of children of `term`, not the type of its brackets.
pub fn binary<L, R, T, F>(term: TreeIterItem<'_>, convert: F) -> Result<T, Error>
where
    L: FromTree,
    R: FromTree,
    F: FnOnce(L, R) -> T,
{
    let (left, right) = term
        .verify_binary("binary expression")
        .map_err(|_| errstr(term.name()))?;
    let left = FromTree::from_tree(left)?;
    let right = FromTree::from_tree(right)?;
    Ok(convert(left, right))
}

#[cfg(test)]
mod tests {
    use std::fmt;
    use std::str::FromStr;

    use super::parse_num;
    use crate::descriptor::pegin::{LegacyPegin, Pegin};
    use crate::extensions::{Arith, CovExtArgs, CovOps, CovenantExt, Expr};
    use crate::policy::{concrete, semantic};
    use crate::{ConfidentialDescriptor, Descriptor, DescriptorPublicKey, Miniscript, Segwitv0};

    #[test]
    fn test_parse_num() {
        assert!(parse_num::<u32>("0").is_ok());
        assert!(parse_num::<u32>("00").is_err());
        assert!(parse_num::<u32>("0000").is_err());
        assert!(parse_num::<u32>("06").is_err());
        assert!(parse_num::<u32>("+6").is_err());
        assert!(parse_num::<u32>("-6").is_err());
    }

    #[test]
    fn extension_child_arity_and_order() {
        use crate::extensions::Extension;

        for name in ["num64_eq", "num64_geq", "num64_gt", "num64_lt", "num64_leq"] {
            let input = format!("{name}(1,2)");
            let parsed = Arith::<String>::from_str(&input).unwrap();
            assert_eq!(parsed.to_string(), input);

            for args in ["", "1", "1,2,3", "1,2,3,4"] {
                let input = format!("{name}({args})");
                let tree = super::Tree::from_str(&input).unwrap();
                let children: Vec<_> = tree.root().children().collect();
                assert!(Arith::<String>::from_name_tree(name, &children).is_err());
                assert!(Arith::<String>::from_str(&input).is_err());
            }
        }

        for (name, args) in [
            ("is_exp_asset", "out_asset(0)"),
            ("is_exp_value", "out_value(0)"),
            ("asset_eq", "inp_asset(0),out_asset(1)"),
            ("value_eq", "inp_value(0),out_value(1)"),
            ("spk_eq", "inp_spk(0),out_spk(1)"),
            ("curr_idx_eq", "3"),
            ("idx_eq", "1,2"),
        ] {
            let input = format!("{name}({args})");
            let tree = super::Tree::from_str(&input).unwrap();
            let children: Vec<_> = tree.root().children().collect();
            let parsed = CovOps::<CovExtArgs>::from_str(&input).unwrap();
            assert_eq!(parsed.to_string(), input);
            assert_eq!(
                CovOps::<CovExtArgs>::from_name_tree(name, &children).ok(),
                Some(parsed)
            );

            assert!(
                CovOps::<CovExtArgs>::from_name_tree(name, &children[..children.len() - 1])
                    .is_err()
            );
            let extra = format!("{name}({args},0,1,2)");
            let tree = super::Tree::from_str(&extra).unwrap();
            let children: Vec<_> = tree.root().children().collect();
            assert!(CovOps::<CovExtArgs>::from_name_tree(name, &children).is_err());
            let err = CovOps::<CovExtArgs>::from_str(&extra).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "unexpected «{}({} args) while parsing Extension»",
                    name,
                    children.len()
                )
            );
        }
    }

    /// Checks that `s` parses, and that it is rejected whenever any one pair of its
    /// round brackets is replaced with curly braces.
    fn check_curly_braces<T>(s: &str)
    where
        T: FromStr,
        T::Err: fmt::Debug,
    {
        T::from_str(s).unwrap();

        let mut open = vec![];
        let mut n_variants = 0;
        for (pos, ch) in s.char_indices() {
            match ch {
                '(' => open.push(pos),
                ')' => {
                    let mut variant = s.as_bytes().to_vec();
                    variant[open.pop().unwrap()] = b'{';
                    variant[pos] = b'}';
                    let variant = String::from_utf8(variant).unwrap();
                    assert!(T::from_str(&variant).is_err(), "accepted {}", variant);
                    n_variants += 1;
                }
                _ => {}
            }
        }
        assert!(n_variants > 0);
    }

    #[test]
    fn curly_braces_only_in_script_trees() {
        type Desc = Descriptor<String, CovenantExt<CovExtArgs>>;

        check_curly_braces::<Miniscript<String, Segwitv0>>(
            "and_v(v:pk(A),or_d(multi(1,B,C),thresh(1,pk(musig(D,E)),s:pk(F))))",
        );
        check_curly_braces::<concrete::Policy<String>>(
            "or(1@pk(A),3@thresh(2,pk(B),sha256(H),and(pk(C),older(10))))",
        );
        check_curly_braces::<semantic::Policy<String>>("or(pk(A),and(pk(B),older(10)))");
        check_curly_braces::<Expr<CovExtArgs>>("add(inp_v(0),mul(out_v(idx_add(1,curr_idx)),2))");
        check_curly_braces::<Arith<String>>(
            "num64_eq(price_oracle1(K,123213),add(inp_v(0),28004))",
        );
        check_curly_braces::<CovOps<CovExtArgs>>("asset_eq(inp_asset(0),out_asset(curr_idx))");

        for desc in [
            "elpkh(A)",
            "elwpkh(A)",
            "elsh(wpkh(A))",
            "elsh(wsh(sortedmulti(1,A,B)))",
            "elwsh(and_v(v:pk(A),or_d(pk(B),older(10))))",
            "elc:pk_k(A)",
            "elcovwsh(A,pk(B))",
            "eltr(A,pk(B))",
            "eltr(musig(A,B),{pk(C),and_v(v:pk(D),older(10))})",
            "eltr(A,{pk(B),{and_v(v:pk(C),is_exp_asset(out_asset(0))),pk(D)}})",
        ] {
            check_curly_braces::<Desc>(desc);
        }

        let key = "03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4";
        let nums = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
        let mbk = "ab5824f4477b4ebb00a132adfd8eb0b7935cf24f6ac151add5d1913db374ce92";
        check_curly_braces::<ConfidentialDescriptor<DescriptorPublicKey>>(&format!(
            "ct(slip77({mbk}),elwsh(or_d(pk({key}),and_v(v:pk({nums}),older(10)))))"
        ));
        check_curly_braces::<Pegin<bitcoin::PublicKey>>(&format!(
            "pegin(wsh(multi(1,{key},{nums})),elwpkh({key}))"
        ));
        check_curly_braces::<LegacyPegin<bitcoin::PublicKey>>(&format!(
            "legacy_pegin(or_d(multi(1,f{key}),and_v(v:older(4032),multi(1,u{nums}))),elwpkh({key}))"
        ));
    }
}
