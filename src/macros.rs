//! Macros
//!
//! Macros meant to be used inside the Rust Miniscript library

/// Allows tests to create a miniscript directly from string as
/// `ms_str!("c:or_i(pk({}),pk({}))", pk1, pk2)`
#[cfg(test)]
macro_rules! ms_str {
    ($($arg:tt)*) => (Miniscript::from_str_ext(&format!($($arg)*), &$crate::ExtParams::allow_all()).unwrap())
}

/// Allows tests to create a concrete policy directly from string as
/// `policy_str!("elwsh(c:or_i(pk({}),pk({})))", pk1, pk2)`
#[cfg(all(feature = "compiler", test))]
macro_rules! policy_str {
    ($($arg:tt)*) => ($crate::policy::Concrete::from_str(&format!($($arg)*)).unwrap())
}

/// Macro for implementing FromTree trait. This avoids copying all the Pk::Associated type bounds
/// throughout the codebase.
macro_rules! impl_from_tree {
    ($(;$gen:ident; $gen_con:ident, )*
        $name: ty,
        $(=> $ext:ident; $trt:ident, )?
        $(#[$meta:meta])*
        fn $fn:ident ( $($arg:ident : $type:ty),* ) -> $ret:ty
        $body:block
    ) => {
        impl<Pk $(, $gen)* $(, $ext)?> $crate::expression::FromTree for $name
        where
            Pk: MiniscriptKey + core::str::FromStr,
            Pk::Sha256: core::str::FromStr,
            Pk::Hash256: core::str::FromStr,
            Pk::Ripemd160: core::str::FromStr,
            Pk::Hash160: core::str::FromStr,
            <Pk as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Sha256 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Hash256 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Ripemd160 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Hash160 as core::str::FromStr>::Err: std::string::ToString,
            $($gen : $gen_con,)*
            $($ext: $trt)?
            {

                $(#[$meta])*
                fn $fn($($arg: $type)* ) -> $ret {
                    $body
                }
            }
    };
}

/// Macro for implementing FromStr trait. This avoids copying all the Pk::Associated type bounds
/// throughout the codebase.
macro_rules! impl_from_str {
    ($(;$gen:ident; $gen_con:ident, )* $name: ty,
        $(=> $ext:ident; $trt:ident, )?
        type Err = $err_ty:ty;,
        $(#[$meta:meta])*
        fn $fn:ident ( $($arg:ident : $type:ty),* ) -> $ret:ty
        $body:block
    ) => {
        impl<Pk $(, $gen)* $(, $ext)?> core::str::FromStr for $name
        where
            Pk: MiniscriptKey + core::str::FromStr,
            Pk::Sha256: core::str::FromStr,
            Pk::Hash256: core::str::FromStr,
            Pk::Ripemd160: core::str::FromStr,
            Pk::Hash160: core::str::FromStr,
            <Pk as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Sha256 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Hash256 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Ripemd160 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Hash160 as core::str::FromStr>::Err: std::string::ToString,
            $($gen : $gen_con,)*
            $($ext: $trt)?
            {
                type Err = $err_ty;

                $(#[$meta])*
                fn $fn($($arg: $type)* ) -> $ret {
                    $body
                }
            }
    };
}

/// Macro for impl Struct with associated bounds. This avoids copying all the Pk::Associated type bounds
/// throughout the codebase.
macro_rules! impl_block_str {
    ($(;$gen:ident; $gen_con:ident, )* $name: ty,
    $(=> $ext:ident; $trt:ident, )?
        $(#[$meta:meta])*
        $v:vis fn $fn:ident ( $($arg:ident : $type:ty, )* ) -> $ret:ty
        $body:block
    ) => {
        impl<Pk $(, $gen)* $(, $ext)?> $name
        where
            Pk: MiniscriptKey + core::str::FromStr,
            Pk::Sha256: core::str::FromStr,
            Pk::Hash256: core::str::FromStr,
            Pk::Ripemd160: core::str::FromStr,
            Pk::Hash160: core::str::FromStr,
            <Pk as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Sha256 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Hash256 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Ripemd160 as core::str::FromStr>::Err: std::string::ToString,
            <<Pk as MiniscriptKey>::Hash160 as core::str::FromStr>::Err: std::string::ToString,
            $($gen : $gen_con,)*
            $($ext: $trt)?
            {
                $(#[$meta])*
                $v fn $fn($($arg: $type,)* ) -> $ret {
                    $body
                }
            }
    };
}

/// A macro that implements serde serialization and deserialization using the
/// `fmt::Display` and `str::FromStr` traits.
macro_rules! serde_string_impl_pk {
    ($name:ident, $expecting:expr $(, $gen:ident; $gen_con:ident)* $(=> $ext:ident ; $ext_bound:ident)*) => {
        #[cfg(feature = "serde")]
        impl<'de, Pk $(, $gen)* $(, $ext)*> $crate::serde::Deserialize<'de> for $name<Pk $(, $gen)* $(, $ext)* >
        where
            Pk: $crate::MiniscriptKey + core::str::FromStr,
            Pk::Sha256: core::str::FromStr,
            Pk::Hash256: core::str::FromStr,
            Pk::Ripemd160: core::str::FromStr,
            Pk::Hash160: core::str::FromStr,
            <Pk as core::str::FromStr>::Err: core::fmt::Display,
            <<Pk as $crate::MiniscriptKey>::Sha256 as core::str::FromStr>::Err:
                core::fmt::Display,
            <<Pk as $crate::MiniscriptKey>::Hash256 as core::str::FromStr>::Err:
                core::fmt::Display,
            <<Pk as $crate::MiniscriptKey>::Ripemd160 as core::str::FromStr>::Err:
                core::fmt::Display,
            <<Pk as $crate::MiniscriptKey>::Hash160 as core::str::FromStr>::Err:
                core::fmt::Display,
            $($gen : $gen_con,)*
            $($ext : $ext_bound,)*
        {
            fn deserialize<D>(deserializer: D) -> Result<$name<Pk $(, $gen)* $(, $ext)*>, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use std::fmt::{self, Formatter};
                use std::marker::PhantomData;
                use std::str::FromStr;

                #[allow(unused_parens)]
                struct Visitor<Pk $(, $gen)* $(, $ext)*>(PhantomData<(Pk $(, $gen)* $(, $ext)*)>);
                impl<'de, Pk $(, $gen)* $(, $ext)*> $crate::serde::de::Visitor<'de> for Visitor<Pk $(, $gen)* $(, $ext)*>
                where
                    Pk: $crate::MiniscriptKey + core::str::FromStr,
                    Pk::Sha256: core::str::FromStr,
                    Pk::Hash256: core::str::FromStr,
                    Pk::Ripemd160: core::str::FromStr,
                    Pk::Hash160: core::str::FromStr,
                    <Pk as core::str::FromStr>::Err: core::fmt::Display,
                    <<Pk as $crate::MiniscriptKey>::Sha256 as core::str::FromStr>::Err:
                        core::fmt::Display,
                    <<Pk as $crate::MiniscriptKey>::Hash256 as core::str::FromStr>::Err:
                        core::fmt::Display,
                    <<Pk as $crate::MiniscriptKey>::Ripemd160 as core::str::FromStr>::Err:
                        core::fmt::Display,
                    <<Pk as $crate::MiniscriptKey>::Hash160 as core::str::FromStr>::Err:
                        core::fmt::Display,
                    $($gen: $gen_con,)*
                    $($ext : $ext_bound,)*
                {
                    type Value = $name<Pk $(, $gen)* $(, $ext)*>;

                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        $name::from_str(v).map_err(E::custom)
                    }

                    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(v)
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(&v)
                    }
                }

                deserializer.deserialize_str(Visitor(PhantomData))
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, Pk $(, $gen)* $(, $ext)*> $crate::serde::Serialize for $name<Pk $(, $gen)* $(, $ext)*>
        where
            Pk: MiniscriptKey,
            $($gen: $gen_con,)*
            $($ext : $ext_bound,)*
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    };
}

macro_rules! match_token {
    // Base case
    ($tokens:expr => $sub:expr,) => { $sub };
    // Recursive case
    ($tokens:expr, $($first:pat $(,$rest:pat)* => $sub:expr,)*) => {
        match $tokens.next() {
            $(
                Some($first) => match_token!($tokens $(,$rest)* => $sub,),
            )*
            Some(other) => return Err(Error::Unexpected(other.to_string())),
            None => return Err(Error::UnexpectedStart),
        }
    };
}
