# No shebang, this file should not be executed.
# shellcheck disable=SC2148
#
# disable verify unused vars, despite the fact that they are used when sourced
# shellcheck disable=SC2034

# Test all these features with "std" enabled. Empty because we do not have a 'std' feature.
FEATURES_WITH_STD=""

# Test all these features without "std" enabled.
FEATURES_WITHOUT_STD="compiler trace serde rand base64 simplicity"

# Run these examples.
EXAMPLES="htlc:compiler parse: sign_multisig: verify_tx: xpub_descriptors: taproot:compiler psbt_sign_finalize:base64"
