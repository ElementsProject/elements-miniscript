# Miniscript Extensions:

Extensions allow users to extend miniscript to have new leaf nodes. This document lists
extensions implemented for elements-miniscript with the tapscript opcodes. Users can
also implement custom extensions using [`Extension`] trait.

# Index expressions (`IdxExpr`)
- Pushes a single CScriptNum on stack top. This is used to represent the index of the input or output. `IndexExpr` must
compute values between [-2^31, 2^31 - 1]. When `IndexExpr` is finally used as an index in some parent fragment, additionally
it's value must fall within bounds. For example, `inp_spk(IdxExpr_i)`, `IdxExpr_i` must be between `0`(inclusive) and
`num_inputs`(exclusive)

Name                    | Script
---                     | ---
curr_idx                | `PUSHCURRENTINPUTINDEX`
`i` `<i64>`             | `i` (`i` as `CScriptNum`)
idx_add(x,y)            | `[X] [Y] ADD`
idx_sub(x,y)            | `[X] [Y] SUB`
idx_mul(x,y)            | `[X] SCIPTNUMTOLE64 [Y] OP_SCIPTNUMTOLE64 MUL64 <1> EQUALVERIFY LE64TOSCIPTNUM`
idx_div(x,y)            | `[X] SCIPTNUMTOLE64 [Y] OP_SCIPTNUMTOLE64 DIV64 <1> EQUALVERIFY  NIP LE64TOSCIPTNUM`

# Value Arithmetic extensions (`NumExpr`)

- Pushes single singed 64 bit LE number on stack top. Since these expressions push a 8 byte number, it does not directly
fit in the miniscript model. These are used in fragments in one of the comparison fragment listed in the next section.
- All of introspection opcodes explicitly assert the amount is explicit.
- This will abort when
    - Any of operations are on confidential amounts. The Null case is automatically converted to explicit zero.
    - Supplied index is out of bounds.
    - Any of the operations overflow. Refer to tapscript [opcodes](https://github.com/ElementsProject/elements/blob/master/doc/tapscript_opcodes.md) spec for overflow specification

Name                    | Script
---                     | ---
`value` `<i64>`         | `8-byte-LE-push of <value>`
curr_inp_v              | `INSPECTCURRENTINPUTINDEX INPSECTINPUTVALUE <1> EQUALVERIFY`
inp_v(IdxExpr_i)        | `[IdxExpr_i] INPSECTINPUTVALUE <1> EQUALVERIFY`
out_v(IdxExpr_i)        | `[IdxExpr_i] INPSECTOUTPUTVALUE <1> EQUALVERIFY`
inp_issue_v(IdxExpr_i)  | `[IdxExpr_i] OP_INSPECTINPUTISSUANCE DROP DROP <1> EQUALVERIFY NIP NIP`
inp_reissue_v(IdxExpr_i)| `[IdxExpr_i] OP_INSPECTINPUTISSUANCE DROP DROP DROP DROP <1> EQUALVERIFY`
bitinv(x)               | `[X] INVERT`
neg(x)                  | `[X] NEG64 <1> EQUALVERIFY`
add(x,y)                | `[X] [Y] ADD64 <1> EQUALVERIFY`
sub(x,y)                | `[X] [Y] SUB64 <1> EQUALVERIFY`
mul(x,y)                | `[X] [Y] MUL64 <1> EQUALVERIFY`
div(x,y)                | `[X] [Y] DIV64 <1> EQUALVERIFY NIP`
mod(x,y)                | `[X] [Y] DIV64 <1> EQUALVERIFY DROP`
bitand(x,y)             | `[X] [Y] AND`
bitor(x,y)              | `[X] [Y] OR (cannot fail)`
bitxor(x,y)             | `[X] [Y] XOR (cannot fail)`


- The division operation pushes the quotient(a//b) such that the remainder a%b (must be non-negative and less than |b|).
- neg(a) returns -a, whereas bitinv(a) returns ~a.

## Comparison extensions

As mentioned earlier, `NumExpr` directly does not fit in the miniscript model as it pushes a 8 byte computation result.
To use these with miniscript fragments, we can use them inside comparison extensions. These comparison are of type `Bzdu`.

Name                                    | Script
---                                     | ---
num64_eq(NumExpr_X,NumExpr_Y)           | `[NumExpr_X] [NumExpr_Y] EQUAL`
num64_le(NumExpr_X,NumExpr_Y)           | `[NumExpr_X] [NumExpr_Y] LESSTHAN64`
num64_ge(NumExpr_X,NumExpr_Y)           | `[NumExpr_X] [NumExpr_Y] GREATERTHAN64`
num64_leq(NumExpr_X,NumExpr_Y)          | `[NumExpr_X] [NumExpr_Y] LESSTHANOREQUAL64`
num64_geq(NumExpr_X,NumExpr_Y)          | `[NumExpr_X] [NumExpr_Y] GREATERTHANOREQUAL64`

- For example, `num64_eq(inp_v(1),mul(curr_inp_v,20))` represents second input value is the multiplication of
current input value and fourth output value. This would abort if any of the values are confidential.

### Tx Value introspection

### AssetExpr

- pushes a 32 byte asset + 1 byte prefix on stack top. These operations also support confidential assets.
- This will abort when
     - Supplied index is out of bounds.

Name                    | Script
---                     | ---
`asset`(33 byte hex)    | `[32-byte comm] [1 byte pref]` of this asset
curr_inp_asset          | `INSPECTCURRENTINPUTINDEX INPSECTINPUTASSET`
inp_asset(IdxExpr_i)    | `[IdxExpr_i] INPSECTINPUTASSET`
out_asset(IdxExpr_i)    | `[IdxExpr_i] INPSECTOUTPUTASSET`

### ValueExpr

- pushes a 32 byte value(8-byte-LE value if explicit)  + 1 byte prefix on stack top. These operations also support confidential values.
- This will abort when
     - Supplied index is out of bounds.

Name                    | Script
---                     | ---
`value`(33/9 byte hex)  | `[32-byte comm/8 byte LE] [1 byte pref]` of this Value
curr_inp_value          | `INSPECTCURRENTINPUTINDEX INPSECTINPUTVALUE`
inp_value(IdxExpr_i)    | `[IdxExpr_i] INPSECTINPUTVALUE`
out_value(IdxExpr_i)    | `[IdxExpr_i] INPSECTOUTPUTVALUE`

### SpkExpr: Script PubKey Expression

- Pushes a witness program + 1 byte witness version on stack top.
- If the script pubkey is not a witness program. Push a sha256 hash of the script pubkey followed by -1 witness version
- This will abort when
    - Supplied index is out of bounds.

Name                    | Script
---                     | ---
`spk`(script_hex)       | `[program] [witness version]` of this spk (`<Sha2Hash(Script)> <-1>`) for legacy
curr_inp_spk            | `INSPECTCURRENTINPUTINDEX INPSECTINPUTSCRIPTPUBKEY`
inp_spk(IdxExpr_i)      | `[IdxExpr_i] INPSECTINPUTSCRIPTPUBKEY`
out_spk(IdxExpr_i)      | `[IdxExpr_i] INPSECTOUTPUTASSETSCRIPTPUBKEY`

## Introspection Operations

- `ValueExpr`, `AssetExpr` and `SpkExpr` do not fit in to the miniscript model. To use these
in miniscript, we can use the below defined introspection operations. These are of type `Bzdu`
- Reasoning the safety of covenants using introspection is not possible for miniscript to do as
from point of view of miniscript these are anyone can spend without any signatures. However, in
practice these are usually secured via cross input transactional logic beyond the current executing script.

Name                                    | Script
---                                     | ---
is_exp_asset(AssetExpr_X)               | `[AssetExpr_X] <1> EQUAL NIP`
is_exp_value(ValueExpr_X)               | `[ValueExpr_X] <1> EQUAL NIP`
asset_eq(AssetExpr_X,AssetExpr_Y)       | `[AssetExpr_X] TOALTSTACK [AssetExpr_Y] FROMALTSTACK EQUAL TOALTSTACK EQUAL FROMALTSTACK BOOLAND`
value_eq(ValueExpr_X,ValueExpr_Y)       | `[ValueExpr_X] TOALTSTACK [ValueExpr_Y] FROMALTSTACK EQUAL TOALTSTACK EQUAL FROMALTSTACK BOOLAND`
spk_eq(SpkExpr_X,SpkExpr_Y)             | `[SpkExpr_X] TOALTSTACK [SpkExpr_Y] FROMALTSTACK EQUAL TOALTSTACK EQUAL FROMALTSTACK BOOLAND`
curr_idx_eq(i)	                        | `i PUSHCURRENTINPUTINDEX EQUAL`
idx_eq(IdxExpr_i, IdxExpr_j)            | `[IdxExpr_i] PUSHCURRENTINPUTINDEX EQUAL`