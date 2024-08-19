import gleam/bit_array
import gleam/result
import secp256k1_gleam/error
import secp256k1_gleam/result as my_result

pub type Signature {
  Signature(r: BitArray, s: BitArray, recovery_id_int: Int)
}

pub fn sign(
  message: BitArray,
  secret_key: BitArray,
) -> Result(Signature, error.Error) {
  use result <- result.try(internal_sign(message, secret_key))
  Ok(Signature(r: result.0, s: result.1, recovery_id_int: result.2))
}

pub fn to_compact(signature: Signature) -> BitArray {
  let Signature(r: r, s: s, ..) = signature
  <<r:bits, s:bits>>
}

pub fn to_string(signature: Signature) -> String {
  let assert Ok(compact) = to_compact(signature) |> bit_array.to_string
  "0x" <> compact
}

pub fn verify(
  message: BitArray,
  signature: Signature,
  public_key: BitArray,
) -> Result(Nil, error.Error) {
  let signature = <<signature.r:bits, signature.s:bits>>

  let result = verify_internal(message, signature, public_key)
  case result {
    my_result.Ok -> Ok(Nil)
    my_result.Error(error) -> Error(error)
  }
}

@external(erlang, "Elixir.ExSecp256k1", "sign")
fn internal_sign(
  message: BitArray,
  secret_key: BitArray,
) -> Result(#(BitArray, BitArray, Int), error.Error)

@external(erlang, "Elixir.ExSecp256k1", "create_public_key")
pub fn create_public_key(private_key: BitArray) -> Result(BitArray, error.Error)

@external(erlang, "Elixir.ExSecp256k1", "verify")
fn verify_internal(
  message: BitArray,
  signature: BitArray,
  public_key: BitArray,
) -> my_result.VerifyResult
