import gleam/bit_array
import gleeunit
import gleeunit/should
import secp256k1_gleam
import secp256k1_gleam/error

pub fn main() {
  gleeunit.main()
}

const message = <<
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 2,
>>

// gleeunit test functions end in `_test`
pub fn signature_test() {
  let assert Ok(private_key) =
    "8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f"
    |> bit_array.base16_decode()

  let signature = secp256k1_gleam.sign(message, private_key)
  should.equal(
    signature,
    Ok(secp256k1_gleam.Signature(
      <<
        73, 102, 23, 43, 29, 88, 149, 68, 77, 65, 248, 57, 200, 155, 43, 249,
        154, 95, 100, 185, 121, 244, 84, 178, 159, 90, 254, 45, 27, 177, 221,
        218,
      >>,
      <<
        21, 214, 167, 20, 61, 86, 189, 86, 241, 39, 239, 70, 71, 66, 201, 140,
        21, 23, 206, 201, 129, 255, 24, 20, 160, 152, 36, 114, 115, 245, 33, 208,
      >>,
      1,
    )),
  )
}

pub fn should_fail_to_sign_with_wrong_private_key_size_test() {
  let assert Error(error.WrongPrivateKeySize) =
    secp256k1_gleam.sign(message, <<1>>)
}

pub fn should_fail_to_sign_with_wrong_message_size_test() {
  let assert Error(error.WrongMessageSize) = secp256k1_gleam.sign(<<1>>, <<1>>)
}

pub fn should_create_public_key_test() {
  let private_key = <<
    120, 128, 174, 201, 52, 19, 241, 23, 239, 20, 189, 78, 109, 19, 8, 117, 171,
    44, 125, 125, 85, 160, 100, 250, 195, 194, 247, 189, 81, 81, 99, 128,
  >>
  let assert Ok(public_key) = secp256k1_gleam.create_public_key(private_key)
  should.equal(public_key, <<
    4, 196, 192, 12, 151, 91, 46, 136, 104, 28, 140, 147, 175, 203, 109, 123,
    247, 168, 3, 74, 46, 67, 92, 219, 154, 218, 144, 135, 114, 76, 12, 140, 213,
    136, 29, 101, 44, 225, 99, 58, 116, 118, 3, 199, 153, 99, 106, 231, 21, 184,
    191, 183, 239, 161, 155, 87, 19, 83, 37, 22, 168, 71, 124, 27, 172,
  >>)
}

pub fn should_fail_to_create_public_key_with_wrong_private_key_size_test() {
  let assert Error(error.WrongPrivateKeySize) =
    secp256k1_gleam.create_public_key(<<1>>)
}

pub fn should_verify_signature_test() {
  // message = :crypto.strong_rand_bytes(32)
  //       private_key = :crypto.strong_rand_bytes(32)
  //       {:ok, {signature, _r}} = ExSecp256k1.sign_compact(message, private_key)
  //
  //       {:ok, public_key} = ExSecp256k1.create_public_key(private_key)
  //
  //       assert :ok = ExSecp256k1.verify(message, signature, public_key)
  let message = strong_rand_bytes(32)
  let private_key = strong_rand_bytes(32)
  let assert Ok(signature) = secp256k1_gleam.sign(message, private_key)
  let assert Ok(public_key) = secp256k1_gleam.create_public_key(private_key)
  let assert Ok(Nil) = secp256k1_gleam.verify(message, signature, public_key)
}

@external(erlang, "crypto", "strong_rand_bytes")
pub fn strong_rand_bytes(size: Int) -> BitArray
