import secp256k1_gleam/error

pub type VerifyResult {
  Ok
  Error(error.Error)
}
