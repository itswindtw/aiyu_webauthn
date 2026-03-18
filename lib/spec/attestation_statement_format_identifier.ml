type t =
  | Packed
  | Tpm
  | Android_key
  | Android_safetynet
  | Fido_u2f
  | Apple
  | None

let of_string = function
  | "packed" -> Some Packed
  | "tpm" -> Some Tpm
  | "android-key" -> Some Android_key
  | "android-safetynet" -> Some Android_safetynet
  | "fido-u2f" -> Some Fido_u2f
  | "apple" -> Some Apple
  | "none" -> Some None
  | _ -> None

let to_json = function
  | Packed -> `String "packed"
  | Tpm -> `String "tpm"
  | Android_key -> `String "android-key"
  | Android_safetynet -> `String "android-safetynet"
  | Fido_u2f -> `String "fido-u2f"
  | Apple -> `String "apple"
  | None -> `String "none"
