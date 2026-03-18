type t = Base64_url_string of string

let pad = false
let alphabet = Base64.uri_safe_alphabet
let of_raw s = Base64_url_string s

let of_encoded s =
  Base64.decode ~pad ~alphabet s
  |> Result.map_error (fun (`Msg msg) -> msg)
  |> Result.map of_raw

let to_raw (Base64_url_string s) = s
let to_encoded (Base64_url_string s) = Base64.encode_string ~pad ~alphabet s
let from_json json = json |> Json.Parse.to_string |> of_encoded
let to_json t = `String (to_encoded t)
