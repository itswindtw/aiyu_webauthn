type t = Base64_url_string.t

let generate size =
  match size >= 16 with
  | true -> Mirage_crypto_rng.generate size |> Base64_url_string.of_raw
  | false -> invalid_arg "Challenges SHOULD therefore be at least 16 bytes long"

let to_json = Base64_url_string.to_json
