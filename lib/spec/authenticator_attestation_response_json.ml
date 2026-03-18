type t = {
  client_data_json : Base64_url_string.t;
  (* authenticator_data : string; *)
  transports : string list;
  (* public_key : string option;
  public_key_algorithm : Cose_algorithm_identifier.t; *)
  attestation_object : Base64_url_string.t;
}

let to_json t =
  `Assoc
    [
      ("clientDataJSON", Base64_url_string.to_json t.client_data_json);
      ("transports", `List (List.map Json.string t.transports));
      ("attestationObject", Base64_url_string.to_json t.attestation_object);
    ]

let of_json json =
  let open Json.Parse in
  let open Result.Syntax in
  try
    let* client_data_json =
      json |> member "clientDataJSON" |> Base64_url_string.from_json
    in
    (* let authenticator_data = json |> member "authenticatorData" |> to_string in *)
    let transports = json |> member "transports" |> convert_each to_string in
    (* let public_key = json |> member "publicKey" |> to_string_option in *)
    (* let public_key_algorithm =
      json |> member "publicKeyAlgorithm" |> Cose_algorithm_identifier.of_json
    in *)
    let* attestation_object =
      json |> member "attestationObject" |> Base64_url_string.from_json
    in
    Ok
      {
        client_data_json;
        (* authenticator_data; *)
        transports;
        (* public_key; *)
        (* public_key_algorithm; *)
        attestation_object;
      }
  with Type_error (msg, _) -> Error msg
