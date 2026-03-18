type t = {
  client_data_json : Base64_url_string.t;
  authenticator_data : Base64_url_string.t;
  signature : Base64_url_string.t;
  user_handle : Base64_url_string.t option;
}

let from_json json =
  let open Result.Syntax in
  let open Json.Parse in
  try
    let* client_data_json =
      json |> member "clientDataJSON" |> Base64_url_string.from_json
    in
    let* authenticator_data =
      json |> member "authenticatorData" |> Base64_url_string.from_json
    in
    let* signature =
      json |> member "signature" |> Base64_url_string.from_json
    in
    let* user_handle =
      match json |> member "userHandle" |> to_string_option with
      | Some s -> Base64_url_string.of_encoded s |> Result.map Option.some
      | None -> Ok None
    in
    Ok { client_data_json; authenticator_data; signature; user_handle }
  with Type_error (m, _) -> Error m

let to_json t =
  Json.option_obj
    [
      ("clientDataJSON", Some (Base64_url_string.to_json t.client_data_json));
      ( "authenticatorData",
        Some (Base64_url_string.to_json t.authenticator_data) );
      ("signature", Some (Base64_url_string.to_json t.signature));
      ("userHandle", Option.map Base64_url_string.to_json t.user_handle);
    ]
