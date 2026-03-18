type t = {
  id : string;
  raw_id : Base64_url_string.t;
  response : Authenticator_attestation_response_json.t;
  authenticator_attachment : string option;
  client_extension_results : Json.t;
  type_ : string;
}

let to_json t =
  Json.option_obj
    [
      ("id", Some (Json.string t.id));
      ("rawId", Some (Base64_url_string.to_json t.raw_id));
      ( "response",
        Some (Authenticator_attestation_response_json.to_json t.response) );
      ( "authenticatorAttachment",
        Option.map Json.string t.authenticator_attachment );
      ("clientExtensionResults", Some t.client_extension_results);
      ("type", Some (Json.string t.type_));
    ]

let from_json json =
  let open Result.Syntax in
  let open Json.Parse in
  try
    let id = json |> member "id" |> to_string in
    let* raw_id = json |> member "rawId" |> Base64_url_string.from_json in
    let* response =
      json |> member "response"
      |> Authenticator_attestation_response_json.of_json
    in
    let authenticator_attachment =
      json |> member "authenticatorAttachment" |> to_string_option
    in
    let client_extension_results = json |> member "clientExtensionResults" in
    let type_ = json |> member "type" |> to_string in
    Ok
      {
        id;
        raw_id;
        response;
        authenticator_attachment;
        client_extension_results;
        type_;
      }
  with Type_error (msg, _) -> Error msg
