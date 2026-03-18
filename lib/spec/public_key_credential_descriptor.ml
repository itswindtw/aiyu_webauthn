type t = {
  type_ : Public_key_credential_type.t;
  id : string;
  transports : Authenticator_transport.t list option;
}

let to_json t =
  Json.option_obj
    [
      ("type", Some (Public_key_credential_type.to_json t.type_));
      ( "id",
        Some (t.id |> Base64_url_string.of_raw |> Base64_url_string.to_json) );
      ( "transport",
        Option.map
          (fun transports ->
            `List (List.map Authenticator_transport.to_json transports))
          t.transports );
    ]
