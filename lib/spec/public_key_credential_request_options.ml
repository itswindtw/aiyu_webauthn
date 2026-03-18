type t = {
  challenge : Challenge.t;
  timeout : int option;
  rp_id : string option;
  allow_credentials : Public_key_credential_descriptor.t list option;
  user_verification : User_verification_requirement.t option;
  hints : Public_key_credential_hint.t list option;
  extensions : Json.t option;
}

let to_json t =
  Json.option_obj
    [
      ("challenge", Some (Challenge.to_json t.challenge));
      ("timeout", Option.map (fun x -> `Int x) t.timeout);
      ("rpId", Option.map (fun x -> `String x) t.rp_id);
      ( "allowCredentials",
        Option.map
          (fun allow_credentials ->
            `List
              (List.map Public_key_credential_descriptor.to_json
                 allow_credentials))
          t.allow_credentials );
      ( "userVerification",
        Option.map User_verification_requirement.to_json t.user_verification );
      ( "hints",
        Option.map
          (fun hints ->
            `List (List.map Public_key_credential_hint.to_json hints))
          t.hints );
      ("extensions", t.extensions);
    ]
