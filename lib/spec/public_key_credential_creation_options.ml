type t = {
  rp : Public_key_credential_rp_entity.t;
  user : Public_key_credential_user_entity.t;
  challenge : Challenge.t;
  pub_key_cred_params : Public_key_credential_parameters.t list;
  timeout : int option;
  exclude_credentials : Public_key_credential_descriptor.t list option;
  authenticator_selection : Authenticator_selection_criteria.t option;
  hints : Public_key_credential_hint.t list option;
  attestation : Attestation_conveyance_preference.t option;
  attestation_formats : Attestation_statement_format_identifier.t list option;
  extensions : Json.t option;
}

let to_json t =
  Json.option_obj
    [
      ("rp", Some (Public_key_credential_rp_entity.to_json t.rp));
      ("user", Some (Public_key_credential_user_entity.to_json t.user));
      ("challenge", Some (Challenge.to_json t.challenge));
      ( "pubKeyCredParams",
        Some
          (`List
             (List.map Public_key_credential_parameters.to_json
                t.pub_key_cred_params)) );
      ("timeout", Option.map (fun x -> `Int x) t.timeout);
      ( "excludeCredentials",
        Option.map
          (fun exclude_credentials ->
            `List
              (List.map Public_key_credential_descriptor.to_json
                 exclude_credentials))
          t.exclude_credentials );
      ( "authenticatorSelection",
        Option.map Authenticator_selection_criteria.to_json
          t.authenticator_selection );
      ( "hints",
        Option.map
          (fun hints ->
            `List (List.map Public_key_credential_hint.to_json hints))
          t.hints );
      ( "attestation",
        Option.map Attestation_conveyance_preference.to_json t.attestation );
      ( "attestationFormats",
        Option.map
          (fun x ->
            `List (List.map Attestation_statement_format_identifier.to_json x))
          t.attestation_formats );
      ("extensions", t.extensions);
    ]
