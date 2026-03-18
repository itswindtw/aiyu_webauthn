type t = Spec.Public_key_credential_creation_options.t

let make ~rp_id ~user_id ~user_name ?(user_display_name = "") ?challenge
    ?(supported_algs = Spec.Cose_key.supported_algs) ?timeout
    ?exclude_credentials ?authenticator_selection ?hints ?attestation
    ?attestation_formats ?extensions () : t =
  let rp =
    Spec.Public_key_credential_rp_entity.{ name = rp_id; id = Some rp_id }
  in
  let user =
    Spec.Public_key_credential_user_entity.
      { name = user_name; id = user_id; display_name = user_display_name }
  in
  let challenge =
    match challenge with
    | None -> Spec.Challenge.generate 64
    | Some challenge -> challenge
  in
  let pub_key_cred_params =
    List.map
      (fun alg ->
        Spec.Public_key_credential_parameters.{ type_ = Public_key; alg })
      supported_algs
  in

  Spec.Public_key_credential_creation_options.
    {
      rp;
      user;
      challenge;
      pub_key_cred_params;
      timeout;
      exclude_credentials;
      authenticator_selection;
      hints;
      attestation;
      attestation_formats;
      extensions;
    }

let to_json = Spec.Public_key_credential_creation_options.to_json
