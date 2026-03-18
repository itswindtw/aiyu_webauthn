type t = Spec.Public_key_credential_request_options.t

let make ~rp_id ?challenge ?timeout ?allow_credentials ?user_verification ?hints
    ?extensions () : t =
  let challenge =
    match challenge with
    | None -> Spec.Challenge.generate 64
    | Some challenge -> challenge
  in

  Spec.Public_key_credential_request_options.
    {
      challenge;
      rp_id = Some rp_id;
      timeout;
      allow_credentials;
      user_verification;
      hints;
      extensions;
    }

let to_json = Spec.Public_key_credential_request_options.to_json
