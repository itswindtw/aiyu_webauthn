type verification_result = {
  credential_record : Spec.Credential_record.t;
  user_handle : string option;
}

let verify ~authentication_response ~challenge ~rp_id ?check_credential_id
    ~fetch_credential_record ~check_origin ?check_top_origin ~allow_cross_origin
    ~require_user_verification () =
  let open Result.Syntax in
  (* 2. Call navigator.credentials.get() and pass options as the argument. Let credential be the result of the successfully resolved promise. *)
  let* credential =
    authentication_response |> Json.from_string
    |> Spec.Authentication_response_json.from_json
  in
  (* 3. Let response be credential.response. If response is not an instance of AuthenticatorAssertionResponse, abort the ceremony with a user-visible error. *)
  let response = credential.response in
  (* 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults(). *)
  (* PASS *)
  (* let client_extension_results = credential.client_extension_results in *)
  (* 5. If pkOptions.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials listed in pkOptions.allowCredentials. *)
  let credential_id = credential.raw_id |> Spec.Base64_url_string.to_raw in
  let* () =
    match check_credential_id with
    | None -> Ok ()
    | Some check_credential_id ->
        if check_credential_id credential_id then Ok ()
        else Error "Unexpected credential.id"
  in
  (* 6. Identify the user being authenticated and let credentialRecord be the credential record for the credential: *)
  let user_handle =
    response.user_handle |> Option.map Spec.Base64_url_string.to_raw
  in
  let* credential_record : Spec.Credential_record.t =
    fetch_credential_record ~user_handle ~credential_id
  in
  (* 7. Let cData, authData and sig denote the value of response’s clientDataJSON, authenticatorData, and signature respectively.  *)
  let c_data = response.client_data_json |> Spec.Base64_url_string.to_raw in
  let raw_auth_data =
    response.authenticator_data |> Spec.Base64_url_string.to_raw
  in
  let* auth_data = raw_auth_data |> Spec.Authenticator_data.of_string in
  let sig_ = response.signature |> Spec.Base64_url_string.to_raw in

  (* 8. Let JSONtext be the result of running UTF-8 decode on the value of cData. *)
  let json_text = c_data in
  (* 9. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext. *)
  let* c =
    json_text |> Json.from_string |> Spec.Collected_client_data.of_json
  in
  (* 10. Verify that the value of C.type is the string webauthn.get. *)
  let* () =
    if c.type_ = "webauthn.get" then Ok ()
    else Error "C.type is not \"webauthn.get\""
  in
  (* 11. Verify that the value of C.challenge equals the base64url encoding of pkOptions.challenge. *)
  let* () =
    if c.challenge = Spec.Base64_url_string.to_encoded challenge then Ok ()
    else Error "C.challenge does not equal to challenge"
  in
  (* 12. Verify that the value of C.origin is an origin expected by the Relying Party. *)
  let* () =
    if check_origin c.origin then Ok () else Error "C.origin is not as expected"
  in
  (* 13. If C.crossOrigin is present and set to true, verify that the Relying Party expects this credential to be used within an iframe that is not same-origin with its ancestors. *)
  let* () =
    match c.cross_origin with
    | Some true ->
        if allow_cross_origin then Ok ()
        else Error "Cross origin is not expected"
    | _ -> Ok ()
  in
  (* 14. If C.topOrigin is present: *)
  let* () =
    match (c.top_origin, check_top_origin) with
    | Some top_origin, Some check_top_origin ->
        (* 1. Verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors. *)
        (* 2. Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. *)
        if allow_cross_origin && check_top_origin top_origin then Ok ()
        else Error "C.top_origin is not as expected"
    | Some _, None -> Error "C.top_origin can't be checked"
    | None, _ -> Ok ()
  in
  (* 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party. *)
  let* () =
    if
      auth_data.rp_id_hash
      = Digestif.SHA256.(rp_id |> digest_string |> to_raw_string)
    then Ok ()
    else Error "authData.rpIdHash is not as expected"
  in
  (* 16. Verify that the UP bit of the flags in authData is set. *)
  let* () =
    if auth_data.flags.user_present then Ok ()
    else Error "User Present is required"
  in
  (* 17. If user verification was determined to be required, verify that the UV bit of the flags in authData is set. Otherwise, ignore the value of the UV flag. *)
  let* () =
    if (not require_user_verification) || auth_data.flags.user_verified then
      Ok ()
    else Error "User Verification is required"
  in
  (* 18. If the BE bit of the flags in authData is not set, verify that the BS bit is not set. *)
  let* () =
    if auth_data.flags.backup_eligibility || not auth_data.flags.backup_state
    then Ok ()
    else Error "Backup State should not be set if Backup Eligibility is not set"
  in
  (* 19. If the credential backup state is used as part of Relying Party business logic or policy, let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData. Compare currentBe and currentBs with credentialRecord.backupEligible and credentialRecord.backupState: *)
  let current_be = auth_data.flags.backup_eligibility in
  let current_bs = auth_data.flags.backup_state in
  let* () =
    if (not credential_record.backup_eligible) || current_be then Ok ()
    else
      Error
        "If credentialRecord.backupEligible is set, verify that currentBe is \
         set."
  in
  let* () =
    let current_be = auth_data.flags.backup_eligibility in
    if credential_record.backup_eligible || not current_be then Ok ()
    else
      Error
        "If credentialRecord.backupEligible is not set, verify that currentBe \
         is not set."
  in
  (* 20. Let hash be the result of computing a hash over the cData using SHA-256. *)
  let hash =
    c_data |> Digestif.SHA256.digest_string |> Digestif.SHA256.to_raw_string
  in
  (* 21. Using credentialRecord.publicKey, verify that sig is a valid signature over the binary concatenation of authData and hash. *)
  let* public_key =
    credential_record.public_key |> Spec.Cose_key.to_x509_public_key
  in
  let scheme =
    match X509.Public_key.key_type public_key with
    | `ED25519 -> `ED25519
    | `RSA -> `RSA_PKCS1
    | _ -> `ECDSA
  in
  let* () =
    X509.Public_key.verify `SHA256 ~scheme ~signature:sig_ public_key
      (`Message (raw_auth_data ^ hash))
    |> Result.map_error (fun (`Msg m) -> m)
  in
  (* 22. If authData.signCount is nonzero or credentialRecord.signCount is nonzero, then run the following sub-step: *)
  (* PASS *)
  (* 23. Process the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData as required by the Relying Party. *)
  (* PASS *)
  (* 24. Update credentialRecord with new state values: *)
  let credential_record =
    Spec.Credential_record.
      {
        credential_record with
        sign_count = auth_data.sign_count;
        backup_state = current_bs;
        uv_initialized =
          credential_record.uv_initialized || auth_data.flags.user_verified;
      }
  in
  Ok { credential_record; user_handle }
