type verfication_result = { credential_record : Spec.Credential_record.t }

let verify_att_stmt att_stmt_fmt att_stmt (raw_auth_data, auth_data) hash =
  let open Result.Syntax in
  match att_stmt_fmt with
  | Spec.Attestation_statement_format_identifier.None ->
      Ok (Spec.Attestation_type.None, [])
  | Packed -> (
      let* kv =
        match att_stmt with
        | Cbor.Map kv -> Ok kv
        | _ -> Error "att_stmt is not a map"
      in
      let* alg =
        match List.assoc_opt (Cbor.Text_string "alg") kv with
        | Some (Integer alg) -> Ok alg
        | None -> Error "att_stmt.alg is missing"
        | _ -> Error "att_stmt.alg is not an integer"
      in
      let* sig_ =
        match List.assoc_opt (Cbor.Text_string "sig") kv with
        | Some (Byte_string sig_) -> Ok sig_
        | None -> Error "att_stmt.sig is missing"
        | _ -> Error "att_stmt.sig is not bytes"
      in
      let* x5c =
        match List.assoc_opt (Cbor.Text_string "x5c") kv with
        | Some (Array (_ :: _ as list)) ->
            List.fold_right
              (fun x acc ->
                let* acc = acc in
                let* x =
                  match x with
                  | Cbor.Byte_string bytes -> Ok bytes
                  | _ -> Error "att_stmt.x5c is not a bytes list"
                in
                Ok (x :: acc))
              list (Ok [])
            |> Result.map Option.some
        | None -> Ok None
        | _ -> Error "att_stmt.x1c is not a list"
      in
      match x5c with
      | Some x5c ->
          (* If x5c is present: *)
          (* Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg. *)
          let* attestn_cert =
            X509.Certificate.decode_der (List.hd x5c)
            |> Result.map_error (fun (`Msg m) -> m)
          in
          let public_key = X509.Certificate.public_key attestn_cert in
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
          (* Verify that attestnCert meets the requirements in § 8.2.1 Certificate Requirements for Packed Attestation Statements. *)
          (* MAYBE *)
          (* If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData. *)
          (* MAYBE *)
          Ok (Spec.Attestation_type.Uncertainty, x5c)
      | None ->
          (* If x5c is not present, self attestation is in use. *)
          (* Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData. *)
          let* attested_credential_data =
            Option.to_result ~none:"attested_credential_data is not present"
              auth_data.Spec.Authenticator_data.attested_credential_data
          in
          let* () =
            if alg = attested_credential_data.credential_public_key.alg then
              Ok ()
            else
              Error
                "alg does not match the algorithm of the credentialPublicKey \
                 in authenticatorData"
          in
          (* Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg. *)
          let* public_key =
            attested_credential_data.credential_public_key
            |> Spec.Cose_key.to_x509_public_key
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
          Ok (Spec.Attestation_type.Self, []))
  | _ -> failwith "MAYBE"

let verify ~registration_response ~challenge ~rp_id ~check_origin
    ?check_top_origin ~check_attestation
    ?(supported_algs = Spec.Cose_key.supported_algs) ~allow_cross_origin
    ~require_user_present ~require_user_verification
    ~is_credential_id_registered () =
  let open Result.Syntax in
  (* 2. Call navigator.credentials.create() and pass options as the argument. Let credential be the result of the successfully resolved promise. *)
  let* credential =
    registration_response |> Json.from_string
    |> Spec.Registration_response_json.from_json
  in
  (* 3. Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse, abort the ceremony with a user-visible error. *)
  let response = credential.response in
  (* 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults(). *)
  (* PASS *)
  (* let client_extension_results = credential.client_extension_results in *)
  (* 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON. *)
  let json_text = response.client_data_json |> Spec.Base64_url_string.to_raw in
  (* 6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext. *)
  let* c =
    json_text |> Json.from_string |> Spec.Collected_client_data.of_json
  in
  (* 7. Verify that the value of C.type is webauthn.create. *)
  let* () =
    if c.type_ = "webauthn.create" then Ok ()
    else Error "C.type is not \"webauthn.create\""
  in
  (* 8. Verify that the value of C.challenge equals the base64url encoding of pkOptions.challenge. *)
  let* () =
    if c.challenge = Spec.Base64_url_string.to_encoded challenge then Ok ()
    else Error "C.challenge does not equal to challenge"
  in
  (* 9. Verify that the value of C.origin is an origin expected by the Relying Party. *)
  let* () =
    if check_origin c.origin then Ok () else Error "C.origin is not as expected"
  in
  (* 10. If C.crossOrigin is present and set to true, verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors. *)
  let* () =
    match c.cross_origin with
    | Some true ->
        if allow_cross_origin then Ok ()
        else Error "Cross origin is not expected"
    | _ -> Ok ()
  in
  (* 11. If C.topOrigin is present: *)
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
  (* 12. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256. *)
  let hash =
    Digestif.SHA256.digest_string
      (response.client_data_json |> Spec.Base64_url_string.to_raw)
    |> Digestif.SHA256.to_raw_string
  in
  (* 13. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt. *)
  let* attestation_object =
    Spec.Attestation_object.of_cbor
      (response.attestation_object |> Spec.Base64_url_string.to_raw)
  in
  let fmt = attestation_object.fmt in
  let* auth_data =
    attestation_object.auth_data |> Spec.Authenticator_data.of_string
  in
  let att_stmt = attestation_object.att_stmt in
  (* 14. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party. *)
  let* () =
    if
      auth_data.rp_id_hash
      = (rp_id |> Digestif.SHA256.digest_string |> Digestif.SHA256.to_raw_string)
    then Ok ()
    else Error "authData.rpIdHash is not as expected"
  in
  (* 15. If options.mediation is not set to conditional, verify that the UP bit of the flags in authData is set. *)
  let* () =
    if (not require_user_present) || auth_data.flags.user_present then Ok ()
    else Error "User Present is required"
  in
  (* 16. If the Relying Party requires user verification for this registration, verify that the UV bit of the flags in authData is set. *)
  let* () =
    if (not require_user_verification) || auth_data.flags.user_verified then
      Ok ()
    else Error "User Verification is required"
  in
  (* 17. If the BE bit of the flags in authData is not set, verify that the BS bit is not set. *)
  let* () =
    if auth_data.flags.backup_eligibility || not auth_data.flags.backup_state
    then Ok ()
    else Error "Backup State should not be set if Backup Eligibility is not set"
  in
  (* 18. If the Relying Party uses the credential’s backup eligibility to inform its user experience flows and/or policies, evaluate the BE bit of the flags in authData. *)
  (* 19. If the Relying Party uses the credential’s backup state to inform its user experience flows and/or policies, evaluate the BS bit of the flags in authData. *)
  (* 20. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in pkOptions.pubKeyCredParams. *)
  let* attested_credential_data =
    Option.to_result ~none:"auth_data.attestedCredentialData is not present"
      auth_data.attested_credential_data
  in
  let* () =
    if
      List.mem attested_credential_data.credential_public_key.alg supported_algs
    then Ok ()
    else Error "Public key algorithm is not supported"
  in
  (* 21. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. *)
  let* att_stmt_fmt =
    Option.to_result ~none:"Unrecognized attestation statement format"
      (Spec.Attestation_statement_format_identifier.of_string fmt)
  in
  (* 22. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash. *)
  let* attestation_type, trust_path =
    verify_att_stmt att_stmt_fmt att_stmt
      (attestation_object.auth_data, auth_data)
      hash
  in
  (* 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. *)
  (* 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows: *)
  (*   If no attestation was provided, verify that None attestation is acceptable under Relying Party policy. *)
  (*   If self attestation was used, verify that self attestation is acceptable under Relying Party policy. *)
  (*   Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure to verify that the attestation public key either correctly chains up to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in step 22 may be the same). *)
  let* () =
    if check_attestation ~attestation_type ~trust_path then Ok ()
    else Error "attestation trustworthiness assertion failed"
  in
  (* 25. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony. *)
  let* () =
    if attested_credential_data.credential_id_length <= 1023 then Ok ()
    else Error "credentialId is not ≤ 1023 bytes"
  in
  (* 26. Verify that the credentialId is not yet registered for any user. If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony. *)
  let* () =
    if is_credential_id_registered attested_credential_data.credential_id then
      Error "this credentialId is already registered"
    else Ok ()
  in
  (* 27. Let credentialRecord be a new credential record with the following contents: *)
  let credential_record =
    Spec.Credential_record.
      {
        type_ = credential.type_;
        id = attested_credential_data.credential_id;
        public_key = attested_credential_data.credential_public_key;
        sign_count = auth_data.sign_count;
        uv_initialized = auth_data.flags.user_verified;
        transports = response.transports;
        backup_eligible = auth_data.flags.backup_eligibility;
        backup_state = auth_data.flags.backup_state;
        attestation_object =
          response.attestation_object |> Spec.Base64_url_string.to_raw;
        attestation_client_data_json =
          response.client_data_json |> Spec.Base64_url_string.to_raw;
        rp_id;
        aaguid = attested_credential_data.aaguid;
      }
  in
  (* 28. Process the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData as required by the Relying Party. *)
  (* PASS *)
  (* 29. If all the above steps are successful, store credentialRecord in the user account that was denoted in pkOptions.user and continue the registration ceremony as appropriate. Otherwise, fail the registration ceremony. *)
  Ok { credential_record }
