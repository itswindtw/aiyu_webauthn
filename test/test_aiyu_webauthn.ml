open Aiyu_webauthn

let rp_id = "example.org"
let origin = "https://example.org"
let top_origin = "https://example.com"
let check_origin x = x = origin
let check_top_origin x = x = top_origin

let uv_be_bs_from_hex hex =
  let value = String.get_uint8 (Hex.to_string hex) 0 in
  let uv = value land 0x04 <> 0 in
  let be = value land 0x08 <> 0 in
  let bs = if be then value land 0x10 <> 0 else false in
  (uv, be, bs)

let test_registration
    (* Test vectors *)
    ~challenge ~aaguid ~credential_id ~auth_data_UV_BE_BS ~client_data_json
    ~attestation_object ?(allow_cross_origin = false)
    (* Parameters *)
    ~check_attestation ?check_top_origin
    (* Input *)
      () =
  let challenge =
    `Hex challenge |> Hex.to_string |> Spec.Base64_url_string.of_raw
  in
  let aaguid = `Hex aaguid |> Hex.to_string in
  let credential_id = `Hex credential_id |> Hex.to_string in
  let uv, be, bs = uv_be_bs_from_hex (`Hex auth_data_UV_BE_BS) in
  let client_data_json = `Hex client_data_json |> Hex.to_string in
  let attestation_object = `Hex attestation_object |> Hex.to_string in
  let transports = [] in

  let registration_response =
    Spec.Registration_response_json.(
      {
        id = credential_id;
        raw_id = Spec.Base64_url_string.of_raw credential_id;
        response =
          Spec.Authenticator_attestation_response_json.
            {
              client_data_json = Spec.Base64_url_string.of_raw client_data_json;
              attestation_object =
                Spec.Base64_url_string.of_raw attestation_object;
              transports;
            };
        authenticator_attachment = None;
        client_extension_results = `Assoc [];
        type_ = "public-key";
      }
      |> to_json |> Json.to_string)
  in
  match
    Registration.Response.verify ~registration_response ~challenge ~rp_id
      ~check_origin ?check_top_origin ~check_attestation ~allow_cross_origin
      ~require_user_present:false ~require_user_verification:false
      ~is_credential_id_registered:(fun _ -> false)
      ()
  with
  | Ok ({ credential_record } as result) ->
      Alcotest.(check string) __LOC__ "public-key" credential_record.type_;
      Alcotest.(check string) __LOC__ credential_id credential_record.id;
      Alcotest.(check bool) __LOC__ uv credential_record.uv_initialized;
      Alcotest.(check bool) __LOC__ be credential_record.backup_eligible;
      Alcotest.(check bool) __LOC__ bs credential_record.backup_state;
      Alcotest.(check string)
        __LOC__ attestation_object credential_record.attestation_object;
      Alcotest.(check string)
        __LOC__ client_data_json credential_record.attestation_client_data_json;
      Alcotest.(check string) __LOC__ aaguid credential_record.aaguid;
      result
  | Error m -> Alcotest.fail m

let test_authentication
    (* Test vectors *)
    ~challenge ~auth_data_UV_BS ~authenticator_data ~client_data_json ~signature
    ?(allow_cross_origin = false)
    (* Parameters *)
    ?check_top_origin
    (* Input *)
      ({ credential_record } : Registration.Response.verfication_result) =
  let challenge =
    `Hex challenge |> Hex.to_string |> Spec.Base64_url_string.of_raw
  in
  let uv, _be, bs = uv_be_bs_from_hex (`Hex auth_data_UV_BS) in
  (* BS is set only if BE was set in the registration *)
  let bs = if credential_record.backup_eligible then bs else false in
  let authenticator_data = `Hex authenticator_data |> Hex.to_string in
  let client_data_json = `Hex client_data_json |> Hex.to_string in
  let signature = `Hex signature |> Hex.to_string in
  let authentication_response =
    Spec.Authentication_response_json.(
      {
        id = credential_record.id;
        raw_id = Spec.Base64_url_string.of_raw credential_record.id;
        response =
          Spec.Authenticator_assertion_response_json.
            {
              client_data_json = Spec.Base64_url_string.of_raw client_data_json;
              authenticator_data =
                Spec.Base64_url_string.of_raw authenticator_data;
              signature = Spec.Base64_url_string.of_raw signature;
              user_handle = None;
            };
        authenticator_attachment = None;
        client_extension_results = `Assoc [];
        type_ = "public-key";
      }
      |> to_json |> Json.to_string)
  in
  match
    Authentication.Response.verify ~authentication_response ~challenge ~rp_id
      ~fetch_credential_record:(fun ~user_handle ~credential_id ->
        Ok credential_record)
      ~check_origin ?check_top_origin ~allow_cross_origin
      ~require_user_verification:false ()
  with
  | Ok result ->
      Alcotest.(check bool)
        __LOC__
        (credential_record.uv_initialized || uv)
        result.credential_record.uv_initialized;
      Alcotest.(check bool) __LOC__ bs result.credential_record.backup_state
  | Error msg -> Alcotest.fail msg

let test_16_2 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-0acd8a1f
    challenge = h'00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='none.ES256', L=32)

    credential_private_key = h'6e68e7a58484a3264f66b77f5d6dc5bc36a47085b615c9727ab334e8c369c2ee'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='none.ES256', L=32)
    client_data_gen_flags = h'f9'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='none.ES256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'06441e0e375c4c1ad70620302532c4e5' = b64'BkQeDjdcTBrXBiAwJTLE5Q'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='none.ES256', L=16)
    aaguid = h'8446ccb9ab1db374750b2367ff6f3a1f'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='none.ES256', L=16)
    credential_id = h'f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='none.ES256', L=32)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'ba'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='none.ES256', L=1)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d'
    attestationObject = h'a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220'
    *)
    test_registration
      ~challenge:
        "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
      ~aaguid:"8446ccb9ab1db374750b2367ff6f3a1f"
      ~credential_id:
        "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
      ~auth_data_UV_BE_BS:"ba"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
      ~attestation_object:
        "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.None, [] -> true
        | _ -> false)
  in

  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-6179f191
    challenge = h'39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='none.ES256', L=32)

    client_data_gen_flags = h'4a'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='none.ES256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'38'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'09', info='none.ES256', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d'
    signature = h'3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87'
    *)
    test_authentication
      ~challenge:
        "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
      ~auth_data_UV_BS:"38"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
      ~signature:
        "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
  in
  test_registration () |> test_authentication

let test_16_3 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-4c550ae2
    challenge = h'7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='packed-self.ES256', L=32)

    credential_private_key = h'b4bbfa5d68e1693b6ef5a19a0e60ef7ee2cbcac81f7fec7006ac3a21e0c5116a'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='packed-self.ES256', L=32)
    client_data_gen_flags = h'db'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='packed-self.ES256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'53d8535ef284d944643276ffd3160756' = b64'U9hTXvKE2URkMnb_0xYHVg'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='packed-self.ES256', L=16)
    aaguid = h'df850e09db6afbdfab51697791506cfc'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='packed-self.ES256', L=16)
    credential_id = h'455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='packed-self.ES256', L=32)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'fd'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='packed-self.ES256', L=1)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d'
    attestationObject = h'a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2'
    *)
    test_registration
      ~challenge:
        "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5"
      ~aaguid:"df850e09db6afbdfab51697791506cfc"
      ~credential_id:
        "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c"
      ~auth_data_UV_BE_BS:"fd"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d"
      ~attestation_object:
        "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.Self, [] -> true
        | _ -> false)
  in

  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-f088ddd3
    challenge = h'4478a10b1352348dd160c1353b0d469b5db19eb91c27f7dfa6fed39fe26af20b'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='packed-self.ES256', L=32)

    client_data_gen_flags = h'1f'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='packed-self.ES256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'8136f9debcfa121496a265c6ce2982d5' = b64'gTb53rz6EhSWomXGzimC1Q'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'09', info='packed-self.ES256', L=16)
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'a1'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'0a', info='packed-self.ES256', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50900000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a225248696843784e534e493352594d45314f7731476d3132786e726b634a5f6666707637546e2d4a71386773222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a206754623533727a36456853576f6d58477a696d433151227d'
    signature = h'304402203310b9431903c401f1be2bdc8d23a4007682dbbddcf846994947b7f465daf84002204e94dd00047b316061b3b99772b7efd95994a83ef584b3b6b825ea3550251b66'
    *)
    test_authentication
      ~challenge:
        "4478a10b1352348dd160c1353b0d469b5db19eb91c27f7dfa6fed39fe26af20b"
      ~auth_data_UV_BS:"a1"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50900000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a225248696843784e534e493352594d45314f7731476d3132786e726b634a5f6666707637546e2d4a71386773222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a206754623533727a36456853576f6d58477a696d433151227d"
      ~signature:
        "304402203310b9431903c401f1be2bdc8d23a4007682dbbddcf846994947b7f465daf84002204e94dd00047b316061b3b99772b7efd95994a83ef584b3b6b825ea3550251b66"
  in
  test_registration () |> test_authentication

let test_16_4 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-ffe119c7
    challenge = h'3be5aacd03537142472340ab5969f240f1d87716e20b6807ac230655fa4b3b49'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='none.ES256.crossOrigin', L=32)

    credential_private_key = h'96c940e769bd9f1237c119f144fa61a4d56af0b3289685ae2bef7fb89620623d'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='none.ES256.crossOrigin', L=32)
    client_data_gen_flags = h'71'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='none.ES256.crossOrigin', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'cd9aae12d0d1f435aaa56e6d0564c5ba' = b64'zZquEtDR9DWqpW5tBWTFug'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='none.ES256.crossOrigin', L=16)
    aaguid = h'883f4f6014f19c09d87aa38123be48d0'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='none.ES256.crossOrigin', L=16)
    credential_id = h'6e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='none.ES256.crossOrigin', L=32)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'27'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='none.ES256.crossOrigin', L=1)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a224f2d57717a514e5463554a484930437257576e7951504859647862694332674872434d475666704c4f306b222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a207a5a7175457444523944577170573574425754467567227d'
    attestationObject = h'a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54500000000883f4f6014f19c09d87aa38123be48d000206e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57a501020326200121582022200a473f90b11078851550d03b4e44a2279f8c4eca27b3153dedfe03e4e97d225820cbd0be95e746ad6f5a8191be11756e4c0420e72f65b466d39bc56b8b123a9c6e'
    *)
    test_registration
      ~challenge:
        "3be5aacd03537142472340ab5969f240f1d87716e20b6807ac230655fa4b3b49"
      ~aaguid:"883f4f6014f19c09d87aa38123be48d0"
      ~credential_id:
        "6e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57"
      ~auth_data_UV_BE_BS:"27"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a224f2d57717a514e5463554a484930437257576e7951504859647862694332674872434d475666704c4f306b222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a207a5a7175457444523944577170573574425754467567227d"
      ~attestation_object:
        "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54500000000883f4f6014f19c09d87aa38123be48d000206e1050c0d2ca2f07c755cb2c66a74c64fa43065c18f938354d9915db2bd5ce57a501020326200121582022200a473f90b11078851550d03b4e44a2279f8c4eca27b3153dedfe03e4e97d225820cbd0be95e746ad6f5a8191be11756e4c0420e72f65b466d39bc56b8b123a9c6e"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.None, [] -> true
        | _ -> false)
      ~allow_cross_origin:true
  in

  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-9c18c6d1
    challenge = h'876aa517ba83fdee65fcffdbca4c84eeae5d54f8041a1fc85c991e5bbb273137'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='none.ES256.crossOrigin', L=32)

    client_data_gen_flags = h'57'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='none.ES256.crossOrigin', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'f76a5c4d50f401bcbeab876d9a3e9e7e' = b64'92pcTVD0Aby-q4dtmj6efg'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'09', info='none.ES256.crossOrigin', L=16)
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'0c'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'0a', info='none.ES256.crossOrigin', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226832716c463771445f65356c5f505f62796b7945377135645650674547685f49584a6b655737736e4d5463222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a2039327063545644304162792d713464746d6a36656667227d'
    signature = h'3046022100eb12fcf23b12764c0f122e22371fab92e283879fd798f38ee1841c951b6e40e7022100c76237ff9db77b3c56f30837cda6a09acfa2e915544e609c0733b1184036d1cf'
    *)
    test_authentication
      ~challenge:
        "876aa517ba83fdee65fcffdbca4c84eeae5d54f8041a1fc85c991e5bbb273137"
      ~auth_data_UV_BS:"0c"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a226832716c463771445f65356c5f505f62796b7945377135645650674547685f49584a6b655737736e4d5463222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a2039327063545644304162792d713464746d6a36656667227d"
      ~signature:
        "3046022100eb12fcf23b12764c0f122e22371fab92e283879fd798f38ee1841c951b6e40e7022100c76237ff9db77b3c56f30837cda6a09acfa2e915544e609c0733b1184036d1cf"
      ~allow_cross_origin:true
  in
  test_registration () |> test_authentication

let test_16_5 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-2a557330
    challenge = h'4e1f4c6198699e33c14f192153f49d7e0e8e3577d5ac416c5f3adc92a41f27e5'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='none.ES256.topOrigin', L=32)

    credential_private_key = h'a2d6de40ab974b80d8c1ef78c6d4300097754f7e016afe7f8ea0ad9798b0d420'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='none.ES256.topOrigin', L=32)
    client_data_gen_flags = h'54'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='none.ES256.topOrigin', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    aaguid = h'97586fd09799a76401c200455099ef2a'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='none.ES256.topOrigin', L=16)
    credential_id = h'b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='none.ES256.topOrigin', L=32)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'a0'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='none.ES256.topOrigin', L=1)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a225468394d595a68706e6a504254786b68555f53646667364f4e58665672454673587a72636b7151664a2d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d'
    attestationObject = h'a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5410000000097586fd09799a76401c200455099ef2a0020b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1a5010203262001215820a1c47c1d82da4ebe82cd72207102b380670701993bc35398ae2e5726427fe01d22582086c1080d82987028c7f54ecb1b01185de243b359294a0ed210cd47480f0adc88'
    *)
    test_registration
      ~challenge:
        "4e1f4c6198699e33c14f192153f49d7e0e8e3577d5ac416c5f3adc92a41f27e5"
      ~aaguid:"97586fd09799a76401c200455099ef2a"
      ~credential_id:
        "b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1"
      ~auth_data_UV_BE_BS:"a0"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a225468394d595a68706e6a504254786b68555f53646667364f4e58665672454673587a72636b7151664a2d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d"
      ~attestation_object:
        "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5410000000097586fd09799a76401c200455099ef2a0020b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1a5010203262001215820a1c47c1d82da4ebe82cd72207102b380670701993bc35398ae2e5726427fe01d22582086c1080d82987028c7f54ecb1b01185de243b359294a0ed210cd47480f0adc88"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.None, [] -> true
        | _ -> false)
      ~allow_cross_origin:true ~check_top_origin
  in

  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-66b193ae
    challenge = h'd54a5c8ca4b62a8e3bb321e3b2bc73856f85a10150db2939ac195739eb1ea066'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='none.ES256.topOrigin', L=32)

    client_data_gen_flags = h'77'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='none.ES256.topOrigin', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'52216824c5514070c0156162e2fc54a5' = b64'UiFoJMVRQHDAFWFi4vxUpQ'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='none.ES256.topOrigin', L=16)
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'9f'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'09', info='none.ES256.topOrigin', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22315570636a4b53324b6f34377379486a7372787a68572d466f51465132796b3572426c584f6573656f4759222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d222c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205569466f4a4d56525148444146574669347678557051227d'
    signature = h'3045022100b5a70c81780d5fcc9a4f2ae9caae99058f8accaf58b91fb59329646c28ac6ffc022012e101c165db3c8e9957f0c54dd6ca9b56bc3bd2f280bd2faa6c1d02c6e5c171'
    *)
    test_authentication
      ~challenge:
        "d54a5c8ca4b62a8e3bb321e3b2bc73856f85a10150db2939ac195739eb1ea066"
      ~auth_data_UV_BS:"9f"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50500000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22315570636a4b53324b6f34377379486a7372787a68572d466f51465132796b3572426c584f6573656f4759222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d222c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205569466f4a4d56525148444146574669347678557051227d"
      ~signature:
        "3045022100b5a70c81780d5fcc9a4f2ae9caae99058f8accaf58b91fb59329646c28ac6ffc022012e101c165db3c8e9957f0c54dd6ca9b56bc3bd2f280bd2faa6c1d02c6e5c171"
      ~allow_cross_origin:true ~check_top_origin
  in
  test_registration () |> test_authentication

let test_16_6 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-f566bb36
    challenge = h'1113c7265ccf5e65124282fa1d7819a7a14cb8539aa4cdbec7487e5f35d8ec6c'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='none.ES256.long-credential-id', L=32)

    credential_private_key = h'6fd2149bb5f1597fe549b138794bde61893b2dc32ca316de65f04808dac211dc'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='none.ES256.long-credential-id', L=32)
    client_data_gen_flags = h'90'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='none.ES256.long-credential-id', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    aaguid = h'8f3360c2cd1b0ac14ffe0795c5d2638e'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='none.ES256.long-credential-id', L=16)
    credential_id = h'3a761a4e1674ad6c4305869435c0eee9c286172c229bb91b48b4ada140c0863417031305cce5b4a27a88d7fe728a5f5a627de771b4b40e77f187980c124f9fe832d7136010436a056cce716680587d23187cf1fc2c62ae86fc3e508ee9617ffc74fbc10488ec16ec5e9096328669a898709b655e549738c666c1ae6281dc3b5f733c251d3eefb76ee70a3805ca91bcc18e49c8dc7f63ebcb486ba8c3d6ab52b88ff72c6a5bb47c32f3ee8683a3ddc8abf60870448ec8a21b5bdcb183c7dead870255575a6df96eb1b6a2a1019780cba9e4887b17ff1164bbbcc10eb0d86ed75984cd3fa3419103024507dfd9ce8f92c56af7914cb0bb50b87ba82a312bb7dcd93028dbdcd6adb266979667158335171e3682d37755701edbf9d872846a291d49e57ef09da1ec637f5052ed2aa7407f7e61827468e94b461844f4c67be5fa9c6055a566f8fdfc29d4bf78a9ff275f552cc68ba543fa3962eea36fd1ea8453764577d021d0a181efc1f6100ab2e4110039e21ee16970bda7432b6134492155afc126295b3a2eccd12c66a68e340969e995e3e8c9c476e395cfc21203414110779474f1c9797406637dbe414f132519d3bf0ce4f01734ef0e1a12c3ad604ff15d766b1624db6a5a7ccbff7bc35c9908df94aba277e0af48f04ff3d16381c47e5a37ed3988a67a3b1ecaa926336b33391fff04128f869991c9fabd905b6fe3ceef5f8b630ec1c5d2636d5b1961ad5ca5004170f6f5e482792aad989b0287fe91e5c479403397152f1fa56aa79b156eb47e6c8ea3eb175c34cfb38ad8e772874639b1023d4d01395c94e55831671cc022aa6fa1e02a02c2e4abc776f6960e51f83b71a8c0f207b6a347573977812c9aa5480b0011aa739bd4b76c18c000cc4757cceccb920f007c40c00e37e5ab21476cd9f6054a8fffb55a108f5c706e2cea2049d81fd321ff47d2a5761b0800955ab1d4f4889f55a84e2601c684f17a4ade7453ea49591d0b59c8d9a765052f62219cf6ef4a5dd9539f0617d6ebbebce7c000455475d18449e25c49ef9a1e3efe18c09082ebe2058d7c347defaa92f0664553b805c7d76bbfce5f330aca220ac90a789380fc479ea0d8793205813cca590a912f699ad52f991a1bc0a503c3ec4b2a696719e3c26591a87127f7305cc7e72f4c8e39355ebb06a5b1042990f38710ee7aa612ee4374bb82e878585a70a96c2a6b47f101a4ff154be4fd76a3167577a5cc54d9167c154c69ac35485e44cc898b719e1be3cc9c0fb5624b8f8a0dae10947a41bf848b6c1bb33d1006ec077d7e286e3f2a7b4843716390119449fe2721e81a5ed2333d331c7120765da58fadae73c19d9a8c4509cf8ac1e9d98b799a5274509069739b5823f3fb496663820033426988eefca53e580e0f9e0dfe0992fc2e53a97e053639f98577058f995bdbd41cefdb'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='none.ES256.long-credential-id', L=1023)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'69'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='none.ES256.long-credential-id', L=1)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22455250484a6c7a50586d5553516f4c364858675a7036464d75464f61704d322d7830682d587a5859374777222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d'
    attestationObject = h'a363666d74646e6f6e656761747453746d74a0686175746844617461590483bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b549000000008f3360c2cd1b0ac14ffe0795c5d2638e03ff3a761a4e1674ad6c4305869435c0eee9c286172c229bb91b48b4ada140c0863417031305cce5b4a27a88d7fe728a5f5a627de771b4b40e77f187980c124f9fe832d7136010436a056cce716680587d23187cf1fc2c62ae86fc3e508ee9617ffc74fbc10488ec16ec5e9096328669a898709b655e549738c666c1ae6281dc3b5f733c251d3eefb76ee70a3805ca91bcc18e49c8dc7f63ebcb486ba8c3d6ab52b88ff72c6a5bb47c32f3ee8683a3ddc8abf60870448ec8a21b5bdcb183c7dead870255575a6df96eb1b6a2a1019780cba9e4887b17ff1164bbbcc10eb0d86ed75984cd3fa3419103024507dfd9ce8f92c56af7914cb0bb50b87ba82a312bb7dcd93028dbdcd6adb266979667158335171e3682d37755701edbf9d872846a291d49e57ef09da1ec637f5052ed2aa7407f7e61827468e94b461844f4c67be5fa9c6055a566f8fdfc29d4bf78a9ff275f552cc68ba543fa3962eea36fd1ea8453764577d021d0a181efc1f6100ab2e4110039e21ee16970bda7432b6134492155afc126295b3a2eccd12c66a68e340969e995e3e8c9c476e395cfc21203414110779474f1c9797406637dbe414f132519d3bf0ce4f01734ef0e1a12c3ad604ff15d766b1624db6a5a7ccbff7bc35c9908df94aba277e0af48f04ff3d16381c47e5a37ed3988a67a3b1ecaa926336b33391fff04128f869991c9fabd905b6fe3ceef5f8b630ec1c5d2636d5b1961ad5ca5004170f6f5e482792aad989b0287fe91e5c479403397152f1fa56aa79b156eb47e6c8ea3eb175c34cfb38ad8e772874639b1023d4d01395c94e55831671cc022aa6fa1e02a02c2e4abc776f6960e51f83b71a8c0f207b6a347573977812c9aa5480b0011aa739bd4b76c18c000cc4757cceccb920f007c40c00e37e5ab21476cd9f6054a8fffb55a108f5c706e2cea2049d81fd321ff47d2a5761b0800955ab1d4f4889f55a84e2601c684f17a4ade7453ea49591d0b59c8d9a765052f62219cf6ef4a5dd9539f0617d6ebbebce7c000455475d18449e25c49ef9a1e3efe18c09082ebe2058d7c347defaa92f0664553b805c7d76bbfce5f330aca220ac90a789380fc479ea0d8793205813cca590a912f699ad52f991a1bc0a503c3ec4b2a696719e3c26591a87127f7305cc7e72f4c8e39355ebb06a5b1042990f38710ee7aa612ee4374bb82e878585a70a96c2a6b47f101a4ff154be4fd76a3167577a5cc54d9167c154c69ac35485e44cc898b719e1be3cc9c0fb5624b8f8a0dae10947a41bf848b6c1bb33d1006ec077d7e286e3f2a7b4843716390119449fe2721e81a5ed2333d331c7120765da58fadae73c19d9a8c4509cf8ac1e9d98b799a5274509069739b5823f3fb496663820033426988eefca53e580e0f9e0dfe0992fc2e53a97e053639f98577058f995bdbd41cefdba50102032620012158203b8176b7504489cc593046d7988abb7905a742de6ac2cdc748a873c663e90cb12258201436d5edc9a75f23999eef9d5950a5c2455514ee1014084720f841a06b828a11'
    *)
    test_registration
      ~challenge:
        "1113c7265ccf5e65124282fa1d7819a7a14cb8539aa4cdbec7487e5f35d8ec6c"
      ~aaguid:"8f3360c2cd1b0ac14ffe0795c5d2638e"
      ~credential_id:
        "3a761a4e1674ad6c4305869435c0eee9c286172c229bb91b48b4ada140c0863417031305cce5b4a27a88d7fe728a5f5a627de771b4b40e77f187980c124f9fe832d7136010436a056cce716680587d23187cf1fc2c62ae86fc3e508ee9617ffc74fbc10488ec16ec5e9096328669a898709b655e549738c666c1ae6281dc3b5f733c251d3eefb76ee70a3805ca91bcc18e49c8dc7f63ebcb486ba8c3d6ab52b88ff72c6a5bb47c32f3ee8683a3ddc8abf60870448ec8a21b5bdcb183c7dead870255575a6df96eb1b6a2a1019780cba9e4887b17ff1164bbbcc10eb0d86ed75984cd3fa3419103024507dfd9ce8f92c56af7914cb0bb50b87ba82a312bb7dcd93028dbdcd6adb266979667158335171e3682d37755701edbf9d872846a291d49e57ef09da1ec637f5052ed2aa7407f7e61827468e94b461844f4c67be5fa9c6055a566f8fdfc29d4bf78a9ff275f552cc68ba543fa3962eea36fd1ea8453764577d021d0a181efc1f6100ab2e4110039e21ee16970bda7432b6134492155afc126295b3a2eccd12c66a68e340969e995e3e8c9c476e395cfc21203414110779474f1c9797406637dbe414f132519d3bf0ce4f01734ef0e1a12c3ad604ff15d766b1624db6a5a7ccbff7bc35c9908df94aba277e0af48f04ff3d16381c47e5a37ed3988a67a3b1ecaa926336b33391fff04128f869991c9fabd905b6fe3ceef5f8b630ec1c5d2636d5b1961ad5ca5004170f6f5e482792aad989b0287fe91e5c479403397152f1fa56aa79b156eb47e6c8ea3eb175c34cfb38ad8e772874639b1023d4d01395c94e55831671cc022aa6fa1e02a02c2e4abc776f6960e51f83b71a8c0f207b6a347573977812c9aa5480b0011aa739bd4b76c18c000cc4757cceccb920f007c40c00e37e5ab21476cd9f6054a8fffb55a108f5c706e2cea2049d81fd321ff47d2a5761b0800955ab1d4f4889f55a84e2601c684f17a4ade7453ea49591d0b59c8d9a765052f62219cf6ef4a5dd9539f0617d6ebbebce7c000455475d18449e25c49ef9a1e3efe18c09082ebe2058d7c347defaa92f0664553b805c7d76bbfce5f330aca220ac90a789380fc479ea0d8793205813cca590a912f699ad52f991a1bc0a503c3ec4b2a696719e3c26591a87127f7305cc7e72f4c8e39355ebb06a5b1042990f38710ee7aa612ee4374bb82e878585a70a96c2a6b47f101a4ff154be4fd76a3167577a5cc54d9167c154c69ac35485e44cc898b719e1be3cc9c0fb5624b8f8a0dae10947a41bf848b6c1bb33d1006ec077d7e286e3f2a7b4843716390119449fe2721e81a5ed2333d331c7120765da58fadae73c19d9a8c4509cf8ac1e9d98b799a5274509069739b5823f3fb496663820033426988eefca53e580e0f9e0dfe0992fc2e53a97e053639f98577058f995bdbd41cefdb"
      ~auth_data_UV_BE_BS:"69"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22455250484a6c7a50586d5553516f4c364858675a7036464d75464f61704d322d7830682d587a5859374777222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
      ~attestation_object:
        "a363666d74646e6f6e656761747453746d74a0686175746844617461590483bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b549000000008f3360c2cd1b0ac14ffe0795c5d2638e03ff3a761a4e1674ad6c4305869435c0eee9c286172c229bb91b48b4ada140c0863417031305cce5b4a27a88d7fe728a5f5a627de771b4b40e77f187980c124f9fe832d7136010436a056cce716680587d23187cf1fc2c62ae86fc3e508ee9617ffc74fbc10488ec16ec5e9096328669a898709b655e549738c666c1ae6281dc3b5f733c251d3eefb76ee70a3805ca91bcc18e49c8dc7f63ebcb486ba8c3d6ab52b88ff72c6a5bb47c32f3ee8683a3ddc8abf60870448ec8a21b5bdcb183c7dead870255575a6df96eb1b6a2a1019780cba9e4887b17ff1164bbbcc10eb0d86ed75984cd3fa3419103024507dfd9ce8f92c56af7914cb0bb50b87ba82a312bb7dcd93028dbdcd6adb266979667158335171e3682d37755701edbf9d872846a291d49e57ef09da1ec637f5052ed2aa7407f7e61827468e94b461844f4c67be5fa9c6055a566f8fdfc29d4bf78a9ff275f552cc68ba543fa3962eea36fd1ea8453764577d021d0a181efc1f6100ab2e4110039e21ee16970bda7432b6134492155afc126295b3a2eccd12c66a68e340969e995e3e8c9c476e395cfc21203414110779474f1c9797406637dbe414f132519d3bf0ce4f01734ef0e1a12c3ad604ff15d766b1624db6a5a7ccbff7bc35c9908df94aba277e0af48f04ff3d16381c47e5a37ed3988a67a3b1ecaa926336b33391fff04128f869991c9fabd905b6fe3ceef5f8b630ec1c5d2636d5b1961ad5ca5004170f6f5e482792aad989b0287fe91e5c479403397152f1fa56aa79b156eb47e6c8ea3eb175c34cfb38ad8e772874639b1023d4d01395c94e55831671cc022aa6fa1e02a02c2e4abc776f6960e51f83b71a8c0f207b6a347573977812c9aa5480b0011aa739bd4b76c18c000cc4757cceccb920f007c40c00e37e5ab21476cd9f6054a8fffb55a108f5c706e2cea2049d81fd321ff47d2a5761b0800955ab1d4f4889f55a84e2601c684f17a4ade7453ea49591d0b59c8d9a765052f62219cf6ef4a5dd9539f0617d6ebbebce7c000455475d18449e25c49ef9a1e3efe18c09082ebe2058d7c347defaa92f0664553b805c7d76bbfce5f330aca220ac90a789380fc479ea0d8793205813cca590a912f699ad52f991a1bc0a503c3ec4b2a696719e3c26591a87127f7305cc7e72f4c8e39355ebb06a5b1042990f38710ee7aa612ee4374bb82e878585a70a96c2a6b47f101a4ff154be4fd76a3167577a5cc54d9167c154c69ac35485e44cc898b719e1be3cc9c0fb5624b8f8a0dae10947a41bf848b6c1bb33d1006ec077d7e286e3f2a7b4843716390119449fe2721e81a5ed2333d331c7120765da58fadae73c19d9a8c4509cf8ac1e9d98b799a5274509069739b5823f3fb496663820033426988eefca53e580e0f9e0dfe0992fc2e53a97e053639f98577058f995bdbd41cefdba50102032620012158203b8176b7504489cc593046d7988abb7905a742de6ac2cdc748a873c663e90cb12258201436d5edc9a75f23999eef9d5950a5c2455514ee1014084720f841a06b828a11"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.None, [] -> true
        | _ -> false)
  in
  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-c1500f32
    challenge = h'ef1deba56dce48f674a447ccf63b9599258ce87648e5c396f2ef0ca1da460e3b'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='none.ES256.long-credential-id', L=32)

    client_data_gen_flags = h'80'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='none.ES256.long-credential-id', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'e5'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='none.ES256.long-credential-id', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22377833727057334f53505a307045664d396a75566d53574d36485a4935634f573875384d6f647047446a73222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d'
    signature = h'304502203ecef83fb12a0cae7841055f9f87103a99fd14b424194bbf06c4623d3ee6e3fd022100d2ace346db262b1374a6b70faa51f518a42ddca13a4125ce6f5052a75bac9fb6'
    *)
    test_authentication
      ~challenge:
        "ef1deba56dce48f674a447ccf63b9599258ce87648e5c396f2ef0ca1da460e3b"
      ~auth_data_UV_BS:"e5"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22377833727057334f53505a307045664d396a75566d53574d36485a4935634f573875384d6f647047446a73222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
      ~signature:
        "304502203ecef83fb12a0cae7841055f9f87103a99fd14b424194bbf06c4623d3ee6e3fd022100d2ace346db262b1374a6b70faa51f518a42ddca13a4125ce6f5052a75bac9fb6"
  in
  test_registration () |> test_authentication

let test_16_7 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-3ec91adf
    challenge = h'c1184a5fddf8045e13dc47f54b61f5a656b666b59018f16d870e9256e9952012'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='packed.ES256', L=32)

    credential_private_key = h'36ed7bea2357cefa8c4ec7e134f3312d2e6ca3058519d0bcb4c1424272010432'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='packed.ES256', L=32)
    client_data_gen_flags = h'8d'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='packed.ES256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'f5af1b3588ca0a05ab05753e7c29756a' = b64'9a8bNYjKCgWrBXU-fCl1ag'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='packed.ES256', L=16)
    aaguid = h'876ca4f52071c3e9b25509ef2cdf7ed6'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='packed.ES256', L=16)
    credential_id = h'c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='packed.ES256', L=32)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'4f'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='packed.ES256', L=1)
    attestation_private_key = h'ec2804b222552b4b277d1f58f8c4343c0b0b0db5474eb55365c89d66a2bc96be'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='packed.ES256', L=32)
    attestation_cert_serial_number = h'88c220f83c8ef1feafe94deae45faad0'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='packed.ES256', L=16)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a227752684b58393334424634543345663153324831706c61325a725751475046746877365356756d56494249222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20396138624e596a4b436757724258552d66436c316167227d'
    attestationObject = h'a363666d74667061636b65646761747453746d74a363616c6726637369675847304502203f19ec4b229f46ab8c45eff29b904ff10c0390dc40bf1216f04a78f4ceba3425022100fe7041a32759aff05a0f9f26c70a999c7a284451ba89234a1d3483c25e21925b637835638159022530820221308201c8a00302010202110088c220f83c8ef1feafe94deae45faad0300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004a91ba4389409dd38a428141940ca8feb1ac0d7b4350558104a3777a49322f3798440f378b3398ab2d3bb7bf91322c92eb23556f59ad0a836fec4c7663b0e4dc3a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414a589ba72d060842ab11f74fb246bdedab16f9b9b301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d040302034700304402201726b9d85ecd8a5ed51163722ca3a20886fd9b242a0aa0453d442116075defd502207ef471e530ac87961a88a7f0d0c17b091ffc6b9238d30f79f635b417be5910e768617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54d00000000876ca4f52071c3e9b25509ef2cdf7ed60020c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423'
    *)
    test_registration
      ~challenge:
        "c1184a5fddf8045e13dc47f54b61f5a656b666b59018f16d870e9256e9952012"
      ~aaguid:"876ca4f52071c3e9b25509ef2cdf7ed6"
      ~credential_id:
        "c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5"
      ~auth_data_UV_BE_BS:"4f"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a227752684b58393334424634543345663153324831706c61325a725751475046746877365356756d56494249222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20396138624e596a4b436757724258552d66436c316167227d"
      ~attestation_object:
        "a363666d74667061636b65646761747453746d74a363616c6726637369675847304502203f19ec4b229f46ab8c45eff29b904ff10c0390dc40bf1216f04a78f4ceba3425022100fe7041a32759aff05a0f9f26c70a999c7a284451ba89234a1d3483c25e21925b637835638159022530820221308201c8a00302010202110088c220f83c8ef1feafe94deae45faad0300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004a91ba4389409dd38a428141940ca8feb1ac0d7b4350558104a3777a49322f3798440f378b3398ab2d3bb7bf91322c92eb23556f59ad0a836fec4c7663b0e4dc3a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414a589ba72d060842ab11f74fb246bdedab16f9b9b301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d040302034700304402201726b9d85ecd8a5ed51163722ca3a20886fd9b242a0aa0453d442116075defd502207ef471e530ac87961a88a7f0d0c17b091ffc6b9238d30f79f635b417be5910e768617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54d00000000876ca4f52071c3e9b25509ef2cdf7ed60020c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.Uncertainty, [ _ ] -> true
        | _ -> false)
  in
  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-7d3e1ac8
    challenge = h'b1106fa46a57bef1781511c0557dc898a03413d5f0f17d244630c194c7e1adb5'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'09', info='packed.ES256', L=32)

    client_data_gen_flags = h'75'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'0a', info='packed.ES256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'019330c8cc486c3f3eba0b85369eabf1' = b64'AZMwyMxIbD8-uguFNp6r8Q'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'0b', info='packed.ES256', L=16)
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'46'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'0c', info='packed.ES256', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273524276704770587676463446524841565833496d4b4130453958773858306b526a44426c4d6668726255222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20415a4d77794d78496244382d756775464e7036723851227d'
    signature = h'30450220694969d3ee928de6f02ef23a9c644d7d779916451734a94b432542f498a1ebe90221008b0819c824218a97152cd099c55bfb1477b29d900a49a64018314f9bfccda163'
    *)
    test_authentication
      ~challenge:
        "b1106fa46a57bef1781511c0557dc898a03413d5f0f17d244630c194c7e1adb5"
      ~auth_data_UV_BS:"46"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273524276704770587676463446524841565833496d4b4130453958773858306b526a44426c4d6668726255222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20415a4d77794d78496244382d756775464e7036723851227d"
      ~signature:
        "30450220694969d3ee928de6f02ef23a9c644d7d779916451734a94b432542f498a1ebe90221008b0819c824218a97152cd099c55bfb1477b29d900a49a64018314f9bfccda163"
  in
  test_registration () |> test_authentication

let test_16_10 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-04103622
    challenge = h'bea8f0770009bd57f2c0df6fea9f743a27e4b61bbe923c862c7aad7a9fc8e4a6'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='packed.RS256', L=32)

    ; The two smallest Mersenne primes 2^p - 1 where p >= 1024
    private_key_p = 2^1279 - 1 = h'7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    private_key_q = 2^2203 - 1 = h'07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    client_data_gen_flags = h'1c'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='packed.RS256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    aaguid = h'428f8878298b9862a36ad8c7527bfef2'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='packed.RS256', L=16)
    credential_id = h'992a18acc83f67533600c1138a4b4c4bd236de13629cf025ed17cb00b00b74df'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='packed.RS256', L=32)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'7e'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='packed.RS256', L=1)
    attestation_private_key = h'08a1322d5aa5b5b40cd67c2cc30b038e7921d7888c84c342d50d79f0c5fc3464'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='packed.RS256', L=32)
    attestation_cert_serial_number = h'1f6fb7a5ece81b45896b983a995da5f3'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='packed.RS256', L=16)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2276716a776477414a76566679774e3976367039304f69666b7468752d6b6a79474c48717465705f49354b59222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d'
    attestationObject = h'a363666d74667061636b65646761747453746d74a363616c672663736967584730450221008b8c5c6ea8c142c032e0be69e1353d44461c5c9109941cdda951b976eb95b6b302204d52f406c19e254b3ff9589bd18070fb055ac8db12fdd0a6734bea9d7168e900637835638159022630820222308201c7a00302010202101f6fb7a5ece81b45896b983a995da5f3300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004b7b36b7542a11120b443c794d0c99fdc25a06b76586413d81e086163ef6fe147a557afc34e2861d9057d6d465d4705a0310550bdeeb5f35ee35b9425ab859981a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414fb37b647bccfb9e54d989eaaacc1633868703fb3301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100b86bc129d92afca7d9869a39f70f139a305b4073a39eb654d81424bed5757d91022100cf9f7c60cab7c4a7d3e7f0020f281a93d4fd0a9f95121b989f56932a68885fba68617574684461746159021bbfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000428f8878298b9862a36ad8c7527bfef20020992a18acc83f67533600c1138a4b4c4bd236de13629cf025ed17cb00b00b74dfa4010303390100205901b403fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012143010001'
    *)
    test_registration
      ~challenge:
        "bea8f0770009bd57f2c0df6fea9f743a27e4b61bbe923c862c7aad7a9fc8e4a6"
      ~aaguid:"428f8878298b9862a36ad8c7527bfef2"
      ~credential_id:
        "992a18acc83f67533600c1138a4b4c4bd236de13629cf025ed17cb00b00b74df"
      ~auth_data_UV_BE_BS:"7e"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2276716a776477414a76566679774e3976367039304f69666b7468752d6b6a79474c48717465705f49354b59222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
      ~attestation_object:
        "a363666d74667061636b65646761747453746d74a363616c672663736967584730450221008b8c5c6ea8c142c032e0be69e1353d44461c5c9109941cdda951b976eb95b6b302204d52f406c19e254b3ff9589bd18070fb055ac8db12fdd0a6734bea9d7168e900637835638159022630820222308201c7a00302010202101f6fb7a5ece81b45896b983a995da5f3300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004b7b36b7542a11120b443c794d0c99fdc25a06b76586413d81e086163ef6fe147a557afc34e2861d9057d6d465d4705a0310550bdeeb5f35ee35b9425ab859981a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414fb37b647bccfb9e54d989eaaacc1633868703fb3301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100b86bc129d92afca7d9869a39f70f139a305b4073a39eb654d81424bed5757d91022100cf9f7c60cab7c4a7d3e7f0020f281a93d4fd0a9f95121b989f56932a68885fba68617574684461746159021bbfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000428f8878298b9862a36ad8c7527bfef20020992a18acc83f67533600c1138a4b4c4bd236de13629cf025ed17cb00b00b74dfa4010303390100205901b403fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012143010001"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.Uncertainty, [ _ ] -> true
        | _ -> false)
  in
  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-6401759a
    challenge = h'295f59f5fa8fe62c5aca9e27626c78c8da376ae6d8cd2dd29aebad601e1bc4c5'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='packed.RS256', L=32)

    client_data_gen_flags = h'0e'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='packed.RS256', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'ba'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'09', info='packed.RS256', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224b56395a39667150356978617970346e596d7834794e6f33617562597a5333536d75757459423462784d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d'
    signature = h'01063d52d7c39b4d432fc7063c5d93e582bdcb16889cd71f888d67d880ea730a428498d3bc8e1ee11f2b1ecbe6c292b118c55ffaaddefa8cad0a54dd137c51f1eec673f1bb6c4d1789d6826a222b22d0f585fc901fdc933212e579d199b89d672aa44891333e6a1355536025e82b25590256c3538229b55737083b2f6b9377e49e2472f11952f79fdd0da180b5ffd901b4049a8f081bb40711bef76c62aed943571f2d0575304cb549d68d8892f95086a30f93716aee818f8dc06e96c0d5e0ed4cfa9fd8773d90464b68cf140f7986666ff9c9e3302acd0535d60d769f465e2ab57ef8aabc89fccfef7ba32a64154a8b3d26be2298f470b8cc5377dbe3dfd4b0b45f8f01e63bde6cfc76b62771f9b70aa27cf40152cad93aa5acd784fd4b90f676e2ea828d0bf2400aebbaae4153e5838f537f88b6228346782a93a899be66ec77de45b3efcf311da6321c92e6b0cd11bfe653bf3e98cee8e341f02d67dbb6f9c98d9e8178090cfb5b70fbc6d541599ac794ae2f1d4de1286ec8de8c2daf7b1d15c8438e90d924df5c19045220a4c8438c1b979bbe016cf3d0eeec23c3999d4882cc645b776de930756612cdc6dd398160ff02a6'
    *)
    test_authentication
      ~challenge:
        "295f59f5fa8fe62c5aca9e27626c78c8da376ae6d8cd2dd29aebad601e1bc4c5"
      ~auth_data_UV_BS:"ba"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224b56395a39667150356978617970346e596d7834794e6f33617562597a5333536d75757459423462784d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
      ~signature:
        "01063d52d7c39b4d432fc7063c5d93e582bdcb16889cd71f888d67d880ea730a428498d3bc8e1ee11f2b1ecbe6c292b118c55ffaaddefa8cad0a54dd137c51f1eec673f1bb6c4d1789d6826a222b22d0f585fc901fdc933212e579d199b89d672aa44891333e6a1355536025e82b25590256c3538229b55737083b2f6b9377e49e2472f11952f79fdd0da180b5ffd901b4049a8f081bb40711bef76c62aed943571f2d0575304cb549d68d8892f95086a30f93716aee818f8dc06e96c0d5e0ed4cfa9fd8773d90464b68cf140f7986666ff9c9e3302acd0535d60d769f465e2ab57ef8aabc89fccfef7ba32a64154a8b3d26be2298f470b8cc5377dbe3dfd4b0b45f8f01e63bde6cfc76b62771f9b70aa27cf40152cad93aa5acd784fd4b90f676e2ea828d0bf2400aebbaae4153e5838f537f88b6228346782a93a899be66ec77de45b3efcf311da6321c92e6b0cd11bfe653bf3e98cee8e341f02d67dbb6f9c98d9e8178090cfb5b70fbc6d541599ac794ae2f1d4de1286ec8de8c2daf7b1d15c8438e90d924df5c19045220a4c8438c1b979bbe016cf3d0eeec23c3999d4882cc645b776de930756612cdc6dd398160ff02a6"
  in
  test_registration () |> test_authentication

let test_16_11 () =
  let test_registration =
    (* https://w3c.github.io/webauthn/#example-4cf7b9e9
    challenge = h'a8abf9dabdc6b0df63466b39bda9e8a34a34e185337a59f1c579990676d3b3bd'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'00', info='packed.EdDSA', L=32)

    private_key = h'971f38c0f73aaf0c5a614eb5e26430ae1ea0ed13e4f425d96e9662349340b0b3'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'01', info='packed.EdDSA', L=32)
    client_data_gen_flags = h'bd'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'02', info='packed.EdDSA', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    extraData_random = h'07f0d3e60ed90fffbd3932d85f922f11' = b64'B_DT5g7ZD_-9OTLYX5IvEQ'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'03', info='packed.EdDSA', L=16)
    aaguid = h'd5aa33581e8ca478e20fe713f5d32ff2'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'04', info='packed.EdDSA', L=16)
    credential_id = h'ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bd'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'05', info='packed.EdDSA', L=32)
    ; auth_data_UV_BE_BS determines the UV, BE and BS bits of the authenticator data flags, but BS is set only if BE is
    auth_data_UV_BE_BS = h'32'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'06', info='packed.EdDSA', L=1)
    attestation_private_key = h'fbe7f950684f23afd045072a8b287ad29528707c662672850ac69733ffe0db85'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'07', info='packed.EdDSA', L=32)
    attestation_cert_serial_number = h'b2cfc9ea33c8643b0e1a760463eaf164'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'08', info='packed.EdDSA', L=16)

    clientDataJSON = h'7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22714b763532723347734e396a526d733576616e6f6f306f303459557a656c6e7878586d5a426e6254733730222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20425f44543567375a445f2d394f544c59583549764551227d'
    attestationObject = h'a363666d74667061636b65646761747453746d74a363616c67266373696758483046022100d83f60bd80269537583218858aefb03ac57d45fa06e42feaae332d187f62da9f022100a02bd3cb6f7e1d283c93bad1f3f4b5a4c0494463da7fdbf256949116754d1f17637835638159022730820223308201c8a003020102021100b2cfc9ea33c8643b0e1a760463eaf164300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004dd2b7a564b73b8c0b81c4c62e521925c4d1198ec9f583dbf1eebe364b65cd9c29a9bdf346aaa81fb6b9507e5249a52fdaf8e39e26b0b7dc45992a7e233b70f70a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e041604140ae27546bc7eccb1b4b597bd354f0c0b1f1f8f8e301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100a0d434ecb5fc3bfd7da5f41904517ad2836249f561bd834ba7a438a8ab7a4ce8022100fac845bb7a02513b58e9f319654dbe49b0f02b95835bac568c71f8a18cdde9ab6861757468446174615881bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54100000000d5aa33581e8ca478e20fe713f5d32ff20020ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bda401010327200621582044e06ddd331c36a8dc667bab52bcae63486c916aa5e339e6acebaa84934bf832'
    *)
    test_registration
      ~challenge:
        "a8abf9dabdc6b0df63466b39bda9e8a34a34e185337a59f1c579990676d3b3bd"
      ~aaguid:"d5aa33581e8ca478e20fe713f5d32ff2"
      ~credential_id:
        "ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bd"
      ~auth_data_UV_BE_BS:"32"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22714b763532723347734e396a526d733576616e6f6f306f303459557a656c6e7878586d5a426e6254733730222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20425f44543567375a445f2d394f544c59583549764551227d"
      ~attestation_object:
        "a363666d74667061636b65646761747453746d74a363616c67266373696758483046022100d83f60bd80269537583218858aefb03ac57d45fa06e42feaae332d187f62da9f022100a02bd3cb6f7e1d283c93bad1f3f4b5a4c0494463da7fdbf256949116754d1f17637835638159022730820223308201c8a003020102021100b2cfc9ea33c8643b0e1a760463eaf164300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004dd2b7a564b73b8c0b81c4c62e521925c4d1198ec9f583dbf1eebe364b65cd9c29a9bdf346aaa81fb6b9507e5249a52fdaf8e39e26b0b7dc45992a7e233b70f70a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e041604140ae27546bc7eccb1b4b597bd354f0c0b1f1f8f8e301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d0403020349003046022100a0d434ecb5fc3bfd7da5f41904517ad2836249f561bd834ba7a438a8ab7a4ce8022100fac845bb7a02513b58e9f319654dbe49b0f02b95835bac568c71f8a18cdde9ab6861757468446174615881bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54100000000d5aa33581e8ca478e20fe713f5d32ff20020ce9f840ed96599580cd140fbc7bb3230633f50f61041aff73308ae71caa8a2bda401010327200621582044e06ddd331c36a8dc667bab52bcae63486c916aa5e339e6acebaa84934bf832"
      ~check_attestation:(fun ~attestation_type ~trust_path ->
        match (attestation_type, trust_path) with
        | Spec.Attestation_type.Uncertainty, [ _ ] -> true
        | _ -> false)
  in

  let test_authentication =
    (* https://w3c.github.io/webauthn/#example-9998063c
    challenge = h'895957e01c633a698348a2d8a31a54b7db27e8c1c43b2080d79ae2190267bfd2'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'09', info='packed.EdDSA', L=32)

    client_data_gen_flags = h'8c'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'0a', info='packed.EdDSA', L=1)
    ; extraData is added to clientDataJSON iff bit 0x01 of client_data_gen_flags is 1
    ; auth_data_UV_BS sets the UV and BS bits of the authenticator data flags, but BS is set only if BE was set in the registration
    auth_data_UV_BS = h'ab'   ; Derived by: HKDF-SHA-256(IKM='WebAuthn test vectors', salt=h'0b', info='packed.EdDSA', L=1)

    authenticatorData = h'bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000'
    clientDataJSON = h'7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2269566c583442786a4f6d6d44534b4c596f7870557439736e364d48454f7943413135726947514a6e763949222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d'
    signature = h'f5c59c7e46c34f6f8cc197101ddf9934fa2595f68eb1913a637e8419eb9ba4cfdfc48f85393bc0d40b011f0d6fecb097d6607525713223a0dc0d453993dae00b'
    *)
    test_authentication
      ~challenge:
        "895957e01c633a698348a2d8a31a54b7db27e8c1c43b2080d79ae2190267bfd2"
      ~auth_data_UV_BS:"ab"
      ~authenticator_data:
        "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000"
      ~client_data_json:
        "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2269566c583442786a4f6d6d44534b4c596f7870557439736e364d48454f7943413135726947514a6e763949222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
      ~signature:
        "f5c59c7e46c34f6f8cc197101ddf9934fa2595f68eb1913a637e8419eb9ba4cfdfc48f85393bc0d40b011f0d6fecb097d6607525713223a0dc0d453993dae00b"
  in

  test_registration () |> test_authentication

let () =
  Alcotest.(
    run "aiyu_webauthn"
      [
        ( "Test Vectors",
          [
            test_case "16.2. ES256 Credential with No Attestation" `Quick
              test_16_2;
            test_case "16.3. ES256 Credential with Self Attestation" `Quick
              test_16_3;
            test_case
              "16.4. ES256 Credential with \"crossOrigin\": true in \
               clientDataJSON"
              `Quick test_16_4;
            test_case
              "16.5. ES256 Credential with \"topOrigin\" in clientDataJSON"
              `Quick test_16_5;
            test_case "16.6. ES256 Credential with very long credential ID"
              `Quick test_16_6;
            test_case "16.7. Packed Attestation with ES256 Credential" `Quick
              test_16_7;
            test_case "16.10. Packed Attestation with RS256 Credential" `Quick
              test_16_10;
            test_case "16.11. Packed Attestation with Ed25519 Credential" `Quick
              test_16_11;
          ] );
      ])
