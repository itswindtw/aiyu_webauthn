type t = {
  rp_id_hash : string;
  flags : Flags.t;
  sign_count : Int32.t;
  attested_credential_data : Attestation_credential_data.t option;
  extensions : Cbor.t option;
}

let of_string s =
  let open Result.Syntax in
  let rp_id_hash = String.sub s 0 32 in
  let flags = String.get_uint8 s 32 |> Flags.of_byte in
  let sign_count = String.get_int32_be s 33 in
  let rest = String.sub s 37 (String.length s - 37) in
  let* attested_credential_data, rest =
    if flags.attested_credential_data_included then begin
      let aaguid = String.sub rest 0 16 in
      let credential_id_length = String.get_uint16_be rest 16 in
      let credential_id = String.sub rest 18 credential_id_length in
      let* credential_public_key, rest =
        let pos = 18 + credential_id_length in
        let sub = String.sub rest pos (String.length rest - pos) in
        Cbor.decode_item sub
      in
      let* credential_public_key = Cose_key.of_cbor credential_public_key in
      Ok
        ( Some
            Attestation_credential_data.
              {
                aaguid;
                credential_id_length;
                credential_id;
                credential_public_key;
              },
          rest )
    end
    else Ok (None, rest)
  in
  let* extensions =
    if flags.extension_data_included then
      let* cbor = Cbor.decode rest in
      Ok (Some cbor)
    else Ok None
  in
  Ok { rp_id_hash; flags; sign_count; attested_credential_data; extensions }
