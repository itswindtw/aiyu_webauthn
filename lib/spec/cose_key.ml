let supported_algs = [ (* Ed25519 *) -8; (* ES256 *) -7; (* RS256 *) -257 ]

type key =
  | OKP of { crv : int; x : string }
  | EC2 of { crv : int; x : string; y : string }
  | RSA of { n : string; e : string }

type t = { alg : int; key : key }

(* https://datatracker.ietf.org/doc/html/rfc9053#name-key-object-parameters *)
(* https://datatracker.ietf.org/doc/html/rfc8230/#section-4 *)
let of_cbor cbor =
  let open Result.Syntax in
  let* kv =
    match cbor with Cbor.Map kv -> Ok kv | _ -> Error "Cose_key is not a map"
  in
  let* kty =
    match List.assoc_opt (Cbor.Integer 1) kv with
    | Some (Integer kty) -> Ok kty
    | None -> Error "kty is missing"
    | Some _ -> Error "kty is not an integer"
  in
  let* alg =
    match List.assoc_opt (Cbor.Integer 3) kv with
    | Some (Integer alg) -> Ok alg
    | None -> Error "alg is missing"
    | Some _ -> Error "alg is not an integer"
  in
  match (alg, kty) with
  | -8, 1 ->
      let* crv =
        match List.assoc_opt (Cbor.Integer (-1)) kv with
        | Some (Integer crv) -> Ok crv
        | None -> Error "crv is missing"
        | Some _ -> Error "crv is not an integer"
      in
      let* x =
        match List.assoc_opt (Cbor.Integer (-2)) kv with
        | Some (Cbor.Byte_string crv) -> Ok crv
        | None -> Error "x is missing"
        | Some _ -> Error "x is not bytes"
      in
      Ok { alg; key = OKP { crv; x } }
  | -7, 2 ->
      let* crv =
        match List.assoc_opt (Cbor.Integer (-1)) kv with
        | Some (Integer crv) -> Ok crv
        | None -> Error "crv is missing"
        | Some _ -> Error "crv is not an integer"
      in
      let* x =
        match List.assoc_opt (Cbor.Integer (-2)) kv with
        | Some (Byte_string x) -> Ok x
        | None -> Error "x is missing"
        | Some _ -> Error "x is not bytes"
      in
      let* y =
        match List.assoc_opt (Cbor.Integer (-3)) kv with
        | Some (Byte_string y) -> Ok y
        | None -> Error "y is missing"
        | Some _ -> Error "y is not bytes"
      in
      Ok { alg; key = EC2 { crv; x; y } }
  | -257, 3 ->
      let* n =
        match List.assoc_opt (Cbor.Integer (-1)) kv with
        | Some (Byte_string n) -> Ok n
        | None -> Error "n is missing"
        | Some _ -> Error "n is not bytes"
      in
      let* e =
        match List.assoc_opt (Cbor.Integer (-2)) kv with
        | Some (Byte_string e) -> Ok e
        | None -> Error "e is missing"
        | Some _ -> Error "e is not bytes"
      in
      Ok { alg; key = RSA { n; e } }
  | _ -> Error "Unrecognized alg, kty pair"

let to_x509_public_key t =
  match t.key with
  | EC2 { crv; x; y } ->
      "\x04" ^ x ^ y
      |> Mirage_crypto_ec.P256.Dsa.pub_of_octets
      |> Result.map (fun x -> `P256 x)
      |> Result.map_error (fun e ->
          Format.asprintf "%a" Mirage_crypto_ec.pp_error e)
  | OKP { crv; x } ->
      x |> Mirage_crypto_ec.Ed25519.pub_of_octets
      |> Result.map (fun x -> `ED25519 x)
      |> Result.map_error (fun e ->
          Format.asprintf "%a" Mirage_crypto_ec.pp_error e)
  | RSA { n; e } ->
      let n = Mirage_crypto_pk.Z_extra.of_octets_be n in
      let e = Mirage_crypto_pk.Z_extra.of_octets_be e in
      Mirage_crypto_pk.Rsa.pub ~n ~e
      |> Result.map (fun x -> `RSA x)
      |> Result.map_error (fun (`Msg m) -> m)
