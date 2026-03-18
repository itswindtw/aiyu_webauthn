type t = { fmt : string; att_stmt : CBOR.Simple.t; auth_data : string }

let of_cbor string =
  let open Result.Syntax in
  match CBOR.Simple.decode string with
  | `Map kv ->
      let* fmt =
        match List.assoc_opt (`Text "fmt") kv with
        | None -> Error "fmt is missing"
        | Some (`Text fmt) -> Ok fmt
        | Some _ -> Error "fmt is not a string"
      in
      let* att_stmt =
        match List.assoc_opt (`Text "attStmt") kv with
        | None -> Error "attStmt is missing"
        | Some att_stmt -> Ok att_stmt
      in
      let* auth_data =
        match List.assoc_opt (`Text "authData") kv with
        | None -> Error "authData is missing"
        | Some (`Bytes raw) -> Ok raw
        | Some _ -> Error "authData is not bytes"
      in
      Ok { fmt; att_stmt; auth_data }
  | _ -> Error "Unrecognized attestation object"
