type t = {
  type_ : Public_key_credential_type.t;
  alg : Cose_algorithm_identifier.t;
}

let to_json t =
  `Assoc
    [
      ("type", Public_key_credential_type.to_json t.type_); ("alg", `Int t.alg);
    ]
