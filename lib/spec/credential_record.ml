type t = {
  type_ : string;
  id : string;
  public_key : Cose_key.t;
  sign_count : Int32.t;
  uv_initialized : bool;
  transports : string list;
  backup_eligible : bool;
  backup_state : bool;
  attestation_object : string;
  attestation_client_data_json : string;
  rp_id : string;
  aaguid : string;
}
