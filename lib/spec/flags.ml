type t = {
  user_present : bool;
  user_verified : bool;
  backup_eligibility : bool;
  backup_state : bool;
  attested_credential_data_included : bool;
  extension_data_included : bool;
}
[@@deriving show]

let of_byte b =
  {
    user_present = b land 0x01 <> 0;
    user_verified = b land 0x04 <> 0;
    backup_eligibility = b land 0x08 <> 0;
    backup_state = b land 0x10 <> 0;
    attested_credential_data_included = b land 0x40 <> 0;
    extension_data_included = b land 0x80 <> 0;
  }
