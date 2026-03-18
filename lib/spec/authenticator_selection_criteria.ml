type t = {
  authenticator_attachment : Authenticator_attachment.t option;
  resident_key : Resident_key_requirement.t option;
  user_verification : User_verification_requirement.t option;
}

let to_json t =
  Json.option_obj
    [
      ( "authenticatorAttachment",
        Option.map Authenticator_attachment.to_json t.authenticator_attachment
      );
      ("residentKey", Option.map Resident_key_requirement.to_json t.resident_key);
      ( "requireResidentKey",
        Option.bind t.resident_key (function
          | Resident_key_requirement.Required -> Some (`Bool true)
          | _ -> None) );
      ( "userVerification",
        Option.map User_verification_requirement.to_json t.user_verification );
    ]
