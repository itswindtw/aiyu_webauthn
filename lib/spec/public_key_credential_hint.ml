type t = Security_key | Client_device | Hybrid

let to_json = function
  | Security_key -> `String "security-key"
  | Client_device -> `String "client-device"
  | Hybrid -> `String "hybrid"
