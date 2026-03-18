type t = Platform | Cross_platform

let to_json = function
  | Platform -> `String "platform"
  | Cross_platform -> `String "cross-platform"
