type t = None | Indirect | Direct | Enterprise

let to_json = function
  | None -> `String "none"
  | Indirect -> `String "indirect"
  | Direct -> `String "direct"
  | Enterprise -> `String "enterprise"
