type t = Required | Preferred | Discouraged

let to_json = function
  | Required -> `String "required"
  | Preferred -> `String "preferred"
  | Discouraged -> `String "discouraged"
