type t = Discouraged | Preferred | Required

let to_json = function
  | Discouraged -> `String "discouraged"
  | Preferred -> `String "preferred"
  | Required -> `String "required"
