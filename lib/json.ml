module M = Yojson.Basic

type t = M.t

let string s = `String s
let int i = `Int i
let obj fields = `Assoc fields

let option_obj fields =
  `Assoc (List.filter_map (fun (k, v) -> Option.map (fun v -> (k, v)) v) fields)

let from_string = M.from_string
let to_string = M.to_string
let pp = M.pp
let equal = M.equal

module Parse = M.Util
