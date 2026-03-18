type t = { name : string; id : string option }

let to_json t =
  Json.option_obj
    [
      ("name", Some (`String t.name));
      ("id", Option.map (fun s -> `String s) t.id);
    ]
