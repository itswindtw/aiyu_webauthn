type t = { name : string; id : string; display_name : string }

let to_json t =
  Json.obj
    [
      ("name", `String t.name);
      ("id", t.id |> Base64_url_string.of_raw |> Base64_url_string.to_json);
      ("displayName", `String t.display_name);
    ]
