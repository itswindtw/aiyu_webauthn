type t = int

let of_json json = json |> Json.Parse.to_int
