type t = {
  type_ : string;
  challenge : string;
  origin : string;
  cross_origin : bool option;
  top_origin : string option;
}

let of_json json =
  let open Json.Parse in
  try
    let type_ = json |> member "type" |> to_string in
    let challenge = json |> member "challenge" |> to_string in
    let origin = json |> member "origin" |> to_string in
    let cross_origin = json |> member "crossOrigin" |> to_bool_option in
    let top_origin = json |> member "topOrigin" |> to_string_option in
    Ok { type_; challenge; origin; cross_origin; top_origin }
  with Type_error (msg, _) -> Error msg
