module Int = struct
  type t = int

  let compare = Int.compare

  (* decode *)
  let of_uint uint = uint
  let of_uint32 uint32 = Int32.unsigned_to_int uint32
  let of_uint64 uint64 = Int64.unsigned_to_int uint64
  let of_nint nint = -1 - nint

  let of_nint32 nint32 =
    Int32.unsigned_to_int nint32 |> Option.map (fun n -> -1 - n)

  let of_nint64 nint64 =
    Int64.unsigned_to_int nint64 |> Option.map (fun n -> -1 - n)

  (* encode *)
  let to_uint64 t = if t >= 0 then Some (Int64.of_int t) else None
  let to_nint64 t = if t < 0 then Some (Int64.of_int (-(t + 1))) else None
end

include Aiyu_cbor.Make (Int)
