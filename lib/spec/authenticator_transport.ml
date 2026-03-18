type t = Usb | Nfc | Ble | Smart_card | Hybrid | Internal

let to_json = function
  | Usb -> `String "usb"
  | Nfc -> `String "nfc"
  | Ble -> `String "ble"
  | Smart_card -> `String "smart-card"
  | Hybrid -> `String "hybrid"
  | Internal -> `String "internal"
