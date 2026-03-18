(lang dune 3.21)
(name aiyu_webauthn)
(package
  (name aiyu_webauthn)
  (depends
    ocaml
    yojson
    base64
    digestif
    mirage-crypto-rng
    x509
    cbor
    hex
    (alcotest :with-test)))
