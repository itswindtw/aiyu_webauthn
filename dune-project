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
    aiyu_cbor
    hex
    (alcotest :with-test)))

(pin
  (url "git+https://github.com/itswindtw/aiyu_cbor")
  (package
    (name aiyu_cbor)))
