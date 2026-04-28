(lang dune 3.21)

(name lokto_webauthn)

(generate_opam_files true)

(package
  (name lokto_webauthn)
  (depends
    ocaml
    yojson
    base64
    digestif
    mirage-crypto-rng
    x509
    lokto_cbor
    (hex :with-test)
    (alcotest :with-test)
    (ocaml-lsp-server :with-dev-setup)
    (ocamlformat :with-dev-setup)))

(pin
  (url "git+https://github.com/itswindtw/lokto_cbor")
  (package
    (name lokto_cbor)))
