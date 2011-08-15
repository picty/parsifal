open Asn1
open X509

let bundle_to_certs f =
  let read_string () =
    let l = input_binary_int f in
    let s = String.create l in
    really_input f s 0 l;
    s
  in
  let rec aux () =
    try
      let name = read_string () in
      let cert = string_to_certificate (read_string ()) in
      (name, cert)::(aux ())
    with _ -> []
  in aux ()

let f = open_in "bundle"
let certs = bundle_to_certs f


