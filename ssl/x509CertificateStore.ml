open X509

type enriched_certificate = {
  cert_content : certificate;
  cert_decorators : (string, string) Hashtbl.t
}

type certificate_store = {
  cert_by_value : (certificate, enriched_certificate) Hashtbl.t;
  cert_by_subject : (string, enriched_certificate) Hashtbl.t;
  cert_by_issuer : (string, enriched_certificate) Hashtbl.t;
}


let new_store ?size:(size=100) () = {
  cert_by_value = Hashtbl.create size;
  cert_by_subject = Hashtbl.create size;
  cert_by_issuer = Hashtbl.create size;
}


let find_by_issuer store issuer = Hashtbl.find_all store.cert_by_issuer issuer
let find_by_subject store issuer = Hashtbl.find_all store.cert_by_issuer issuer
let is_present store cert = Hashtbl.mem store.cert_by_value cert


let add_cert store cert =
  if not (is_present store cert) then begin
    let enriched_cert = {
      cert_content = cert;
      cert_decorators = Hashtbl.create 30;
    } in
    Hashtbl.replace store.cert_by_value cert enriched_cert;
    Hashtbl.add store.cert_by_subject cert.tbsCertificate.subject_raw enriched_cert;
    Hashtbl.add store.cert_by_issuer cert.tbsCertificate.issuer_raw enriched_cert
  end;
  enriched_cert


let filter_out h cert k =
  let rec filter_out_aux () =
    try
      let c = Hashtbl.find h k in
      Hashtbl.remove h k;
      if c.cert_content <> cert then begin
	filter_out_aux ();
	Hashtbl.add h k c
      end
    with Not_found -> ()
  in filter_out_aux ()

let remove_cert store cert =
  Hashtbl.remove store.cert_by_value cert;
  filter_out store.cert_by_issuer cert cert.tbsCertificate.issuer_raw;
  filter_out store.cert_by_subject cert cert.tbsCertificate.subject_raw
