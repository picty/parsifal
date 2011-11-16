open Common
open Types
open Printer
open Modules
open ParsingEngine
open Asn1
open Asn1Constraints



(* Version *)

let extract_version l =
  match l with
    | [s] ->
      if String.length s = 1
      then int_of_char (s.[0]) + 1
      else 0
    | _ -> 0

let version_constraint : int asn1_constraint =
  Simple_cons (C_ContextSpecific, true, 0, "Version",
	       parse_sequenceof extract_version int_cons (Exactly (1, s_specfatallyviolated)))



(* Serial *)
let serial_constraint = int_cons



(* OId Objects (OId + ASN1_Object depending on the OId) *)

type oid_type =
  | HashAlgo
  | SigAlgo
  | PubKeyAlgo
  | ATV
  | Extension

let (object_directory : ((oid_type * int list),
			 (asn1_object asn1_constraint * severity)) Hashtbl.t) = Hashtbl.create 50


type oid_object = {
  oo_id : int list;
  oo_content : asn1_object option
}

let empty_oid_object = { oo_id = []; oo_content = None }


let parse_oid_object oid_type oid_sev pstate =
  let oid = constrained_parse_def oid_cons oid_sev [] pstate in
  let content_cons, content_sev =
    try Hashtbl.find object_directory (oid_type, oid)
    with Not_found -> (Anything identity), s_benign
  in
  let content = match common_constrained_parse content_cons pstate with
    | Left (TooFewObjects _) -> None
    | Left err ->
      asn1_emit err (Some content_sev) None pstate;
      (* We try to get anything if the severity was not too much *)
      constrained_parse_opt (Anything identity) s_ok pstate
    | Right o -> Some o
  in
  if not (eos pstate) then asn1_emit UnexpectedJunk (Some s_speclightlyviolated) None pstate;
  { oo_id = oid; oo_content = content }


let object_constraint oid_type oid_sev name =
  Simple_cons (C_Universal, true, 16, name, parse_oid_object oid_type oid_sev)


let string_of_oid_object title o =
  let oid_string = string_of_oid o.oo_id in
  begin
    let c = match o.oo_content with
      | None
      | Some {a_content = Null} -> [oid_string]
      | Some p -> oid_string::(string_of_object p)
    in
    PrinterLib._string_of_strlist title (only_ml (List.length c > 1)) c
  end


module OIdObjectParser = struct
  type t = oid_object
  let name = "oid_object"
  let params = []

  let parse pstate = raise NotImplemented (*constrained_parse object_constraint pstate *)

  let dump oo = raise NotImplemented

  let enrich oo dict =
    Hashtbl.replace dict "oid" (Asn1Parser.value_of_asn1_content (OId oo.oo_id));
    match oo.oo_content with
      | None -> ()
      | Some content ->
	Hashtbl.replace dict "content" (Asn1Module.register content)

  let update dict =
    let id = match Asn1Parser.asn1_content_of_value (false, hash_find dict "oid") with
      | OId l -> l
      | _ -> raise (ContentError ("oid should be an object identifier (int list)"))
    in
    let content =
      try Some (Asn1Module.pop_object (Hashtbl.find dict "content"))
      with Not_found -> None
    in
    { oo_id = id; oo_content = content }

  let to_string = string_of_oid_object (Some "Object")
end

module OIdObjectModule = MakeParserModule (OIdObjectParser)
let _ = add_module ((module OIdObjectModule : Module))



(* Signature algo *)

let sigalgo_constraint : oid_object asn1_constraint =
  object_constraint SigAlgo s_specfatallyviolated "Signature Algorithm"
