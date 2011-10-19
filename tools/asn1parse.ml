open Asn1;;
open Asn1.Asn1EngineParams
open Asn1.Engine
open Asn1Constraints;;
open X509Directory;;

(* display type *)

type display_type =
  | ASN1
  | ASN1PARSE
  | X509

let dtype = ref ASN1


(* General options *)

let type_repr = ref PrettyType
let data_repr = ref PrettyData
let resolver = ref (Some (X509.name_directory))
let indent = ref true

let tolerance = ref s_specfatallyviolated
let minDisplay = ref s_ok
let files = ref []


(* ASN1PARSE *)

let print_depth = ref true
let print_offset = ref true
let print_headerlen = ref true
let print_len = ref true



let assign r v = Arg.Unit (fun () -> r:=v)

let update_sev r arg =
  let v = match String.lowercase arg with
    | "ok" | "0" -> s_ok
    | "benign" | "1" -> s_benign
    | "idempotence" | "2" -> s_idempotencebreaker
    | "speclightly" | "3" -> s_speclightlyviolated
    | "spcefatally" | "4" -> s_specfatallyviolated
    | _ -> raise (Arg.Bad "Invalid severity (should be one of OK, Benign, Idempotence, SpecLightly, SpecFatally)")
  in r := v

let set_dtype arg =
  let v = match String.lowercase arg with
    | "asn1" -> ASN1
    | "asn1parse" -> ASN1PARSE
    | "x509" -> X509
    | _ -> raise (Arg.Bad "Invalid display (should be one of asn1, asn1parse, x509)")
  in dtype := v

let options = [
  (* display type *)
  ("-display", Arg.String set_dtype, "Set display type (asn1, asn1parse or x509)");

  (* General options *)
  ("-tolerance", Arg.String (update_sev tolerance), "Adjust the maximum severity acceptable while parsing");
  ("-minDisplay", Arg.String (update_sev minDisplay), "Adjust the minimum severity to be displayed");

  ("-notype", assign type_repr NoType, "Do not print types");
  ("-rawtype", assign type_repr RawType, "Print raw types");
  ("-prettytype", assign type_repr PrettyType, "Print pretty types");
  ("-namedtype", assign type_repr NamedType, "Print types using the name given by the spec");

  ("-nodata", assign data_repr NoData, "Do not print data");
  ("-rawdata", assign data_repr RawData, "Print raw data");
  ("-prettydata", assign data_repr PrettyData, "Print pretty data");

  ("-indent", Arg.Set indent, "Display ASN.1 dump with indentation");
  ("-noindent", Arg.Clear indent, "Display ASN.1 dump without indentation");

  (* ASN1PARSE *)
  ("-depth", Arg.Set print_depth, "Print depth column in asn1parse");  
  ("-nodepth", Arg.Clear print_depth, "Print depth column in asn1parse");  
  ("-offset", Arg.Set print_offset, "Print offset column in asn1parse");  
  ("-nooffset", Arg.Clear print_offset, "Print offset column in asn1parse");  
  ("-headerlen", Arg.Set print_headerlen, "Print header len column in asn1parse");  
  ("-noheaderlen", Arg.Clear print_headerlen, "Print header len column in asn1parse");  
  ("-len", Arg.Set print_len, "Print len column in asn1parse");  
  ("-nolen", Arg.Clear print_len, "Print len column in asn1parse");  
];;

let add_input s = files := s::(!files) in
Arg.parse options add_input "asn1parse [options]";;


let opts = { type_repr = !type_repr; data_repr = !data_repr; resolver = !resolver; indent_output = !indent }
let ehf = default_error_handling_function !tolerance !minDisplay
let inputs = match !files with
  | [] -> [pstate_of_channel ehf "(stdin)" stdin]
  | _ -> List.map (fun s -> pstate_of_channel ehf s (open_in s)) !files;;



(* ASN1 *)
let parse_input pstate =
  while not (eos pstate) do
    let o = parse pstate in
    output_string stdout (string_of_object "" opts o)
  done


(* ASN1PARSE *)
let string_of_header_asn1parse depth c isC t = 
  let supertag = match c with
    | C_Universal ->
      if t >= 0 && t < (Array.length universal_tag_map)
      then universal_tag_map.(t)
      else T_Unknown
    | _ -> T_Unknown
  in

  let res = match supertag with
    | T_EndOfContents ->    "EOC               "
    | T_Boolean ->          "BOOLEAN           "
    | T_Integer ->          "INTEGER           "
    | T_BitString ->        "BIT STRING        "
    | T_OctetString ->      "OCTET STRING      "
    | T_Null ->             "NULL              "
    | T_OId ->              "OBJECT            "
    | T_ObjectDescriptor -> "OBJECT DESCRIPTOR "
    | T_External ->         "EXTERNAL          "
    | T_Real ->             "REAL              "
    | T_Enumerated ->       "ENUMERATED        "
    | T_UTF8String ->       "UTF8STRING        "
    | T_Sequence ->         "SEQUENCE          "
    | T_Set ->              "SET               "
    | T_NumericString ->    "NUMERICSTRING     "
    | T_PrintableString ->  "PRINTABLESTRING   "
    | T_T61String ->        "T61STRING         "
    | T_VideoString ->      "VIDEOTEXSTRING    "
    | T_IA5String ->        "IA5STRING         "
    | T_UTCTime ->          "UTCTIME           "
    | T_GeneralizedTime ->  "GENERALIZEDTIME   "
    | T_GraphicString ->    "GRAPHICSTRING     "
    | T_VisibleString ->    "VISIBLESTRING     "
    | T_GeneralString ->    "GENERALSTRING     "
    | T_UniversalString ->  "UNIVERSALSTRING   "
    | T_BMPString ->        "BMPSTRING         "
    | _ -> begin
      match c with
	| C_Universal ->       "<ASN1 " ^ (string_of_int t) ^ ">          "
	| C_Private ->         "priv [ " ^ (string_of_int t) ^ " ]        "
	| C_Application ->     "appl [ " ^ (string_of_int t) ^ " ]        "
	| C_ContextSpecific -> "cont [ " ^ (string_of_int t) ^ " ]        "
    end
  in
  (if isC then "cons: " else "prim: ") ^
    (if !indent then String.make (depth * 2) ' ' else "") ^
    res


let content_string content =
  let v = match !data_repr, content with
    | _, Constructed _
    | NoData, _
    | _, EndOfContents
    | _, Null -> None

    | _, Boolean true -> Some "0"
    | _, Boolean false -> Some "255"

    (* TODO: I would like it to be in hexa *)
    | _, Integer i -> Some (Common.hexdump_int_list i)

    | _, BitString (nBits, s) -> Some (string_of_bitstring (!data_repr = RawData) nBits s)
    | _, OId oid -> Some (string_of_oid !resolver oid)

    | RawData, String (s, _)
    | _, String (s, true)
    | _, Unknown s -> Some ("[HEX DUMP]:" ^ (Common.hexdump s))
    | _, String (s, _) -> Some (s)
  in
  match v with
    | None -> ""
    | Some value -> ":" ^ value


let rec asn1parse_input depth pstate =
  while not (eos pstate) do
    let offset = get_offset pstate in
    let (c, isC, t) = extract_header pstate in
    extract_length pstate (string_of_header_pretty c isC t);
    let hl = (get_offset pstate) - offset in
    let len = get_len pstate in

    if !print_offset
    then Printf.printf "%5d:" offset;

    if !print_depth
    then Printf.printf "d=%d  " depth;

    if !print_headerlen
    then Printf.printf "hl=%d " hl;

    if !print_len
    then Printf.printf "l=%4d " len;

    if !type_repr <> NoType
    then print_string (string_of_header_asn1parse depth c isC t);

    if isC then begin
      print_newline ();
      asn1parse_input (depth + 1) pstate
    end else begin
      if c = C_Universal && t >= 0 &&
	t < Array.length universal_tag_map &&
	universal_tag_map.(t) <> T_Unknown
      then
	let parse_fun = choose_parse_fun pstate c isC t in
	let o = parse_fun pstate in
	Printf.printf "%s\n" (content_string o)
      else
	print_newline ();
    end;

    if not (eos pstate) then begin
      emit UnexpectedJunk s_idempotencebreaker pstate;
      ignore (pop_string pstate)
    end;

    go_up pstate
  done;;


(* X509 *)
let parse_and_validate_cert cons pstate =
  while not (eos pstate) do
    let o = constrained_parse cons pstate in
    print_endline (X509.string_of_certificate true "" !resolver o)
  done;;


try
  begin
    match !dtype with
      | ASN1 -> List.iter parse_input inputs
      | ASN1PARSE -> List.iter (asn1parse_input 0) inputs
      | X509 -> List.iter (parse_and_validate_cert (X509.certificate_constraint X509.object_directory)) inputs
  end
with
  | ParsingError (err, sev, pstate) ->
    output_string stderr ("Fatal (" ^ (string_of_exception err sev pstate) ^ "\n");;
