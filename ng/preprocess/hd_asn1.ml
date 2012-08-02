type expected_header_string = string option

type field_type =
  | AT_Boolean
  | AT_SmallInteger
  | AT_Integer
  | AT_BitString
  (*  TODO: AT_EnumeratedBitString *)
  | AT_Null
  | AT_OId
  (* AT_String (constraints : None -> no_constraint, Some s -> $s_constraint) *)
  | AT_String of string option
  | AT_Primitive
  | AT_Container of expected_header_string * field_type
  (* AT_SequenceOf (name of the sequence [default is proposed_name_list], min, max, sub_type, sub_header) *)
  | AT_SequenceOf of string option * int option * int option * expected_header_string * field_type
  | AT_SetOf of string option * int option * int option * expected_header_string * field_type

  | AT_Custom of string option * string
  | AT_Anything

type asn1_option =
  | AO_EnrichRawString
  | AO_EnrichASN1Info
  | AO_TopLevel

(* TODO: Add constraints
    - optional fields SHOULDs and SHOULDNOTs *)


type field_desc = {
  field_name : string;
  field_type : field_type;
  field_optional : bool;
  field_expected_header : string option;
}

type description = {
  name : string;
  fields : field_desc list;
  expected_header : string option;
  options : asn1_option list;
}


let mkf ?opt:(o=false) ?hdr:(h=None) n t = {
  field_name = n;
  field_type = t;
  field_optional = o;
  field_expected_header = h;
}

let mkd ?options:(o=[]) ?hdr:(h=None) n f = {
  name = n;
  fields = f;
  expected_header = h;
  options = o;
}
