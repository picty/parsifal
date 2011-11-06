open Asn1;;

let i = { a_class = C_Universal; a_tag = 2; a_content = Integer "\x05"; a_name = "Integer"; a_ohl = None };;
let s = { a_class = C_Universal; a_tag = 4; a_content = String ("titi", true); a_name = "Str"; a_ohl = None };;
let s2 = { a_class = C_Universal; a_tag = 19; a_content = String ("234", false); a_name = "Str"; a_ohl = None };;

let opts = { type_repr = PrettyType; data_repr = PrettyData; indent_output = true };;
let opts2 = { type_repr = PrettyType; data_repr = RawData; indent_output = false };;

let c = {a_class = C_Universal; a_tag = 16; a_content = Constructed [i; s; s2]; a_name = "Seq"; a_ohl = None };;

print_string (string_of_object "   " opts c);;

print_string (string_of_object "" opts2 c);;
print_char '\n';;
