open Common
open Types
open Modules
open Asn1

exception MessageTooLong
exception InvalidBlockType
exception PaddingError
exception InvalidSignature


(* TODO: Define a private key / public key type? *)

let hash_funs = [
  "md5", [42;840;113549;2;5], Crypto.md5sum;
  "sha1", [43;14;3;2;26], Crypto.sha1sum;
  "sha256", [96;840;1;101;3;4;2;1], Crypto.sha256sum;
  "sha384", [96;840;1;101;3;4;2;2], Crypto.sha384sum;
  "sha512", [96;840;1;101;3;4;2;3], Crypto.sha512sum;
  "sha224", [96;840;1;101;3;4;2;4], Crypto.sha224sum;
]

let get_hash_fun_by_name n =
  let rec aux = function
    | [] -> raise (NotFound ("Unknown hash function " ^ n))
    | (name, oid, f)::r ->
      if n = name
      then oid, f
      else aux r
  in aux hash_funs

let get_hash_fun_by_oid id =
  let rec aux = function
    | [] -> raise (NotFound ("Unknown hash function oid " ^ (raw_string_of_oid id)))
    | (_, oid, f)::r ->
      if oid = id
      then f
      else aux r
  in aux hash_funs

let _ =
  let register_hash_fun (name, oid, _) = register_oid oid name in
  List.map register_hash_fun hash_funs



let find_not_null s i =
  let s_len = String.length s in
  let rec aux i =
    if i = s_len || s.[i] != '\x00'
    then i
    else aux (i+1)
  in aux i

let normalize_modulus n =
  let n_len = String.length n in
  let to_drop = find_not_null n 0 in
  let new_len = n_len - to_drop in
  String.sub n to_drop new_len

let format_encryption_block block_type padding_len d =
  let padding = match block_type with
    | 0 -> String.make padding_len '\x00'
    | 1 -> String.make padding_len '\xff'
    | 2 -> Random.random_string Random.RandomLib.state padding_len
    | _ -> raise InvalidBlockType
  in
  let tmp1 = String.make 1 '\x00' in
  let tmp2 = String.make 1 (char_of_int block_type) in
  tmp1 ^ tmp2 ^ padding ^ tmp1 ^ d


let encrypt block_type d n c =
  let normalized_n = normalize_modulus n in
  let k = String.length normalized_n in
  let d_len = String.length d in
  if d_len > k - 11
  then raise MessageTooLong;
  let encryption_block = format_encryption_block block_type (k - d_len - 3) d in
  Crypto.exp_mod encryption_block c normalized_n


(* TODO: block_type should be optional *)

let decrypt block_type expected_len ed n c =
  let normalized_n = normalize_modulus n in
  let encryption_block = Crypto.exp_mod ed c normalized_n in
  let res = ref true in

  if encryption_block.[0] != '\x00'
  or encryption_block.[1] != (char_of_int block_type)
  then res := false;

  let block_len = String.length encryption_block in
  let d_start =
    try
      match block_type with
	| 1
	| 2 -> begin
	  let tmp = String.index_from encryption_block 2 '\x00' in
	  if tmp < 10 then raise Not_found;
	  let l = block_len - tmp - 1 in
	  match expected_len with
	    | None -> tmp + 1
	    | Some len ->
	      if len = l
	      then tmp + 1
	      else raise Not_found
	end
	| 0 -> begin
	  let first_non_null = find_not_null encryption_block 2 in
	  match expected_len with
	    | None -> first_non_null
	    | Some len ->
	      if len < block_len - first_non_null
	      then raise Not_found;
	      block_len - len
	end
	| _ -> raise Not_found
    with Not_found ->
      res := false;
      0
  in
  if !res
  then String.sub encryption_block d_start (block_len - d_start)
  else raise PaddingError


let raw_sign typ hash msg n d =
  let oid, f = get_hash_fun_by_name hash in
  let digest = f msg in
  Printf.printf "%s -> %s\n" msg (hexdump digest);
  (* TODO: This is rather ugly. Could it be a little cleaner *)
  let asn1_struct = mk_object' "DigestInfo" C_Universal 16
    (Constructed [mk_object' "DigestAlgorithmIdentifier" C_Universal 16
		     (Constructed [mk_object' hash C_Universal 6 (OId oid);
				   mk_object' "Parameter" C_Universal 5 Null]);
		  mk_object' "Digest" C_Universal 4 (String (digest, true))])
  in
  encrypt typ (dump asn1_struct) n d

let raw_verify typ msg s n e =
  try
    let digest_info = decrypt typ None s n e in
    let pstate = ParsingEngine.pstate_of_string (Some "DigestInfo") digest_info in
    let asn1_obj = parse pstate in
  (* TODO: This is rather ugly. Could it be a little cleaner *)
    match asn1_obj with
      | {a_class = C_Universal; a_tag = 16; a_content = Constructed
	[{a_class = C_Universal; a_tag = 16; a_content = Constructed
	    [{a_class = C_Universal; a_tag = 6; a_content = OId oid};
	     {a_class = C_Universal; a_tag = 5; a_content = Null}]};
	 {a_class = C_Universal; a_tag = 4; a_content = String (digest, _)}]}
      | {a_class = C_Universal; a_tag = 16; a_content = Constructed
	  [{a_class = C_Universal; a_tag = 16; a_content = Constructed
	    [{a_class = C_Universal; a_tag = 6; a_content = OId oid}]};
	   {a_class = C_Universal; a_tag = 4; a_content = String (digest, _)}]} ->
	let f = get_hash_fun_by_oid oid in
	f msg = digest
      | _ -> false
  with
    | Not_found _ | ParsingEngine.ParsingError _ | ParsingEngine.OutOfBounds _ -> false



module Pkcs1Lib = struct
  let name = "pkcs1"
  let params = []

  let pkcs1_encrypt typ d n c =
    V_BinaryString (encrypt (eval_as_int typ) (eval_as_string d) (eval_as_string n) (eval_as_string c))

  let pkcs1_decrypt typ d n c =
    V_BinaryString (decrypt (eval_as_int typ) None (eval_as_string d) (eval_as_string n) (eval_as_string c))

  let pkcs1_raw_sign typ h m n d =
    V_BinaryString (raw_sign (eval_as_int typ) (eval_as_string h) (eval_as_string m) (eval_as_string n) (eval_as_string d))

  let pkcs1_raw_verify typ m s n d =
    V_Bool (raw_verify (eval_as_int typ) (eval_as_string m) (eval_as_string s) (eval_as_string n) (eval_as_string d))

  (* TODO: This still sucks... We need a key type to encapsulate n+d or n+e *)
  let pkcs1_sign h m n d =
    V_BinaryString (raw_sign 1 (eval_as_string h) (eval_as_string m) (eval_as_string n) (eval_as_string d))

  let pkcs1_verify m s n d =
    V_Bool (raw_verify 1 (eval_as_string m) (eval_as_string s) (eval_as_string n) (eval_as_string d))

  let functions = [
    "encrypt", NativeFun (four_value_fun pkcs1_encrypt);
    "decrypt", NativeFun (four_value_fun pkcs1_decrypt);
    "raw_sign", NativeFun (five_value_fun pkcs1_raw_sign);
    "raw_verify", NativeFun (five_value_fun pkcs1_raw_verify);
    "sign", NativeFun (four_value_fun pkcs1_sign);
    "verify", NativeFun (four_value_fun pkcs1_verify);
  ]
end

module Pkcs1Module = MakeLibraryModule (Pkcs1Lib)
let _ = add_library_module ((module Pkcs1Module : Module))
