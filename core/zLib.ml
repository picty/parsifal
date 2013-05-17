open Parsifal
open BasePTypes


(*********************)
(* DEFLATE Algorithm *)
(*********************)

(* RFC 1951 -- section 3.2.1 -- Huffman coding *)
type 'a huffman_tree = Leaf of 'a | Node of 'a huffman_tree * 'a huffman_tree | Nothing

let rec huffman_decode tree input =
  match tree with
  | Nothing -> raise (ParsingException (CustomException "Internal inconsistency in huffman_decode", _h_of_si input))
  | Leaf v -> v
  | Node (l, r) -> huffman_decode (if parse_rtol_bit input = 0 then l else r) input


(* RFC 1951 -- section 3.2.2 -- Building Huffman code, DEFLATE style *)
(* TODO: Add sanity checks *)
let build_tree len_array =
  let len_list = Array.to_list len_array in
  let max_bits = List.fold_left max 0 len_list in 
  (* TODO: Check max_bits for overflow! *)
  let bl_count = Array.make (max_bits + 1) 0 in
  List.iter (fun n -> bl_count.(n) <- bl_count.(n) + 1) len_list;
  bl_count.(0) <- 0;
  let next_code = Array.make (max_bits + 1) 0 in

  let rec compute_next_code code bits =
    if bits <= max_bits then begin
      let new_code = (code + bl_count.(bits - 1)) lsl 1 in
      next_code.(bits) <- new_code;
      compute_next_code new_code (bits+1)
    end
  in

  let rec bit_list_of_code accu v = function
    | 0 -> accu
    | len -> bit_list_of_code ((v land 1 = 1)::accu) (v lsr 1) (len - 1)
  in

  let rec add_leaf tree leaf bit_list =
    match tree, bit_list with
    | Nothing, [] -> Leaf leaf

    | Nothing, false::bits ->
      let subtree = add_leaf Nothing leaf bits in
      Node (subtree, Nothing)
    | Nothing, true::bits ->
      let subtree = add_leaf Nothing leaf bits in
      Node (Nothing, subtree)
    | Node (l, r), false::bits ->
      let subtree = add_leaf l leaf bits in
      Node (subtree, r)
    | Node (l, r), true::bits ->
      let subtree = add_leaf r leaf bits in
      Node (l, subtree)

    | Leaf _, _
    | _, [] -> failwith "Internal inconsistency in add_leaf" (* TODO: Better exception? *)
  in

  let rec populate_tree tree n = function
    | [] -> tree
    | 0::lens -> populate_tree tree (n+1) lens
    | len::lens ->
      let bit_list = bit_list_of_code [] next_code.(len) len in
      let new_tree = add_leaf tree n bit_list in
      next_code.(len) <- next_code.(len) + 1;
      populate_tree new_tree (n+1) lens
  in

  compute_next_code 0 1;
  populate_tree Nothing 0 len_list


(* RFC 1951 -- section 3.2.5. --  Compressed blocks (length and distance codes) *)
let length_translator =
  [| (0, 3); (0, 4); (0, 5); (0, 6); (0, 7); (0, 8); (0, 9); (0, 10);
     (1, 11); (1, 13); (1, 15); (1, 17);
     (2, 19); (2, 23); (2, 27); (2, 31);
     (3, 35); (3, 43); (3, 51); (3, 59);
     (4, 67); (4, 83); (4, 99); (4, 115);
     (5, 131); (5, 163); (5, 195); (5, 227);
     (0, 258) |]

let distance_translator =
  [| (0, 1); (0, 2); (0, 3); (0, 4);
     (1, 5); (1, 7); (2, 9); (2, 13);
     (3, 17); (3, 25); (4, 33); (4, 49);
     (5, 65); (5, 97); (6, 129); (6, 193);
     (7, 257); (7, 385); (8, 513); (8, 769);
     (9, 1025); (9, 1537); (10, 2049); (10, 3073);
     (11, 4097); (11, 6145); (12, 8193); (12, 12289);
     (13, 16385); (13, 24577) |]


(* RFC 1951 -- section 3.2.6 -- Compression with fixed Huffman codes *)
let fixed_ll_lens =
  let lens = Array.make 288 8 in
  for i = 144 to 255 do
    lens.(i) <- 9
  done;
  for i = 256 to 279 do
    lens.(i) <- 7
  done;
  lens

let fixed_dist_lens = Array.make 32 5

let fixed_huffman_codes =
  (build_tree fixed_ll_lens, build_tree fixed_dist_lens)


(* RFC 1951 -- section 3.2.7 Compression with dynamic Huffman codes *)
let code_lens_order = [| 16; 17; 18; 0; 8; 7; 9; 6; 10; 5; 11; 4; 12; 3; 13; 2; 14; 1; 15 |]

let get_lengths code_tree nlens input =
  let res = Array.make nlens 0 in
  let rec get_lengths_aux rem_lens =
    let idx = nlens - rem_lens in
    if rem_lens > 0 then begin
      match huffman_decode code_tree input, idx with
      | 16, 0 ->
        raise (ParsingException (CustomException "Internal inconsistency in get_lengths", _h_of_si input))
      | 16, _ ->
        let ntimes = 3 + (parse_rtol_bits 2 input) in
        Array.fill res idx ntimes res.(idx - 1);
        get_lengths_aux (rem_lens - ntimes)
      | 17, _ ->
        let ntimes = 3 + (parse_rtol_bits 3 input) in
        Array.fill res idx ntimes 0;
        get_lengths_aux (rem_lens - ntimes)        
      | 18, _ ->
        let ntimes = 11 + (parse_rtol_bits 7 input) in
        Array.fill res idx ntimes 0;
        get_lengths_aux (rem_lens - ntimes)
      | x, _ ->
        res.(idx) <- x;
        get_lengths_aux (rem_lens-1)
    end else res
  in get_lengths_aux nlens

let read_huffman_codes input =
  let hlit = 257 + (parse_rtol_bits 5 input) in
  let hdist = 1 + (parse_rtol_bits 5 input) in
  let hclen = 4 + (parse_rtol_bits 4 input) in
  let code_lens = Array.make 19 0 in
  for i = 0 to (hclen - 1) do
    code_lens.(code_lens_order.(i)) <- parse_rtol_bits 3 input;
  done;
  let code_tree = build_tree code_lens in
  let ll_and_dist_lens = get_lengths code_tree (hlit + hdist) input in
  let ll_lens = Array.sub ll_and_dist_lens 0 hlit
  and dist_lens = Array.sub ll_and_dist_lens hlit hdist in
  (build_tree ll_lens, build_tree dist_lens)


(* RFC 1951 -- sections 3.2.3 -- Big picture *)
let finalize_value tab index input =
  let n_extra_bits, base = tab.(index) in
  if n_extra_bits = 0
  then base
  else base + (parse_rtol_bits n_extra_bits input)

let copy_bytes buf distance length =
  (* TODO: Be more efficient!!! *)
  let initial_index = (Buffer.length buf) - distance in
  for i = 0 to length - 1 do
    Buffer.add_char buf (Buffer.nth buf (initial_index + i))
  done
  

let rec handle_compressed_block buf ll_tree distance_tree input =
  let literal_or_length = huffman_decode ll_tree input in
  if literal_or_length = 256
  then ()
  else begin
    if literal_or_length < 256
    then Buffer.add_char buf (char_of_int literal_or_length)
    else begin
      if literal_or_length > 285
      then emit_parsing_exception true (CustomException "Invalid literal/length value") input;
      let length = finalize_value length_translator (literal_or_length - 257) input in
      let raw_distance = huffman_decode distance_tree input in
      let distance = finalize_value distance_translator raw_distance input in
      copy_bytes buf distance length
    end;
    handle_compressed_block buf ll_tree distance_tree input
  end


let decompress input =
  let rec decompress_aux buf input =
    let bfinal = parse_rtol_bit input in
    let btype = parse_rtol_bits 2 input in
    begin
      match btype with
      | 0 -> (* Section 3.2.4 -- No Compression *)
        drop_remaining_bits input;
        let len = parse_uint16le input in
        let nlen = parse_uint16le input in
        if (len + nlen <> 0x10000)
        then emit_parsing_exception false (CustomException "Invalid nlen value") input;
        Buffer.add_string buf (parse_string len input)

      | 1 -> (* Compressed with fixed Huffman codes *)
        let ll_tree, distance_tree = fixed_huffman_codes in
        handle_compressed_block buf ll_tree distance_tree input

      | 2 -> (* Compressed with dynamic Huffman codes *)
        let ll_tree, distance_tree = read_huffman_codes input in
        handle_compressed_block buf ll_tree distance_tree input

      | _ -> emit_parsing_exception true (CustomException "Invalid block type value") input
    end;
    if bfinal <> 1
    then decompress_aux buf input
    else buf
  in

  let res = Buffer.create (input.cur_length) in
  decompress_aux res input



let compress_block buf s index =
  let remaining = String.length s in
  let len = min (remaining - index) 65535 in
  let nlen = 0x10000 - len in
  POutput.add_char buf '\x00';
  dump_uint16le buf len;
  dump_uint16le buf nlen;
  POutput.add_substring buf s index len;
  index + len

let compress buf s =
  let len = String.length s in
  let rec mk_next_block index =
    if index < len
    then begin
      let new_index = compress_block buf s index in
      mk_next_block new_index
    end
  in
  mk_next_block 0



(***********************************)
(* RFC 1951: raw DEFLATE container *)
(***********************************)

type 'a deflate_container = 'a

let parse_deflate_container parse_fun input =
  let content_buf = decompress input in
  drop_remaining_bits input;
  let new_input = get_in_container input "deflate_container" (Buffer.contents content_buf) in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_deflate_container dump_fun buf o =
  let tmp_buf = POutput.create () in
  dump_fun tmp_buf o;
  compress buf (POutput.contents tmp_buf)

let value_of_deflate_container = value_of_container



(*************************)
(* RFC 1950: zLib stream *)
(*************************)

(* TODO: add a rtol option to enum *)
(* enum zlib_compression_method (4, UnknownVal UnknownCompressionMethod) =
|  8 -> CM_Deflate
| 15 -> CM_Reserved *)

(* TODO: Check these values and implement RFC 1950? *)
struct zlib_stream = {
  compression_method : rtol_bit_int(4); (* TODO: this should use the previous enum *)
  compression_info : rtol_bit_int(4);   (* TODO: this should depend on compression_method *)
  fcheck : rtol_bit_int(5);
  fdict : rtol_bit_bool;
  flevel : rtol_bit_int(2);
  (* if fdict is set, dict : uint32; *) (* TODO *)
  zlib_data : deflate_container of binstring;
  adler32_checksum : uint32;            (* TODO *)
}

type 'a zlib_container = 'a

let parse_zlib_container parse_fun input =
  let stream = parse_zlib_stream input in
  let new_input = get_in_container input "zlib_container" stream.zlib_data in
  let res = parse_fun new_input in
  check_empty_input true new_input;
  res

let dump_zlib_container dump_fun buf o =
  let stream = {
    compression_method = 8;
    compression_info = 7;
    fcheck = 0;           (* TODO: Implement RFC 1950 *)
    fdict = false;
    flevel = 0;
    zlib_data = exact_dump dump_fun o;
    adler32_checksum = 0; (* TODO: Implement RFC 1950 *)
  } in
  dump_zlib_stream buf stream

let value_of_zlib_container = value_of_container
