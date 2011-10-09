let extract_class (x : int) : asn1_class =
  let i = x lsr 6 in
  class_map.(i)

let extract_isConstructed (x : int) : bool =
  let i = (x lsr 5) land 1 in
  i = 1

let extract_shorttype (x : int) : int =
  x land 31

let extract_longtype (pstate : parsing_state) : (int * parsing_state) =
  (* str is the complete string, with one char to skip *)
  raise NotImplemented ("Long type", pstate)

let extract_header (pstate : parsing_state) : ((asn1_class * bool * int) * parsing_state) =
  let hdr = cur_byte pstate in
  let c = extract_class hdr in
  let isC = extract_isConstructed hdr in
  let t = extract_shorttype hdr in
  if (t < 0x1f)
  then ((c, isC, t), eat_bytes pstate 1
  else
    let (longT, new_pstate) = extract_longtype pstate in
    ((c, isC, longT), new_pstate)

let extract_length (pstate : parsing_state) : parsing_state =
  let first = cur_byte pstate in
  if first land 0x80 = 0
  then pstate with {offset = pstate.offset + 1; len = first}
  else
    let lenlen = first land 0x7f in
    let rec aux accu offset = function
      | 0 -> (accu, offset)
      | n -> aux ((accu lsl 8) lor (int_of_char (String.get str offset))) (offset + 1) (n-1)
    in (aux 0 (offset + 1) lenlen)
