type t = {
  buffer : Buffer.t;
  mutable cur_byte : int;
  mutable cur_freebits : int;
}


let default_buffer_size = ref 1024

let create () = {
  buffer = Buffer.create !default_buffer_size;
  cur_byte = 0;
  cur_freebits = 8;
}


let clean_slate buf =
  if buf.cur_freebits <> 8 then begin
    let new_byte = buf.cur_byte lsl buf.cur_freebits in
    Buffer.add_char buf.buffer (char_of_int new_byte);
    buf.cur_byte <- 0;
    buf.cur_freebits <- 8
  end


let contents buf =
  clean_slate buf;
  Buffer.contents buf.buffer

let length buf =
  clean_slate buf;
  Buffer.length buf.buffer

let byte_at buf n = int_of_char (Buffer.nth buf.buffer n)


let bits_masks = [|0; 1; 3; 7; 15; 31; 63; 127; 255|]

let add_bits buf nbits value =
  let rec add_bits_aux buf nbits cur_byte cur_freebits value =
    match nbits, cur_freebits with
    | _, 0 ->
      Buffer.add_char buf.buffer (char_of_int cur_byte);   
      add_bits_aux buf nbits 0 8 value
    | 0, _ ->
      buf.cur_byte <- cur_byte;
      buf.cur_freebits <- cur_freebits
    | _, _ ->
      if nbits < cur_freebits
      then begin
	buf.cur_byte <- (cur_byte lsl nbits) lor (value land bits_masks.(nbits));
	buf.cur_freebits <- cur_freebits - nbits
      end else begin
	let shift = nbits - cur_freebits in
	let new_byte = (cur_byte lsl cur_freebits) lor ((value lsr shift) land bits_masks.(cur_freebits)) in
	Buffer.add_char buf.buffer (char_of_int new_byte);
	add_bits_aux buf shift 0 8 value
      end
  in
  add_bits_aux buf nbits buf.cur_byte buf.cur_freebits value

let add_byte buf b =
  clean_slate buf;
  Buffer.add_char buf.buffer (char_of_int b)

let add_char buf c =
  clean_slate buf;
  Buffer.add_char buf.buffer c

let add_string buf s =
  clean_slate buf;
  Buffer.add_string buf.buffer s

let bprintf buf format =
  Printf.bprintf buf.buffer format

let add_output buf sub_buf =
  clean_slate buf;
  clean_slate sub_buf;
  Buffer.add_buffer buf.buffer sub_buf.buffer


let output_buffer ch buf = Buffer.output_buffer ch buf.buffer
