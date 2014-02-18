let polynom = 0xedb88320l

let crc_table = Array.init 256 (fun n ->
  let crc = ref (Int32.of_int n) in
  for _j = 0 to 7 do
    crc := if Int32.to_int (Int32.logand (!crc) 1l) <> 0 then
      Int32.logxor (Int32.shift_right_logical (!crc) 1) polynom
    else
      Int32.shift_right_logical (!crc) 1;
  done;
  !crc) 

let update_crc crc buf pos len =
  let c = ref (Int32.lognot crc) in
  for i = pos to (len + pos - 1) do
    let b = Int32.of_int (int_of_char (String.get buf i)) in
    c := Int32.logxor (Array.get crc_table (Int32.to_int (Int32.logand (Int32.logxor !c b) 0xFFl))) (Int32.shift_right_logical !c 8);
  done;
  let ret = Int32.lognot !c in
  ret

let crc32 s =
  let int32res = update_crc 0l s 0 (String.length s) in
  let res = String.make 4 '\x00' in
  res.[0] <- char_of_int (Int32.to_int (Int32.logand (Int32.shift_right_logical int32res 24) 0xFFl));
  res.[1] <- char_of_int (Int32.to_int (Int32.logand (Int32.shift_right_logical int32res 16) 0xFFl));
  res.[2] <- char_of_int (Int32.to_int (Int32.logand (Int32.shift_right_logical int32res 8) 0xFFl));
  res.[3] <- char_of_int (Int32.to_int (Int32.logand int32res 0xFFl));
  res

let crc32le s =
  let int32res = update_crc 0l s 0 (String.length s) in
  let res = String.make 4 '\x00' in
  res.[3] <- char_of_int (Int32.to_int (Int32.logand (Int32.shift_right_logical int32res 24) 0xFFl));
  res.[2] <- char_of_int (Int32.to_int (Int32.logand (Int32.shift_right_logical int32res 16) 0xFFl));
  res.[1] <- char_of_int (Int32.to_int (Int32.logand (Int32.shift_right_logical int32res 8) 0xFFl));
  res.[0] <- char_of_int (Int32.to_int (Int32.logand int32res 0xFFl));
  res
