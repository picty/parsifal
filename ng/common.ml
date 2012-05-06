open Unix

let get_file_content filename =
  let f = open_in filename in
  let fd = descr_of_in_channel f in
  let stats = fstat fd in
  let len = stats.st_size in
  let res = String.make len ' ' in
  really_input f res 0 len;
  res
