(* String parsing *)

let lwt_parse_string n input =
  really_read input.lwt_ch n >>= fun s ->
  input.lwt_offset <- input.lwt_offset + n;
  return s

let lwt_parse_rem_string name input =
  fail (Common.NotImplemented "lwt_parse_rem_string")

let lwt_parse_varlen_string name len_fun input =
  len_fun input >>= fun n ->
  get_in input name n >>= fun str_input ->
  let res = parse_rem_string str_input in
  get_out input str_input >>= fun () ->
  return res

let lwt_drop_bytes n input =
  really_read input.lwt_ch n >>= fun _ ->
  input.lwt_offset <- input.lwt_offset + n;
  return ()



(* List parsing *)

let lwt_parse_list n parse_fun input =
  let rec aux accu = function
    | 0 -> return (List.rev accu)
    | i ->
      parse_fun input >>= fun x ->
      aux (x::accu) (i-1)
  in aux [] n

let lwt_parse_rem_list name input =
  fail (Common.NotImplemented "lwt_parse_rem_list")

let lwt_parse_varlen_list name len_fun parse_fun input =
  len_fun input >>= fun n ->
  get_in input name n >>= fun str_input ->
  wrap2 parse_rem_list parse_fun str_input >>= fun res ->
  get_out input str_input >>= fun () ->
  return res


let lwt_parse_container name n parse_fun input =
  get_in input name n >>= fun str_input ->
  wrap1 parse_fun str_input >>= fun res ->
  get_out input str_input >>= fun () ->
  return res

let lwt_parse_varlen_container name len_fun parse_fun input =
  len_fun input >>= fun n ->
  lwt_parse_container name n parse_fun input
