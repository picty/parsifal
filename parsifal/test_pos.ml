open Lwt

let is_rewindable ch =
  let handle_unix_error = function
    | Unix.Unix_error (Unix.ESPIPE, "lseek", "") -> return false
    | e -> fail e
  and get_length () = Lwt_io.length ch
  and is_not_null x = return (Int64.compare Int64.zero x <> 0)
  in try_bind get_length is_not_null handle_unix_error

let print_bool b = print_string (string_of_bool b)


let _ =
  let input_pos = Lwt_io.position Lwt_io.stdin in
  print_endline (Int64.to_string input_pos);
  
  try
      Lwt_unix.run (is_rewindable Lwt_io.stdin >>= wrap1 print_bool);
  with
    | e -> print_endline (Printexc.to_string e)
  
