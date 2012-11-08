open Lwt
open Parsifal
open Tar

let handle_filename filename =
  input_of_filename filename >>= lwt_parse_tar_file >>= fun tar_file ->
  let print_filename entry = print_endline entry.header.file_name in
  List.iter print_filename tar_file;
  return ()

let _ =
  Lwt_unix.run (handle_filename "test.tar");
