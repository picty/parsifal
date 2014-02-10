open Lwt
open Unix
open Parsifal
open LwtUtil
open TlsEnums
open Tls


(* Config *)

let config : (string, (string * int)) Hashtbl.t = Hashtbl.create 10
let default_server = ref ("", -1)
let unknown_server = ref ("", -1)

let read_config filename =
  let f = open_in filename in
  let rec handle_lines () =
    let line = input_line f in
    begin
      match string_split ';' line with
      | ["default"; host; port] -> default_server := host, int_of_string port
      | ["unknown"; host; port] -> unknown_server := host, int_of_string port
      | [domain; host; port] -> Hashtbl.replace config domain (host, int_of_string port)
      | _ -> Printf.fprintf Pervasives.stderr "Invalid config line: \"%s\"\n" (quote_string line)
    end;
    handle_lines ()
  in
  try handle_lines ()
  with End_of_file -> ()


(* Useful funs *)

let write_record o record =
  let s = exact_dump_tls_record record in
  really_write o s

let catcher = function
  | ParsingException (e, h) -> prerr_endline (string_of_exception e h); return ()
  | e -> prerr_endline (Printexc.to_string e); return ()




let rec extract_server_name = function
  | { extension_type = HE_ServerName;
      extension_data = ServerName (ClientServerName l) }::_ ->
    let rec interpret_name = function
      | { sni_name_type = NT_HostName;
          sni_name = HostName n }::r ->
        begin
          try Hashtbl.find config n
          with Not_found -> interpret_name r
        end
      | _::r -> interpret_name r
      | [] -> !unknown_server
    in
    interpret_name l
  | _::r -> extract_server_name r
  | [] -> !default_server


let rec forward i o =
  let s = String.create 1024 in
  Lwt_unix.read i s 0 1024 >>= fun l ->
  if l > 0 then begin
    _really_write o s 0 l >>= fun () ->
    forward i o
  end else begin
    Lwt_unix.shutdown o Unix.SHUTDOWN_SEND;
    Lwt.return ()
  end

let handle_client client_side =
  input_of_fd "Socket" client_side >>= fun input ->
  TlsEngine.lwt_parse_tls_record None input >>= fun record ->
  match record.record_content with
  | Handshake {handshake_content = ClientHello ch} ->
    let h, p = match ch.client_extensions with
      | None -> !default_server
      | Some es -> extract_server_name es
    in
    client_socket h p >>= fun server_side ->
    write_record server_side record >>= fun () ->
    let io = forward client_side server_side in
    let oi = forward server_side client_side in
    catch (fun () -> pick [io; oi]) catcher >>= fun () ->
    Lwt_unix.close server_side
  | _ ->
    prerr_endline "Wrong record...\n";
    return ()



let rec my_accept sock =
  Lwt_unix.accept sock >>= fun (s, _) ->
  prerr_endline "Connexion accepted";
  match Lwt_unix.fork () with
  | 0 ->
    Lwt_unix.close sock >>= fun () ->
    begin
      match Lwt_unix.fork () with
      | 0 ->
        catch (fun () -> handle_client s) catcher >>= fun () ->
        Lwt_unix.close s
      | _ -> exit 0
    end;
  | _ ->
    Lwt_unix.close s >>= fun () ->
    my_accept sock

let rec my_accept sock =
  Lwt_unix.accept sock >>= fun (s, _) ->
  prerr_endline "Connexion accepted";
  let t = catch (fun () -> handle_client s) (fun e -> Lwt_unix.close s >>= fun () -> catcher e) in
  join [t; my_accept sock]


let _ =
  let config_file = Sys.argv.(1)
  and accept_port = int_of_string (Sys.argv.(2)) in
  read_config config_file;
  enrich_record_content := true;
  let socket = server_socket accept_port in
  Lwt_unix.run (my_accept socket)
