open Common
open Types
open ParsingEngine
open Tls
open TlsCommon
open TlsRecord
open TlsHandshake



let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  TlsHandshake.parse_certificates := false;
  tolerance := s_specfatallyviolated;
  minDisplay := s_specfatallyviolated;
  
  try
    let records, error = Tls.TlsLib.shallow_parse_records pstate in
    let parsed_recs = Tls.TlsLib._deep_parse_aux "(stdin)" records true in
    match parsed_recs with
      | [{content_type = 0x16; content = c; version = vmin}] ->
	begin
	  match HandshakeModule.pop_object c with
	    | 1, V_Dict ch ->
	      let vmax = eval_as_int (ch --> "version")
	      and ciphersuites = List.map eval_as_int (eval_as_list (ch --> "cipher_suites"))
	      and extensions = match (ch --> "extensions") with
		| V_List l -> List.map (fun x -> eval_as_int (List.hd (eval_as_list x))) l
		| _ -> []
	      in
	      Printf.printf "%4.4x:%4.4x\n" vmin vmax;
	      Printf.printf "Ciphersuites\n";
	      List.iter (fun cs -> Printf.printf "  %4.4x\n" cs) ciphersuites;
	      Printf.printf "Extensions\n";
	      List.iter (fun e -> Printf.printf "  %4.4x\n" e) extensions;
	      exit 0
	    | _ -> failwith ""
	end
      | _ -> failwith ""
  with
    | _ -> exit 1
