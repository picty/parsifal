open Common
open Types
open ParsingEngine
open Ssl2

let _ =
  let pstate = pstate_of_channel "(stdin)" stdin in

  TlsHandshake.parse_certificates := false;
  tolerance := s_specfatallyviolated;
  minDisplay := s_specfatallyviolated;
  
  try
    let msg = Ssl2.parse pstate in
    match msg with
      | ClientHello (vmax, ciphersuites, _sid, _challenge) ->
	Printf.printf "%4.4x:%4.4x\n" 0x0002 vmax;
	Printf.printf "Ciphersuites\n";
	List.iter (fun cs -> Printf.printf "  %4.4x\n" cs) ciphersuites;
	exit 0
      | _ -> failwith ""
  with
    | _ -> exit 1


