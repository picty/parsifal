open Common
open Types
open ParsingEngine
open Ssl2


let rec acceptable_versions min max = match min, max with
  | 0x0002, 0x0002 -> [0x0002]
  | 0x0002, _ -> 0x0002::(acceptable_versions 0x0300 max)
  | _ ->
    if min = max
    then [min]
    else min::(acceptable_versions (min+1) max)


let str_of_cs x =
  if x < 0x10000
  then hexdump_int_n 4 x
  else hexdump_int_n 5 x

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

	Printf.printf "acceptable_versions=\"\\(%s\\)\"\n"
	  (String.concat "\\|" (List.map (hexdump_int_n 4) (acceptable_versions 2 vmax)));
	Printf.printf "acceptable_suites=\"\\(%s\\)\"\n" (String.concat "\\|" (List.map str_of_cs ciphersuites));
	Printf.printf "acceptable_extensions=\"NO\"\n";
	exit 0
      | _ -> failwith ""
  with
    | _ -> exit 1


