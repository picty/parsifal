open Types
open Modules
open Printer
open ParsingEngine
open Asn1
open Asn1Constraints


(* Time and validity *)

type datetime = {
  year : int; month : int; day : int;
  hour : int; minute : int; second : int option;
  second_fraction : string option
}

let empty_datetime = {
  year = 0; month = 0; day = 0;
  hour = 0; minute = 0; second = None;
  second_fraction = None
}


let pop_datetime four_digit_year pstate =
  let s = pop_string pstate in
  let year_len = if four_digit_year then 4 else 2 in
  let expected_len = year_len + 8 in
  let n = String.length s in

  let year_of_string () =
    if four_digit_year
    then Common.pop_int s 0 4
    else begin
      match Common.pop_int s 0 2 with
	| None -> None
	| Some x -> Some ((if x < 50 then 2000 else 1900) + x)
    end
  in

  let second_of_string () =
    if (n < expected_len + 2)
    then begin
      asn1_emit NotInNormalForm (Some s_benign) (Some "Missing seconds") pstate;
      if n <= expected_len || s.[expected_len] != 'Z'
      then asn1_emit NotInNormalForm None (Some "Time field should end with a Z") pstate;
      None, None
    end else begin
      let ss = Common.pop_int s expected_len 2 in
      let sfrac = match ss with
	| None ->
	  asn1_emit NotInNormalForm None (Some "Missing seconds") pstate;
	  None
	| Some _ ->
	  let end_of_trail = expected_len + 2 in
	  if n <= end_of_trail || s.[n-1] != 'Z'
	  then asn1_emit NotInNormalForm None (Some "Time field should end with a Z") pstate;
	  if n <= end_of_trail then None else Some (String.sub s end_of_trail (n - end_of_trail - 1))
      in
      ss, sfrac
    end
  in

  let invalid_date () =
    asn1_emit InvalidDate None None pstate;
    empty_datetime
  in

  if n < expected_len then invalid_date () else begin
    let year = year_of_string () in
    let month = Common.pop_int s year_len 2 in
    let day = Common.pop_int s (2 + year_len) 2 in
    let hour = Common.pop_int s (4 + year_len) 2 in
    let minute = Common.pop_int s (6 + year_len) 2 in
    match year, month, day, hour, minute with
      | Some y, Some m, Some d, Some hh, Some mm ->
	let ss, sfrac = second_of_string () in
	{ year = y; month = m; day = d;
	  hour = hh; minute = mm; second = ss;
	  second_fraction = sfrac}
      | _ -> invalid_date ()
  end


let datetime_constraint : datetime asn1_constraint =
  let aux c isC t =
    if c = C_Universal && not isC then begin
      match t with
	| 23 -> Some ("Time", pop_datetime false)
	| 24 -> Some ("Time", pop_datetime true)
	| _ -> None
    end else None
  in Complex_cons aux


let string_of_datetime title dt =
  PrinterLib._single_line title 
    (Printf.sprintf "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d%s"
       dt.year dt.month dt.day dt.hour dt.minute
       (Common.pop_option dt.second 0)
       (Common.pop_option dt.second_fraction ""))


module DateTimeParser = struct
  type t = datetime
  let name = "datetime"
  let params = []

  let parse = constrained_parse datetime_constraint
  let dump dt = raise NotImplemented
  let enrich dt dict =
    Hashtbl.replace dict "year" (V_Int dt.year);
    Hashtbl.replace dict "month" (V_Int dt.month);
    Hashtbl.replace dict "day" (V_Int dt.day);
    Hashtbl.replace dict "hour" (V_Int dt.hour);
    Hashtbl.replace dict "minute" (V_Int dt.minute);
    begin
      match dt.second with
	| None -> ()
	| Some sec -> Hashtbl.replace dict "second" (V_Int sec)
    end;
    match dt.second_fraction with
      | None -> ()
      | Some sec -> Hashtbl.replace dict "second_fraction" (V_String sec)

  let update dict = raise NotImplemented
  let to_string dt = [string_of_datetime None dt]
  let functions = []
end

module DateTimeModule = MakeParserModule (DateTimeParser)
let _ = add_object_module ((module DateTimeModule : ObjectModule))





type validity = { not_before : datetime;
		  not_after : datetime }
let empty_validity = { not_before = empty_datetime;
		       not_after = empty_datetime }

let extract_validity = function
  | [nb; na] -> { not_before = nb; not_after = na }
  | _ -> { not_before = empty_datetime; not_after = empty_datetime }

let validity_constraint : validity asn1_constraint =
  seqOf_cons extract_validity "Validity" datetime_constraint (Exactly (2, s_specfatallyviolated))


let string_of_validity v =
  [string_of_datetime (Some "Not before") v.not_before;
   string_of_datetime (Some "Not after") v.not_after]


module ValidityParser = struct
  type t = validity
  let name = "validity"
  let params = []

  let parse = constrained_parse validity_constraint
  let dump dt = raise NotImplemented

  let enrich dt dict =
    Hashtbl.replace dict "not_before" (DateTimeModule.register dt.not_before);
    Hashtbl.replace dict "not_after" (DateTimeModule.register dt.not_after);
    ()

  let update dict = raise NotImplemented
  let to_string = string_of_validity
  let functions = []
end

module ValidityModule = MakeParserModule (ValidityParser)
let _ = add_object_module ((module ValidityModule : ObjectModule))
