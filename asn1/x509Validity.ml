(*
(* Time and validity *)

type datetime_content = {
  year : int; month : int; day : int;
  hour : int; minute : int; second : int option
}

type datetime = datetime_content option

let pop_datetime four_digit_year pstate =
  let s = pop_string pstate in

  let year_of_string () =
    if four_digit_year
    then pop_int s 0 4
    else begin
      match pop_int s 0 2 with
	| None -> None
	| Some x -> Some ((if x < 50 then 2000 else 1900) + x)
    end
  in

  let year_len = if four_digit_year then 4 else 2 in
  let expected_len = year_len + 8 in
  let n = String.length s in
  if n < expected_len then None else begin
    let year = year_of_string () in
    let month = pop_int s year_len 2 in
    let day = pop_int s (2 + year_len) 2 in
    let hour = pop_int s (4 + year_len) 2 in
    let minute = pop_int s (6 + year_len) 2 in
    match year, month, day, hour, minute with
      | Some y, Some m, Some d, Some hh, Some mm ->
	let ss = if (n < expected_len + 2)
	  then None
	  else pop_int s (8 + year_len) 2
	in Some { year = y; month = m; day = d;
		  hour = hh; minute = mm; second = ss }
      | _ -> None
  (* TODO: Handle trailing bytes? *)
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


type validity = { not_before : datetime; not_after : datetime }

let empty_validity = { not_before = None; not_after = None }

let extract_validity = function
  | [nb; na] -> { not_before = nb; not_after = na }
  | _ -> { not_before = None; not_after = None }

let validity_constraint : validity asn1_constraint =
  seqOf_cons extract_validity "Validity" datetime_constraint (Exactly (2, s_specfatallyviolated))


let string_of_datetime = function
  | None -> "Invalid date/time"
  | Some dt ->
    Printf.sprintf "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d"
      dt.year dt.month dt.day dt.hour dt.minute (pop_option dt.second 0)

let string_of_validity indent _ v =
  indent ^ "Not before: " ^ (string_of_datetime v.not_before) ^ "\n" ^
  indent ^ "Not after: " ^ (string_of_datetime v.not_after) ^ "\n"







module DateTimeParser = struct
  type t = datetime_content
  let name = "date_time"
  let params = []

  type pstate = unit
  let pstate_of_string _ = raise NotImplemented
  let pstate_of_stream _ _ = raise NotImplemented
  let eos _ = raise NotImplemented
  let mk_ehf _ = raise NotImplemented
  let parse _ = raise NotImplemented
  let dump _ = raise NotImplemented
  let update _ = raise NotImplemented

  let enrich dt dict =
    Hashtbl.replace dict "year" (V_Int dt.year);
    Hashtbl.replace dict "month" (V_Int dt.month);
    Hashtbl.replace dict "day" (V_Int dt.day);
    Hashtbl.replace dict "hour" (V_Int dt.hour);
    Hashtbl.replace dict "minute" (V_Int dt.minute);
    match dt.second with
      | None -> ()
      | Some sec -> Hashtbl.replace dict "second" (V_Int sec)

  let to_string o = string_of_datetime (Some o)
end

module DateTimeModule = MakeParserModule (DateTimeParser)
let _ = add_module ((module DateTimeModule : Module))
*)
