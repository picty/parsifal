module type ParsingParameters = sig
  type parsing_error
  val out_of_bounds_error : string -> parsing_error
  val string_of_perror : parsing_error -> string

  type severity
  val fatal_severity : severity
  val string_of_severity : severity -> string
  val compare_severity : severity -> severity -> int
end

module ParsingEngine =
  functor (Params : ParsingParameters) -> struct
    open Params
    type parsing_error = Params.parsing_error
    let out_of_bounds_error = Params.out_of_bounds_error
    let string_of_perror = Params.string_of_perror

    type severity = Params.severity
    let fatal_severity = Params.fatal_severity
    let string_of_severity = Params.string_of_severity
    let compare_severity = Params.compare_severity

    type plength = UndefLength | Length of int

    type error_handling_function = parsing_error -> severity -> parsing_state -> unit
    and parsing_state = {
      ehf : error_handling_function;
      origin : string;        (* The origin of what we are parsing (a filename for example) *)
      str : char Stream.t;    (* The content of the innermost constructed currently parsed *)
      mutable len : plength;  (* The length of the current object to parse in str *)
      mutable position : string list; (* A list of strings describing the objects including str *)
      mutable lengths : plength list  (* List of the previous lengths *)
    }

    exception ParsingError of parsing_error * severity * parsing_state;;

    let emit err sev pstate =  pstate.ehf err sev pstate

    let get_depth pstate = List.length pstate.position
    let get_offset pstate = Stream.count pstate.str
    let get_len pstate = match pstate.len with
      | UndefLength -> -1
      | Length n -> n

    let string_of_pstate pstate =
      pstate.origin ^
	" at offset " ^ (string_of_int (Stream.count pstate.str)) ^
	" (len = " ^ (string_of_int (get_len pstate)) ^ ")" ^
	" inside [" ^ (String.concat ", " (List.rev pstate.position)) ^ "]"

    let eos pstate = 
      match pstate.len with
	| UndefLength -> begin
	  try
	    Stream.empty pstate.str;
	    true
	  with Stream.Failure -> false
	end
	| Length 0 -> true
	| _ -> false

    let pop_byte pstate =
      try
	match pstate.len with
	  | UndefLength -> int_of_char (Stream.next pstate.str)
	  | Length n ->
	    pstate.len <- Length (n - 1);
	    int_of_char (Stream.next pstate.str)
      with
	  Stream.Failure -> raise (ParsingError (out_of_bounds_error "pop_byte", fatal_severity, pstate))

    let peek_byte pstate n =
      match pstate.len with
	| Length l when l < n -> raise (ParsingError (out_of_bounds_error "peek_bytes", fatal_severity, pstate))
	| _ ->
	  let tmp = Stream.npeek (n+1) pstate.str in
	  try
	    int_of_char (List.nth tmp n)
	  with Failure "nth" -> raise (ParsingError (out_of_bounds_error "peek_bytes", fatal_severity, pstate))


    let _pop_bytes pstate n assign =
      try
	for i = 0 to (n - 1) do
	  assign i (Stream.next pstate.str)
	done;
        begin
          match pstate.len with
            | Length l -> pstate.len <- Length (l - n)
            | _ -> ()
        end;
      with
	  Stream.Failure -> raise (ParsingError (out_of_bounds_error "get_string", fatal_severity, pstate))

    let pop_string pstate =
      match pstate.len with
	| UndefLength -> raise (ParsingError (out_of_bounds_error "get_string(UndefLength)", fatal_severity, pstate))
	| Length n ->
	  let res = String.make n ' ' in
	  _pop_bytes pstate n (String.set res);
	  res

    let pop_bytes pstate n =
      match pstate.len with
	| Length l when l < n -> raise (ParsingError (out_of_bounds_error "get_bytes", fatal_severity, pstate))
	| _ ->
	  let res = Array.make n 0 in
	  _pop_bytes pstate n (fun i -> fun c -> Array.set res i (int_of_char c));
	  res

    let pop_list pstate =
      match pstate.len with
	| UndefLength -> raise (ParsingError (out_of_bounds_error "get_string(UndefLength)", fatal_severity, pstate))
	| Length n ->
	  let res = Array.make n 0 in
	  _pop_bytes pstate n (fun i -> fun c -> Array.set res i (int_of_char c));
	  Array.to_list (res)


    let default_error_handling_function tolerance minDisplay err sev pstate =
      if compare_severity sev tolerance >= 0
      then raise (ParsingError (err, sev, pstate))
      else if compare_severity minDisplay sev <= 0
      then
	output_string stderr ("Warning (" ^ (string_of_severity sev) ^ "): " ^ 
				 (string_of_perror err) ^ " in " ^ (string_of_pstate pstate) ^ "\n")

    let pstate_of_string ehfun orig contents =
      {ehf = ehfun; origin = orig; str = Stream.of_string contents;
       len = Length (String.length contents); position = []; lengths = []}

    let pstate_of_channel ehfun orig contents =
      {ehf = ehfun; origin = orig; str = Stream.of_channel contents;
       len = UndefLength; position = []; lengths = []}

    let go_down pstate name l =
      let saved_len = match pstate.len with
	| UndefLength -> UndefLength
	| Length n ->
	  if l > n
	  then raise (ParsingError (out_of_bounds_error "go_down", fatal_severity, pstate))
	  else Length (n - l)
      in
      pstate.lengths <- saved_len::(pstate.lengths);
      pstate.position <- name::(pstate.position);
      pstate.len <- Length l
	  
    let go_up pstate =
      match pstate.lengths, pstate.position with
	| l::lens, _::names ->
	  pstate.len <- l;
	  pstate.lengths <- lens;
	  pstate.position <- names	  
	| _ -> raise (ParsingError (out_of_bounds_error "go_up", fatal_severity, pstate))
  end
