module type ParsingParameters = sig
  type parsing_error
  val out_of_bounds_error : string -> parsing_error
  val string_of_perror : parsing_error -> string

  val severities : string array
end

module ParsingEngine =
  functor (Params : ParsingParameters) -> struct
    type plength = int option
    type severity = int
    type error_handling_function = Params.parsing_error -> severity -> parsing_state -> unit
    and parsing_state = {
      ehf : error_handling_function;
      origin : string;        (* The origin of what we are parsing (a filename for example) *)
      str : char Stream.t;    (* The content of the innermost constructed currently parsed *)
      mutable len : plength;  (* The length of the current object to parse in str *)
      mutable position : string list; (* A list of strings describing the objects including str *)
      mutable lengths : plength list  (* List of the previous lengths *)
    }

    exception ParsingError of Params.parsing_error * severity * parsing_state;;

    let emit err sev pstate =  pstate.ehf err sev pstate

    let fatal_severity = (Array.length Params.severities) - 1

    let get_depth pstate = List.length pstate.position
    let get_offset pstate = Stream.count pstate.str
    let get_len pstate = match pstate.len with
      | None -> -1
      | Some n -> n

    let string_of_pstate pstate =
      pstate.origin ^
	" at offset " ^ (string_of_int (Stream.count pstate.str)) ^
	" (len = " ^ (string_of_int (get_len pstate)) ^ ")" ^
	" inside [" ^ (String.concat ", " (List.rev pstate.position)) ^ "]"

    let string_of_severity sev =
      if sev >= 0 && sev < (Array.length Params.severities)
      then Params.severities.(sev)
      else "Wrong severity"

    let string_of_exception err sev pstate =
      "(" ^ (string_of_severity sev) ^ "): " ^ (Params.string_of_perror err) ^ " in " ^ (string_of_pstate pstate)



    let default_error_handling_function tolerance minDisplay err sev pstate =
      if sev >= tolerance || sev >= fatal_severity
      then raise (ParsingError (err, sev, pstate))
      else if minDisplay <= sev
      then output_string stderr ("Warning (" ^ (string_of_exception err sev pstate) ^ "\n")

    let pstate_of_stream ehfun orig contents =
      {ehf = ehfun; origin = orig; str = contents;
       len = None; position = []; lengths = []}

    let pstate_of_string ehfun orig contents =
      pstate_of_stream ehfun orig (Stream.of_string contents)

    let pstate_of_channel ehfun orig contents =
      pstate_of_stream ehfun orig (Stream.of_channel contents)


    let go_down pstate name l =
      let saved_len = match pstate.len with
	| None -> None
	| Some n ->
	  if l > n
	  then raise (ParsingError (Params.out_of_bounds_error "go_down", fatal_severity, pstate))
	  else Some (n - l)
      in
      pstate.lengths <- saved_len::(pstate.lengths);
      pstate.position <- name::(pstate.position);
      pstate.len <- Some l

    let go_up pstate =
      match pstate.lengths, pstate.position with
	| l::lens, _::names ->
	  pstate.len <- l;
	  pstate.lengths <- lens;
	  pstate.position <- names
	| _ -> raise (ParsingError (Params.out_of_bounds_error "go_up", fatal_severity, pstate))


    let eos pstate = 
      match pstate.len with
	| None -> begin
	  try
	    Stream.empty pstate.str;
	    true
	  with Stream.Failure -> false
	end
	| Some 0 -> true
	| _ -> false

    let pop_byte pstate =
      try
	match pstate.len with
	  | None -> int_of_char (Stream.next pstate.str)
	  | Some 0 -> raise Stream.Failure
	  | Some n ->
	    pstate.len <- Some (n - 1);
	    int_of_char (Stream.next pstate.str)
      with
	  Stream.Failure -> raise (ParsingError (Params.out_of_bounds_error "pop_byte", fatal_severity, pstate))

    let peek_byte pstate n =
      match pstate.len with
	| Some l when l < n -> raise (ParsingError (Params.out_of_bounds_error "peek_bytes", fatal_severity, pstate))
	| _ ->
	  let tmp = Stream.npeek (n+1) pstate.str in
	  try
	    int_of_char (List.nth tmp n)
	  with Failure "nth" -> raise (ParsingError (Params.out_of_bounds_error "peek_bytes", fatal_severity, pstate))



    let _pop_bytes pstate n assign =
      try
	for i = 0 to (n - 1) do
	  assign i (Stream.next pstate.str)
	done;
        begin
          match pstate.len with
            | Some l -> pstate.len <- Some (l - n)
            | _ -> ()
        end;
      with
	  Stream.Failure -> raise (ParsingError (Params.out_of_bounds_error "get_string", fatal_severity, pstate))

    let pop_string pstate =
      match pstate.len with
	| None -> raise (ParsingError (Params.out_of_bounds_error "get_string(undefined length)", fatal_severity, pstate))
	| Some n ->
	  let res = String.make n ' ' in
	  _pop_bytes pstate n (String.set res);
	  res

    let pop_bytes pstate n =
      match pstate.len with
	| Some l when l < n -> raise (ParsingError (Params.out_of_bounds_error "get_bytes", fatal_severity, pstate))
	| _ ->
	  let res = Array.make n 0 in
	  _pop_bytes pstate n (fun i -> fun c -> Array.set res i (int_of_char c));
	  res

    let pop_list pstate =
      match pstate.len with
	| None -> raise (ParsingError (Params.out_of_bounds_error "get_string(undefined length)", fatal_severity, pstate))
	| Some n ->
	  let res = Array.make n 0 in
	  _pop_bytes pstate n (fun i -> fun c -> Array.set res i (int_of_char c));
	  Array.to_list (res)



    let extract_uint32 pstate =
      let res = pop_bytes pstate 4 in
      (res.(0) lsl 24) lor (res.(1) lsl 16) lor (res.(2) lsl 8) lor res.(3)

    let extract_uint24 pstate =
      let res = pop_bytes pstate 3 in
      (res.(0) lsl 16) lor (res.(1) lsl 8) lor res.(2)

    let extract_uint16 pstate =
      let res = pop_bytes pstate 2 in
      (res.(0) lsl 8) lor res.(1)

    let extract_string name len pstate =
      go_down pstate name len;
      let res = pop_string pstate in
      go_up pstate;
      res

    let extract_variable_length_string name length_fun pstate =
      let len = length_fun pstate in
      go_down pstate name len;
      let res = pop_string pstate in
      go_up pstate;
      res
  end
