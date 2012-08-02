type action_result =
  | ActionDone
  | ParameterExpected
  | ShowUsage of string option

type option_type =
  | Set of bool ref
  | Clear of bool ref
  | IntVal of int ref
  | FloatVal of float ref
  | TrivialFun of (unit -> unit)
  | SimpleFun of (unit -> action_result)
  | StringVal of string ref
  | StringFun of (string -> action_result)
  | ClearList of string list ref
  | StringList of string list ref
  | Usage

type option_desc = {
  short_opt : char option;
  long_opt : string;
  action : option_type;
  description : string;
}

type getopt_params = {
  default_progname : string;
  options : option_desc list;
  postprocess_funs : (unit -> unit) list
}

let mkopt s l a d = {
  short_opt = s;
  long_opt = l;
  action = a;
  description = d
}


let usage progname options error =
  let exit_code = match error with
    | None -> 0
    | Some e -> prerr_endline e; 1
  in
  Printf.fprintf stderr "Usage: %s [options] [--] [arguments]\n" progname;
  let max_aux m opt = max m (String.length opt.long_opt) in
  prerr_endline "\nOptions:\n";
  let max_length = (List.fold_left max_aux 0 options) + 2 in
  let usage_option opt =
    let value_str = match opt.action with
      | Set _ | Clear _ | SimpleFun _ | TrivialFun _ | Usage | ClearList _ -> "  "
      | IntVal _ | FloatVal _ -> "=n"
      | StringVal _ | StringFun _ | StringList _ -> "=s"
    in
    match opt.short_opt with
    | None -> Printf.fprintf stderr "      --%*s  %s\n" (-max_length) (opt.long_opt ^ value_str) opt.description
    | Some c -> Printf.fprintf stderr "  -%c  --%*s  %s\n" c (-max_length) (opt.long_opt ^ value_str) opt.description
  in
  List.iter usage_option options;
  exit (exit_code)


let act_on_option opt param =
  match opt.action, param with
  | Set b, None -> b := true; ActionDone
  | Clear b, None -> b := false; ActionDone
  | Usage, None -> ShowUsage None
  | TrivialFun f, None -> f (); ActionDone
  | SimpleFun f, None -> f ()
  | ClearList l, None -> l := []; ActionDone

  | (Set _ | Clear _ | Usage | TrivialFun _ | SimpleFun _ | ClearList _), Some _ ->
    ShowUsage (Some ("Option \"" ^ opt.long_opt ^ "\" does not expect a parameter"))

  | IntVal _, None
  | FloatVal _, None
  | StringVal _, None
  | StringFun _, None
  | StringList _, None -> ParameterExpected

  | IntVal i, Some p -> begin
    try
      i := int_of_string p;
      ActionDone
    with _ ->
      ShowUsage (Some ("Integer expected for option \"" ^ opt.long_opt ^ "\""))
  end
  | FloatVal f, Some p -> begin
    try
      f := float_of_string p;
      ActionDone
    with _ ->
      ShowUsage (Some ("Float expected for option \"" ^ opt.long_opt ^ "\""))
  end
  | StringVal s, Some p -> s := p; ActionDone
  | StringFun f, Some p -> f p
  | StringList l, Some p -> l := p::(!l); ActionDone

let rec find_by_shortopt c = function
  | [] -> None
  | ({short_opt = Some so} as o)::r ->
    if so = c
    then Some o
    else find_by_shortopt c r
  | _::r -> find_by_shortopt c r

let rec find_by_longopt s = function
  | [] -> None
  | o::r ->
    if o.long_opt = s
    then Some o
    else find_by_longopt s r

let reverse_list = function
  | {action = StringList l} -> l := List.rev !l
  | _ -> ()


let parse_args gop args =
  let arg_len = Array.length args in
  let progname, arg_list =
    if arg_len > 0
    then args.(0), Array.to_list (Array.sub args 1 (arg_len - 1))
    else gop.default_progname, []
  in

  let rec handle_option_with_param opt p arguments r = 
    match act_on_option opt (Some p) with
    | ActionDone -> handle_next_option arguments r
    | ShowUsage s -> usage progname gop.options s
    | ParameterExpected -> usage progname gop.options (Some "Internal unexpected error")

  and handle_next_option arguments = function
    | [] -> List.rev arguments
    | "--"::r -> List.rev_append arguments r
    | a::r ->
      let str_len = String.length a in
      if str_len = 0
      then handle_next_option (a::arguments) r
      else if a.[0] = '-' then begin
	if str_len = 1 then usage progname gop.options (Some "Invalid option: \"-\"");
	if a.[1] = '-' then begin
	  match find_by_longopt (String.sub a 2 (str_len - 2)) gop.options with
	  | None -> begin
	    try
	      let equal_pos = String.index_from a 2 '=' in
	      match find_by_longopt (String.sub a 2 (equal_pos - 2)) gop.options with
	      | None -> usage progname gop.options (Some ("Unknown option \"" ^ a ^ "\""))
	      | Some opt -> handle_option_with_param opt (String.sub a (equal_pos + 1) (str_len - equal_pos - 1)) arguments r
	    with Not_found -> usage progname gop.options (Some ("Unknown option \"" ^ a ^ "\""))
	  end
	  | Some opt ->
	    match (act_on_option opt None), r with
	    | ActionDone, _ -> handle_next_option arguments r
	    | ShowUsage s, _ -> usage progname gop.options s
	    | ParameterExpected, [] -> 
	      usage progname gop.options (Some ("Option \"" ^ opt.long_opt ^ "\" expects a parameter"))
	    | ParameterExpected, p::new_r -> handle_option_with_param opt p arguments new_r
	end else handle_short_options a 1 str_len arguments r
      end else handle_next_option (a::arguments) r

  and handle_short_options current i n arguments r =
    if i >= n
    then handle_next_option arguments r
    else begin
      let c = current.[i] in
      match find_by_shortopt c gop.options with
      | None -> usage progname gop.options (Some ("Unknown option \"-" ^ (String.make 1 c) ^ "\""))
      | Some opt ->
	match act_on_option opt None with
	| ActionDone -> handle_short_options current (i+1) n arguments r
	| ShowUsage s -> usage progname gop.options s
	| ParameterExpected ->
	  let p, new_r = match n-(i+1), r with
	    | 0, [] -> 
	      usage progname gop.options (Some ("Option \"-" ^ (String.make 1 c) ^ "\" expects a parameter"))
	    | 0, p::new_r -> p, new_r
	    | _ -> String.sub current (i+1) (n-(i+1)), r
	  in handle_option_with_param opt p arguments new_r
    end

  in
  let res = handle_next_option [] arg_list in
  List.iter reverse_list gop.options;
  List.iter (fun f -> f ()) gop.postprocess_funs;
  res
				 
