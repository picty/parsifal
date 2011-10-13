module type ParsingParameters =
  sig
    type parsing_error
    val out_of_bounds_error : string -> parsing_error
    val string_of_perror : parsing_error -> string
    type severity
    val fatal_severity : severity
    val string_of_severity : severity -> string
    val compare_severity : severity -> severity -> int
  end
module ParsingEngine :
  functor (Params : ParsingParameters) ->
    sig
      type parsing_error = Params.parsing_error
      val out_of_bounds_error : string -> Params.parsing_error
      val string_of_perror : Params.parsing_error -> string
      type severity = Params.severity
      val fatal_severity : Params.severity
      val string_of_severity : Params.severity -> string
      val compare_severity : Params.severity -> Params.severity -> int
      type plength = UndefLength | Length of int
      type parsing_state
      type error_handling_function
      val get_depth : parsing_state -> int
      val get_offset : parsing_state -> int
      val get_len : parsing_state -> int
      val emit : parsing_error -> severity -> parsing_state -> unit
      exception ParsingError of parsing_error * severity * parsing_state
      val string_of_pstate : parsing_state -> string
      val eos : parsing_state -> bool
      val pop_byte : parsing_state -> int
      val pop_string : parsing_state -> string
      val pop_list : parsing_state -> int list
      val pop_bytes : parsing_state -> int -> int array
      val default_error_handling_function :
        Params.severity -> Params.severity -> error_handling_function
      val pstate_of_string :
        error_handling_function -> string -> string -> parsing_state
      val pstate_of_channel :
        error_handling_function -> string -> in_channel -> parsing_state
      val go_down : parsing_state -> string -> int -> unit
      val go_up : parsing_state -> unit
    end
