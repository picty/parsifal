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
      type plength = UndefLength | Length of int
      type parsing_state
      type error_handling_function
      val get_depth : parsing_state -> int
      val get_offset : parsing_state -> int
      val get_len : parsing_state -> int
      val emit : Params.parsing_error -> Params.severity -> parsing_state -> unit
      exception ParsingError of Params.parsing_error * Params.severity * parsing_state
      val string_of_pstate : parsing_state -> string
      val string_of_exception : Params.parsing_error -> Params.severity -> parsing_state -> string
      val eos : parsing_state -> bool

      val peek_byte : parsing_state -> int -> int

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

      val extract_uint32 : parsing_state -> int
      val extract_uint24 : parsing_state -> int
      val extract_uint16 : parsing_state -> int
      val extract_string : string -> int -> parsing_state -> string
      val extract_variable_length_string : string -> (parsing_state -> int) -> parsing_state -> string
    end
