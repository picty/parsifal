type severity = int
val severities : string array
val string_of_severity : severity -> string

val s_ok : severity
val s_benign : severity
val s_idempotencebreaker : severity
val s_speclightlyviolated : severity
val s_specfatallyviolated : severity
val s_fatal : severity

exception OutOfBounds of string


module type ParsingParameters =
  sig
    val default_tolerance : severity
    val default_minDisplay : severity

    type parsing_error
    val string_of_perror : parsing_error -> string
  end

module Make :
  functor (Params : ParsingParameters) ->
    sig
      type plength = int option
      type error_handling_function
      type parsing_state
      exception ParsingError of Params.parsing_error * severity * parsing_state
      val emit : Params.parsing_error -> severity -> parsing_state -> unit

      val get_depth : parsing_state -> int
      val get_offset : parsing_state -> int
      val get_len : parsing_state -> int
      val string_of_pstate : parsing_state -> string
      val string_of_exception : Params.parsing_error -> severity -> parsing_state -> string

      val default_error_handling_function :
        severity -> severity -> error_handling_function
      val tolerance : severity ref
      val minDisplay : severity ref

      val pstate_of_stream : string -> char Stream.t -> parsing_state
      val pstate_of_string : string -> string -> parsing_state
      val pstate_of_channel : string -> in_channel -> parsing_state
      val pstate_of_pstate : parsing_state -> string -> parsing_state
      val go_down : parsing_state -> string -> int -> unit
      val go_up : parsing_state -> unit

      val eos : parsing_state -> bool
      val pop_byte : parsing_state -> int
      val peek_byte : parsing_state -> int -> int

      val pop_string : parsing_state -> string
      val pop_bytes : parsing_state -> int -> int array
      val pop_list : parsing_state -> int list

      val extract_uint32 : parsing_state -> int
      val extract_uint24 : parsing_state -> int
      val extract_uint16 : parsing_state -> int
      val extract_string : string -> int -> parsing_state -> string
      val extract_variable_length_string : string -> (parsing_state -> int) -> parsing_state -> string
    end
