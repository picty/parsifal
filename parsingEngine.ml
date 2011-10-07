module type ParsingParameters = sig
  type parsing_error
  val out_of_bounds_error : parsing_error
  val string_of_perror : parsing_error -> string

  type severity
  val fatal_severity : severity
  val string_of_severity : severity -> string
  val compare_severity : severity -> severity -> int
end

module Asn1ParserParams = struct
  type parsing_error =
    | InternalMayhem
    | OutOfBounds
    | NotImplemented of string
    | IncorrectLength of string
    | NotInNormalForm of string
    | UnknownUniversal of int

  let out_of_bounds_error = OutOfBounds

  let string_of_perror = function
    | InternalMayhem -> "Internal mayhem"
    | OutOfBounds -> "Out of bounds"
    | NotImplemented s -> "Not implemented (" ^ s ^  ")"
    | IncorrectLength t -> "Incorrect length for a " ^ t
    | NotInNormalForm t -> t ^ " not in normal form"
    | UnknownUniversal t -> "Unknown universal type " ^ (string_of_int t)


  type severity =
    | S_OK
    | S_Benign
    | S_IdempotenceBreaker
    | S_SpecLightlyViolated
    | S_SpecFatallyViolated
    | S_Fatal

  let fatal_severity = S_Fatal

  let string_of_severity = function
    | S_OK -> "OK"
    | S_Benign -> "Benign"
    | S_IdempotenceBreaker -> "IdempotenceBreaker"
    | S_SpecLightlyViolated -> "SpecLightlyViolated"
    | S_SpecFatallyViolated -> "SpecFatallyViolated"
    | S_Fatal -> "Fatal"

  let int_of_severity = function
    | S_OK -> 0
    | S_Benign -> 1
    | S_IdempotenceBreaker -> 2
    | S_SpecLightlyViolated -> 3
    | S_SpecFatallyViolated -> 4
    | S_Fatal -> 5

  let compare_severity x y =
    compare (int_of_severity x) (int_of_severity y)
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

    type error_handling_function = parsing_error -> severity -> parsing_state -> unit
    and parsing_state = {
      ehf : error_handling_function;
      origin : string;        (* The origin of what we are parsing (a filename for example) *)
      str : string;           (* The content of the innermost constructed currently parsed *)
      base : int;             (* The offset of str in the global string *)
      offset : int;           (* The offset of the object to parse in str *)
      len : int;              (* The length of the object to parse in str *)
      (* The invariant should be offset+len <= String.length str *)
      position : string list; (* A list of strings describing the objects including str *)
    }

    exception ParsingError of parsing_error * severity * parsing_state;;

    let string_of_pstate pstate =
      " in " ^ pstate.origin ^
	" at offset " ^ (string_of_int (pstate.base + pstate.offset)) ^
	" inside [" ^ (String.concat ", " (List.rev pstate.position)) ^ "]"

    let cur_char pstate = String.get pstate.str pstate.offset
    let cur_byte pstate = int_of_char (String.get pstate.str pstate.offset)

    let update_pstate pstate newoffset newlen = 
      if newoffset >= 0 && (newoffset + newlen) <= (String.length pstate.str)
      then {pstate with offset = newoffset; len = newlen}
      else raise (ParsingError (out_of_bounds_error, fatal_severity, pstate))

    let eat_bytes pstate howmany =
      let newoffset = pstate.offset + howmany
      and newlen = pstate.len - howmany in
      update_pstate pstate newoffset newlen

    let default_error_handling_function tolerance minDisplay err sev pstate =
      if compare_severity sev tolerance < 0
      then raise (ParsingError (err, sev, pstate))
      else if compare_severity minDisplay sev <= 0
      then print_endline ("Warning (" ^ (string_of_severity sev) ^ "): " ^ 
			     (string_of_perror err) ^ (string_of_pstate pstate))

    let make_pstate ehfun orig contents =
      {ehf = ehfun; origin = orig; str = contents;
       base = 0; offset = 0; len = String.length str;
       position = []}

  end


(*
ocaml

open ParsingEngine;;
module ASN1Parser = ParsingEngine (Asn1ParserParams);;
open ASN1Parser;;
open ASN1ParserParams;;
let s = {ehf = default_error_handling_function S_OK S_OK; origin = "stdin"; str = "tititoto"; base = 0; offset = 0; len = 4; position = []};;
*)
