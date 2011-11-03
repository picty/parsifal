open Types
open Modules
open NewParsingEngine
open TlsCommon


type tls_change_cipher_spec_errors =
  | InvalidValue
  | UnexpectedJunk

let tls_change_cipher_spec_errors_strings = [|
  (InvalidValue, s_idempotencebreaker, "Invalid ChangeCipherSpec value");
  (UnexpectedJunk, s_idempotencebreaker, "Unexpected junk in ChangeCipherSpec message");
|]

let tls_change_cipher_spec_emit =
  register_module_errors_and_make_emit_function "tlsChangeCipherSpec" tls_change_cipher_spec_errors_strings



module ChangeCipherSpecParser = struct
  let name = "change_cipher_spec"
  type t = unit

  let mk_ehf () = default_error_handling_function !tolerance !minDisplay


  (* TODO: Should disappear soon... *)
  type pstate = NewParsingEngine.parsing_state
  let pstate_of_string s = NewParsingEngine.pstate_of_string (mk_ehf ()) s
  let pstate_of_stream n s = NewParsingEngine.pstate_of_stream (mk_ehf ()) n s
  let eos = eos
  (* TODO: End of blob *)

  let parse pstate =
    let ccs = pop_byte pstate in
    if ccs <> 1
    then tls_change_cipher_spec_emit InvalidValue (Some (string_of_int ccs)) pstate;

    if not (eos pstate)
    then tls_change_cipher_spec_emit UnexpectedJunk (Some (Common.hexdump (pop_string pstate))) pstate;
    Some ()

  let dump _ = ""

  let enrich _ _ = ()

  let update _ = ()

  let to_string _ =
    "TLS Change_Cipher_Spec"

  let params = []
end

module ChangeCipherSpecModule = MakeParserModule (ChangeCipherSpecParser)

let _ =
  add_module ((module ChangeCipherSpecModule : Module));
  ()
