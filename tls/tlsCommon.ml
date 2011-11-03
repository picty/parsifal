(* Protocol version *)

type protocol_version = { major : int; minor : int }

let string_of_protocol_version v = match (v.major, v.minor) with
  | 2, 0 -> "SSLv2"
  | 3, 0 -> "SSLv3"
  | 3, 1 -> "TLSv1.0"
  | 3, 2 -> "TLSv1.1"
  | 3, 3 -> "TLSv1.2"
  | maj, min -> "version " ^ (string_of_int maj) ^ "." ^ (string_of_int min)



let tolerance = ref 0
let minDisplay = ref 0

