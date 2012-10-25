(* List dumping *)

let dump_list dump_fun l =
  String.concat "" (List.map dump_fun l)

let dump_varlen_list len_fun dump_fun l =
  let res = dump_list dump_fun l in
  let n = String.length res in
  (len_fun n) ^ res

let dump_container len_fun dump_fun content =
  let res = dump_fun content in
  let n = String.length res in
  (len_fun n) ^ res


(* Useful function *)

let try_dump dump_fun = function
  | None -> ""
  | Some x -> dump_fun x
