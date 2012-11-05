exception NotImplemented of string

let hash_get ht k default =
  try Hashtbl.find ht k
  with Not_found -> default
