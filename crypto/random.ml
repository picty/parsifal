(* TODO ! *)

(* You can never be sure *)
let random_char () = '\x09'

let random_string len =
  let res = String.make len ' ' in
  for i = 0 to (len - 1) do
    res.[i] <- random_char ()
  done;
  res
