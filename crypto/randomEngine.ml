(*
  In the interactive mode, we can seed the random engine with
  random.seed (read_some (open ("/dev/urandom"), 64))
*)

(* TODO: Work on exceptions *)
exception InvalidRandomState

let refresh_bh h s x =
  let n = String.length !s in
  let tmp = Bytes.of_string (h ("extract" ^ x)) in
  if n = Bytes.length tmp then begin
    Cryptokit.xor_string !s 0 tmp 0 n;
    s := h ("G_prime" ^ (Bytes.to_string tmp))
  end else raise InvalidRandomState

let next_bh h s () =
  let rnd_bytes = h ("G_first" ^ !s) in
  s := h ("G_secnd" ^ !s);
  rnd_bytes

type state = {
  seed : string -> unit;
  refresh : string -> unit;
  next : unit -> string;
}

let make_bh_prng h seed =
  let state = ref (h seed) in
  { seed = (fun x -> state := (h x));
    refresh = refresh_bh h state;
    next = next_bh h state }


let random_char s =
  let tmp = s.next () in
  tmp.[0]

let random_string s len =
  let rec aux accu remaining =
    let tmp = s.next () in
    if String.length tmp >= remaining
    then String.concat "" ((String.sub tmp 0 remaining)::accu)
    else aux (tmp::accu) (remaining - (String.length tmp))
  in aux [] len

let random_int s max =
  let rec n_bytes n =
    if n = 0 then 0
    else 1 + (n_bytes (n lsr 8))
  in

  (* TODO: Exception? *)
  if max < 0 then raise (Failure "random_int expect a positive max");
  let len = n_bytes (max - 1) in

  (* TODO: Add an optimisation here to mask some bits: it is possible
     to have only one execution of the loop *)

  let rec aux () =
    let tmp = ref 0
    and rnd = random_string s len in
    for i = 0 to (len - 1) do
      tmp := (!tmp lsl 8) lor (int_of_char rnd.[i])
    done;
    if !tmp < max then !tmp else aux ()
  in
  aux ()



let seeded_random_generator seed =
  make_bh_prng CryptoUtil.sha256sum seed

let default_random_generator () =
  let f = open_in "/dev/urandom" in
  let seed = Bytes.create 32 in
  really_input f seed 0 32;
  close_in f;
  seeded_random_generator (Bytes.to_string seed)

let dummy_random_generator () = {
  seed = (fun _ -> ());
  refresh = (fun _ -> ());
  next = (fun () -> String.make 32 '\x00');
}
