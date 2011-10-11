(* ocamlc -pp "camlp4o pa_extend.cmo" -I +camlp4 -c map_lexer.ml *)

(* TODO: Add comments... *)

type keyword =
  | KWIn | KWIf | KWThen | KWElse | KWFi | KWIEq | KWINe | KWILt | KWILe | KWIGt | KWIGe
  | KWLeftPar | KWRightPar | KWSEq | KWSNeq | KWIPlus | KWISub | KWIMult | KWIDiv | KWIMod

type string_token =
  | STString of string
  | STVar of string

type token =
  | TKeyword of string
  | TIdent of string
  | TInt of int
  | TString of string_token list
  | TEof


let zero_ascii = int_of_char '0'

let string_of_list l =
  let len = List.length l in
  let res = String.make len ' ' in
  let rec aux i = function
    | [] -> res
    | c::r -> res.[i] <- c; aux (i+1) r
  in
  aux 0 l

let add_str l = function
  | [] -> l
  | cl -> STString (string_of_list (List.rev cl))::l

let discr_limit = 64
let ident_buffer = String.make discr_limit ' '


let rec read_int accu s = match s with parser
  | [< ' ('0'..'9' as c) >] ->
    read_int ((accu * 10) + (int_of_char c - zero_ascii)) s
  | [< >] -> accu

let rec read_string cur accu s = match s with parser
  | [< ' ('\\'); ' ('\\' | '"' | '$' as c) >] -> read_string (c::cur) accu s
  | [< ' ('"') >] -> List.rev (add_str accu cur)
  | [< ' ('$'); ' ('A'..'Z' | 'a'..'z' | '_' as c) >] ->
    ident_buffer.[0] <- c;
    let ident = read_ident 1 s in
    read_string [] ((STVar ident)::(add_str accu cur)) s
  | [< 'c >] -> read_string (c::cur) accu s

and read_ident pos s = match s with parser
  | [< ' ('A'..'Z' | 'a'..'z' | '0'..'9' | '_' as c) >] ->
    if 0 < pos && pos < discr_limit
    then ident_buffer.[pos] <- c;
    read_ident (pos + 1) s
  | [< >] -> String.sub ident_buffer 0 pos


let rec skip_blanks s = match s with parser
  | [< ' (' ' | '\t' | '\n') >] -> skip_blanks s
  | [< >] -> ()

exception EndOfStream

let read_token kwtable s =
  skip_blanks s;

  match s with parser
    | [< ' ('<' | '>' | '!' | '=' | '~') as c >] -> begin
      match s with parser
	| [< ' ('=') >] ->  
	  let res = String.make 2 '=' in
	  res.[0] <- c;
	  TKeyword res
	| [< >] -> 
	  TKeyword (String.make 1 c)

    end

    | [< ' ( '+' | '-' | '*' | '/' | '%' | '&' | '^' | '|' | '(' | ')' as c) >] ->
      TKeyword (String.make 1 c)

    | [< ' ('"') >] ->
      TString (read_string [] [] s)

    | [< ' ('A'..'Z' | 'a'..'z' | '_' as c) >] ->
      ident_buffer.[0] <- c;
      let ident = read_ident 1 s in
      if List.mem ident kwtable
      then TKeyword ident
      else TIdent ident

    | [< ' ('0'..'9' as c) >] ->
      TInt (read_int (int_of_char c - zero_ascii) s)

    | [< 'c >] -> raise Stream.Failure

    | [< >] -> TEof
