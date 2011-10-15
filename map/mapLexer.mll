{
open MapParser
  
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
  | cl -> MapLang.ST_String (string_of_list (List.rev cl))::l
}


rule main_token = parse
  | '(' { T_LeftPar }
  | ')' { T_RightPar }

  | '+' { T_Plus }
  | '-' { T_Minus }
  | '*' { T_Mult }
  | '/' { T_Div }
  | '%' { T_Mod }

  | ":=" { T_Assign }
  | "==" { T_Equal }
  | "=" { T_Equal }
  | "!=" { T_Neq }
  | "<=" { T_Le }
  | '<'  { T_Lt }
  | ">=" { T_Ge }
  | '>'  { T_Gt }
  | "in" { T_In }
  | "~=" { T_Like }

  | "&&" { T_LAnd }
  | "||" { T_LOr }
  | '!'  { T_LNot }

  | '&'  { T_BAnd }
  | '|'  { T_BOr }
  | '^'  { T_BXor }
  | '~'  { T_BNot }

  | "if"   { T_If }
  | "then" { T_Then }
  | "else" { T_Else }
  | "fi"   { T_Fi }

  | "print" { T_Print }
  | "filter" { T_Filter }
  | ';' { T_SemiColumn }

  | "typeof" { T_TypeOf }
  | "open" { T_Open }
  | "parse" { T_Parse }

  | eof { T_Eof }
  | [' ' '\n' '\t' ] { main_token lexbuf }
  | ['0'-'9']+ { T_Int (int_of_string (Lexing.lexeme lexbuf))}
  | ['A'-'Z' 'a'-'z' '_'] ['A'-'Z' 'a'-'z' '_' '0'-'9']*
      { T_Ident (Lexing.lexeme lexbuf) }

  | "/*" { comment_token lexbuf }
  | "//" { comment_oneline_token lexbuf }
  | '"'  { string_token [] [] lexbuf }

and comment_token = parse
  | "*/" { main_token lexbuf }
  | _    { comment_token lexbuf }

and comment_oneline_token = parse
  | '\n' { main_token lexbuf }
  | _    { comment_token lexbuf }

and string_token cur accu = parse
  | '\\' ['\\' '"' '$'] { string_token ((Lexing.lexeme_char lexbuf 1)::cur) accu lexbuf }
  | '"' { T_String (List.rev (add_str accu cur)) }
  | '$' ( ['A'-'Z' 'a'-'z' '_'] ['A'-'Z' 'a'-'z' '_' '0'-'9']* as ident )
      { string_token [] ((MapLang.ST_Var ident)::(add_str accu cur)) lexbuf }
  | _ as c { string_token (c::cur) accu lexbuf }
