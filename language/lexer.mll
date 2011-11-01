{
open Parser
  
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
  | cl -> Language.ST_String (string_of_list (List.rev cl))::l
}


rule main_token = parse
  | eof { T_Eof }
  | [' ' '\n' '\t' ] { main_token lexbuf }

  | '(' { T_LeftPar }
  | ')' { T_RightPar }
  | '{' { T_LeftBrace }
  | '}' { T_RightBrace }
  | '[' { T_LeftBracket }
  | ']' { T_RightBracket }
  | ',' { T_Comma }
  | '.' { T_Period }
  | "::" { T_Cons }

  | "++" { T_Concat }
  | '+' { T_Plus }
  | '-' { T_Minus }
  | '*' { T_Mult }
  | '/' { T_Div }
  | '%' { T_Mod }

  | ":=" { T_Assign }
  | "<-" {T_FieldAssign }
  | "==" { T_Equal }
  | "="  { T_Equal }
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

  | "while"    { T_While}
  | "do"       { T_Do}
  | "done"     { T_Done }
  | "break"    { T_Break }
  | "continue" { T_Continue }

  | "function" { T_Function }
  | "local" { T_Local }
  | "return" { T_Return }
  | "unset" { T_Unset }

  | ';' { T_SemiColumn }

  | "exists" { T_Exists }

  | "true"     { T_Bool true }
  | "false"    { T_Bool false }
  | "0x" ['0'-'9' 'a'-'f' 'A'-'F']+
  | ['0'-'9']+ { T_Int (int_of_string (Lexing.lexeme lexbuf))}
  | ['A'-'Z' 'a'-'z' '_'] ['A'-'Z' 'a'-'z' '_' '0'-'9']*
               { T_Ident (Lexing.lexeme lexbuf) }

  | "/*" { comment_token lexbuf }
  | "//" { comment_oneline_token lexbuf }
  | '#' { comment_oneline_token lexbuf }
  | '"'  { string_token [] [] lexbuf }
  | '\''  { uninterp_string_token [] lexbuf }

and comment_token = parse
  | "*/" { main_token lexbuf }
  | eof  { T_Eof }
  | _    { comment_token lexbuf }

and comment_oneline_token = parse
  | '\n' { main_token lexbuf }
  | eof  { T_Eof }
  | _    { comment_oneline_token lexbuf }

and string_token cur accu = parse
  | '\\' ['\\' '"' '$'] { string_token ((Lexing.lexeme_char lexbuf 1)::cur) accu lexbuf }
  | "\\n" { string_token ('\n'::cur) accu lexbuf }
  | "\\t" { string_token ('\t'::cur) accu lexbuf }
  | "\\x" ['A'-'F' 'a'-'f' '0'-'9'] ['A'-'F' 'a'-'f' '0'-'9']
      {
	let s = String.copy (Lexing.lexeme lexbuf) in
	s.[0] <- '0';
	let c = char_of_int (int_of_string s) in
	string_token (c::cur) accu lexbuf 
      }
  | '"' { T_String (List.rev (add_str accu cur)) }
  | '$' ( ['A'-'Z' 'a'-'z' '_'] ['A'-'Z' 'a'-'z' '_' '0'-'9']* as ident )
      { string_token [] ((Language.ST_Var ident)::(add_str accu cur)) lexbuf }
  | "${" ( [^ '}']* as e ) '}'
      { string_token [] ((Language.ST_Expr e)::(add_str accu cur)) lexbuf }
  | _ as c { string_token (c::cur) accu lexbuf }

and uninterp_string_token cur = parse
  | '\\' ['\\' '\''] { uninterp_string_token ((Lexing.lexeme_char lexbuf 1)::cur) lexbuf }
  | '\'' { T_String [Language.ST_String (string_of_list (List.rev cur))] }
  | _ as c { uninterp_string_token (c::cur) lexbuf }
