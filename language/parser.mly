%token T_LeftPar T_RightPar T_LeftBrace T_RightBrace T_LeftBracket T_RightBracket T_Comma T_Period T_Cons
%token T_Plus T_Minus T_Mult T_Div T_Mod
%token T_Equal T_Neq T_Le T_Lt T_Ge T_Gt T_In T_Like
%token T_Concat
%token T_LAnd T_LOr T_LNot
%token T_BAnd T_BOr T_BNot T_BXor
%token T_If T_Then T_Else T_Fi
%token T_While T_Do T_Done T_Break T_Continue
%token T_Assign T_FieldAssign
%token T_SemiColumn
%token T_Eof
%token T_Exists
%token T_Function T_Return T_Local T_Unset
%token <bool> T_Bool
%token <int> T_Int
%token <string> T_Ident
%token <Language.string_token list> T_String

%right T_Exists T_Return T_Assign T_FieldAssign T_Unset
%left T_SemiColumn T_Comma
%left T_LOr
%left T_LAnd
%left T_LNot
%left T_Equal T_Neq T_Le T_Lt T_Ge T_Gt T_In T_Like
%right T_Cons
%left T_Plus T_Minus T_Concat
%left T_Mult T_Div T_Mod
%left T_BOr T_BXor
%left T_BAnd
%left T_BNot
%left T_Period
%right T_LeftPar T_RightPar
%nonassoc T_UMinus


%start exprs
%type <Language.expression list> exprs

%%

expr:
    | T_Bool     { Language.E_Bool $1 }
    | T_Int      { Language.E_Int $1 }
    | T_String   { Language.E_String $1 }
    | T_Ident    { Language.E_Var $1 }

    | T_LeftPar expr T_RightPar { $2 }

    | expr T_Concat expr { Language.E_Concat ($1, $3) }
    | expr T_Plus expr   { Language.E_Plus ($1, $3) }
    | expr T_Minus expr  { Language.E_Minus ($1, $3) }
    | expr T_Mult expr   { Language.E_Mult ($1, $3) }
    | expr T_Div expr    { Language.E_Div ($1, $3) }
    | expr T_Mod expr    { Language.E_Mod ($1, $3) }
    | T_Minus expr %prec T_UMinus { Language.E_Minus (Language.E_Int 0, $2) }

    | expr T_Equal expr  { Language.E_Equal ($1, $3) }
    | expr T_Neq expr    { Language.E_LNot (Language.E_Equal ($1, $3)) }
    | expr T_Le expr     { Language.E_LNot (Language.E_Lt ($3, $1)) }
    | expr T_Lt expr     { Language.E_Lt ($1, $3) }
    | expr T_Ge expr     { Language.E_LNot (Language.E_Lt ($1, $3)) }
    | expr T_Gt expr     { Language.E_Lt ($3, $1) }
    | expr T_In expr     { Language.E_In ($1, $3) }
    | expr T_Like expr   { Language.E_Like ($1, $3) }

    | expr T_LAnd expr   { Language.E_LAnd ($1, $3) }
    | expr T_LOr expr    { Language.E_LOr  ($1, $3) }
    | T_LNot expr        { Language.E_LNot $2 }

    | expr T_BAnd expr   { Language.E_BAnd ($1, $3) }
    | expr T_BOr expr    { Language.E_BOr  ($1, $3) }
    | expr T_BXor expr   { Language.E_BXor ($1, $3) }
    | T_BNot expr        { Language.E_BNot $2 }

    | T_Exists expr      { Language.E_Exists $2 }

    | T_Ident T_Assign expr  { Language.E_Assign ($1, $3) }
    | T_Unset T_Ident { Language.E_Unset $2 }
    | T_If expr T_Then function_exprs T_Else function_exprs T_Fi
	{ Language.E_IfThenElse ($2, $4, $6) }
    | T_If expr T_Then function_exprs T_Fi
	{ Language.E_IfThenElse ($2, $4, []) }
    | T_While expr T_Do function_exprs T_Done
	{ Language.E_While ($2, $4) }
    | T_Break    { Language.E_Break }
    | T_Continue { Language.E_Continue }

    | T_Function T_LeftPar args T_RightPar T_LeftBrace function_exprs T_RightBrace
	                 { Language.E_Function ($3, $6) }
    | expr T_LeftPar expr_list T_RightPar { Language.E_Apply ($1, $3) }
    | T_Return expr { Language.E_Return (Some $2) }
    | T_Return { Language.E_Return None }
 
    | T_LeftBracket expr_list T_RightBracket { Language.E_List $2 }

    | expr T_Cons expr   { Language.E_Cons ($1, $3) }
    | expr T_Period T_Ident { Language.E_GetField ($1, $3) }
    | expr T_Period T_Ident T_FieldAssign expr { Language.E_SetField ($1, $3, $5) }

args:
    | /* empty */          { [] }
    | T_Ident              { [$1] }
    | T_Ident T_Comma args { $1::$3 }

expr_list: 
    | /* empty */            { [] }
    | expr                   { [$1] }
    | expr T_Comma expr_list { $1::$3 }

exprs:
    | T_Eof       { [] }
    | /* empty */ { [] }
    | expr T_Eof  { [$1] }
    | expr        { [$1] }
    | expr T_SemiColumn exprs { $1::$3 }

function_expr:
    | expr { $1 }
    | T_Local args { Language.E_Local $2 }

function_exprs:
    | /* empty */ { [] }
    | function_expr        { [$1] }
    | function_expr T_SemiColumn function_exprs { $1::$3 }
