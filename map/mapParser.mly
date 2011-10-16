%token T_LeftPar T_RightPar T_LeftBrace T_RightBrace T_LeftBracket T_RightBracket T_Comma
%token T_Plus T_Minus T_Mult T_Div T_Mod
%token T_Equal T_Neq T_Le T_Lt T_Ge T_Gt T_In T_Like
%token T_LAnd T_LOr T_LNot
%token T_BAnd T_BOr T_BNot T_BXor
%token T_If T_Then T_Else T_Fi
%token T_While T_Do T_Done T_Break T_Continue
%token T_Assign
%token T_SemiColumn
%token T_Eof
%token T_TypeOf
%token T_Function T_Return T_Local
%token <bool> T_Bool
%token <int> T_Int
%token <string> T_Ident
%token <MapLang.string_token list> T_String

%right T_TypeOf T_Return T_Assign
%left T_SemiColumn T_LeftPar T_RightPar T_Comma
%left T_LOr
%left T_LAnd
%left T_LNot
%left T_Equal T_Neq T_Le T_Lt T_Ge T_Gt T_In T_Like
%left T_Plus T_Minus
%left T_Mult T_Div T_Mod
%left T_BOr T_BXor
%left T_BAnd
%left T_BNot
%nonassoc T_UMinus


%start exprs
%type <MapLang.expression list> exprs

%%

expr:
    | T_Bool     { MapLang.E_Bool $1 }
    | T_Int      { MapLang.E_Int $1 }
    | T_String   { MapLang.E_String $1 }
    | T_Ident    { MapLang.E_Var $1 }

    | T_LeftPar expr T_RightPar { $2 }

    | expr T_Plus expr   { MapLang.E_Plus ($1, $3) }
    | expr T_Minus expr  { MapLang.E_Minus ($1, $3) }
    | expr T_Mult expr   { MapLang.E_Mult ($1, $3) }
    | expr T_Div expr    { MapLang.E_Div ($1, $3) }
    | expr T_Mod expr    { MapLang.E_Mod ($1, $3) }
    | T_Minus expr %prec T_UMinus { MapLang.E_Minus (MapLang.E_Int 0, $2) }

    | expr T_Equal expr  { MapLang.E_Equal ($1, $3) }
    | expr T_Neq expr    { MapLang.E_LNot (MapLang.E_Equal ($1, $3)) }
    | expr T_Le expr     { MapLang.E_LNot (MapLang.E_Lt ($3, $1)) }
    | expr T_Lt expr     { MapLang.E_Lt ($1, $3) }
    | expr T_Ge expr     { MapLang.E_LNot (MapLang.E_Lt ($1, $3)) }
    | expr T_Gt expr     { MapLang.E_Lt ($3, $1) }
    | expr T_In expr     { MapLang.E_In ($1, $3) }
    | expr T_Like expr   { MapLang.E_Like ($1, $3) }

    | expr T_LAnd expr   { MapLang.E_LAnd ($1, $3) }
    | expr T_LOr expr    { MapLang.E_LOr  ($1, $3) }
    | T_LNot expr        { MapLang.E_LNot $2 }

    | expr T_BAnd expr   { MapLang.E_BAnd ($1, $3) }
    | expr T_BOr expr    { MapLang.E_BOr  ($1, $3) }
    | expr T_BXor expr   { MapLang.E_BXor ($1, $3) }
    | T_BNot expr        { MapLang.E_BNot $2 }

    | T_TypeOf expr      { MapLang.E_TypeOf $2 }

    | T_Ident T_Assign expr  { MapLang.E_Assign ($1, $3) }
    | T_If expr T_Then exprs T_Else exprs T_Fi
	{ MapLang.E_IfThenElse ($2, $4, $6) }
    | T_If expr T_Then exprs T_Fi
	{ MapLang.E_IfThenElse ($2, $4, []) }
    | T_While expr T_Do exprs T_Done
	{ MapLang.E_While ($2, $4) }
    | T_Break    { MapLang.E_Break }
    | T_Continue { MapLang.E_Continue }

    | T_Function T_LeftPar args T_RightPar T_LeftBrace exprs T_RightBrace
	                 { MapLang.E_Function ($3, $6) }
    | expr T_LeftPar expr_list T_RightPar { MapLang.E_Apply ($1, $3) }
    | T_Local T_Ident  { MapLang.E_Local $2 }
    | T_Return expr { MapLang.E_Return $2 }

    | T_LeftBracket expr_list T_RightBracket { MapLang.E_List $2 }

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
