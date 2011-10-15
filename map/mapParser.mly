%token T_LeftPar T_RightPar T_LeftBrace T_RightBrace
%token T_Plus T_Minus T_Mult T_Div T_Mod
%token T_Equal T_Neq T_Le T_Lt T_Ge T_Gt T_In T_Like
%token T_LAnd T_LOr T_LNot
%token T_BAnd T_BOr T_BNot T_BXor
%token T_If T_Then T_Else T_Fi
%token T_Assign
%token T_SemiColumn
%token T_Eof
%token T_Print
%token T_TypeOf T_Parse T_Open
%token T_Function
%token T_Return
%token <int> T_Int
%token <string> T_Ident
%token <MapLang.string_token list> T_String

%left T_SemiColumn
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

%start commands
%type <MapLang.command list> commands

%%

expr:
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
    | T_Parse expr       { MapLang.E_Parse $2 }
    | T_Open expr        { MapLang.E_Open $2 }

    | T_Function T_LeftBrace commands T_RightBrace
	                 { MapLang.E_Function $3 }
    | expr T_LeftPar T_RightPar { MapLang.E_Apply $1 }


command:
    | T_Ident T_Assign expr  { MapLang.C_Assign ($1, $3) }
    | T_If expr T_Then commands T_Else commands T_Fi
	{ MapLang.C_IfThenElse ($2, $4, $6) }
    | T_If expr T_Then commands T_Fi
	{ MapLang.C_IfThenElse ($2, $4, []) }
    | T_Print expr  { MapLang.C_Print $2 }
    | T_Return expr { MapLang.C_Return $2 }
    | expr          { MapLang.C_Print $1 }

commands:
    | T_Eof          { [] }
    | /* empty */    { [] }
    | command T_Eof  { [$1] }
    | command        { [$1] }
    | command T_SemiColumn commands { $1::$3 }
