open Parsifal
open BasePTypes
open PTypes

alias int8 = uint8
alias int16 = uint16
alias int24 = uint24
alias int32 = uint32 (* SHAME! *)


type varuint = int

let parse_varuint n input = match n with
  | 1 -> parse_uint8 input
  | 2 -> parse_uint16 input
  | 3 -> parse_uint24 input
  | 4 -> parse_uint32 input
  | _ -> failwith "invalid parameter n"

let dump_varuint n buf v = match n with
  | 1 -> dump_uint8 buf v
  | 2 -> dump_uint16 buf v
  | 3 -> dump_uint24 buf v
  | 4 -> dump_uint32 buf v
  | _ -> failwith "invalid parameter n"

let value_of_varuint n = VSimpleInt n




struct dvi_pre = {
  i : uint8;
  num : uint32;
  den : uint32;
  mag : uint32;
  comment : string[uint8];
}

struct dvi_bop = {
  counts : array(10) of uint32;
  previous_bop : int32;
}

struct fnt_def [both_param sz] = {
  k : varuint[sz];
  font_checksum : binstring(4);
  at_size : uint32;
  design_size : uint32;
  area_name_len : uint8;
  font_name_len : uint8;
  area_name : string(area_name_len);
  font_name : string(font_name_len);
}

struct dvi_post = {
  final_bop : int32;
  num_dup : uint32;
  den_dup : uint32;
  mag_dup : uint32;
  post_l : uint32;
  post_u : uint32;
  max_stack_depth : uint16;
  n_pages : uint16;
}

struct dvi_post_post = {
  post_pointer : int32;
  post_post_i : uint8;
  post_post_magic : magic("\xdf\xdf\xdf\xdf");
  post_post_padding : binstring
}


enum opcode (8, UnknownVal OP_Opcode) =
| 128 -> OP_set1, "set1"
| 129 -> OP_set2, "set2"
| 130 -> OP_set3, "set3"
| 131 -> OP_set4, "set4"
| 132 -> OP_set_rule, "set_rule"
| 133 -> OP_put1, "put1"
| 134 -> OP_put2, "put2"
| 135 -> OP_put3, "put3"
| 136 -> OP_put4, "put4"
| 137 -> OP_put_rule, "put_rule"
| 138 -> OP_nop, "nop"
| 139 -> OP_bop, "bop"
| 140 -> OP_eop, "eop"
| 141 -> OP_push, "push"
| 142 -> OP_pop, "pop"
| 143 -> OP_right1, "right1"
| 144 -> OP_right2, "right2"
| 145 -> OP_right3, "right3"
| 146 -> OP_right4, "right4"
| 147 -> OP_w0, "w0"
| 148 -> OP_w1, "w1"
| 149 -> OP_w2, "w2"
| 150 -> OP_w3, "w3"
| 151 -> OP_w4, "w4"
| 152 -> OP_x0, "x0"
| 153 -> OP_x1, "x1"
| 154 -> OP_x2, "x2"
| 155 -> OP_x3, "x3"
| 156 -> OP_x4, "x4"
| 157 -> OP_down1, "down1"
| 158 -> OP_down2, "down2"
| 159 -> OP_down3, "down3"
| 160 -> OP_down4, "down4"
| 161 -> OP_y0, "y0"
| 162 -> OP_y1, "y1"
| 163 -> OP_y2, "y2"
| 164 -> OP_y3, "y3"
| 165 -> OP_y4, "y4"
| 166 -> OP_z0, "z0"
| 167 -> OP_z1, "z1"
| 168 -> OP_z2, "z2"
| 169 -> OP_z3, "z3"
| 170 -> OP_z4, "z4"
| 235 -> OP_fnt1, "fnt1"
| 236 -> OP_fnt2, "fnt2"
| 237 -> OP_fnt3, "fnt3"
| 238 -> OP_fnt4, "fnt4"
| 239 -> OP_xxx1, "xxx1"
| 240 -> OP_xxx2, "xxx2"
| 241 -> OP_xxx3, "xxx3"
| 242 -> OP_xxx4, "xxx4"
| 243 -> OP_fnt_def1, "fnt_def1"
| 244 -> OP_fnt_def2, "fnt_def2"
| 245 -> OP_fnt_def3, "fnt_def3"
| 246 -> OP_fnt_def4, "fnt_def4"
| 247 -> OP_pre, "pre"
| 248 -> OP_post, "post"
| 249 -> OP_post_post, "post_post"
| 250 -> OP_Undefined, "Undefined opcode"
| 251 -> OP_Undefined, "Undefined opcode"
| 252 -> OP_Undefined, "Undefined opcode"
| 253 -> OP_Undefined, "Undefined opcode"
| 254 -> OP_Undefined, "Undefined opcode"
| 255 -> OP_Undefined, "Undefined opcode"


type dvi_string = int * string
let parse_dvi_string n_chars s _input = n_chars, s
let dump_dvi_string _ _ = ()
let value_of_dvi_string (_, s) = VString (s, false)


union dvi_command_detail [enrich] (UnknownCommand) =
| OP_set1 -> DVIString of dvi_string (1; parse_string 1 input)
| OP_set2 -> DVIString of dvi_string (2; parse_string 2 input)
| OP_set3 -> DVIString of dvi_string (3; parse_string 3 input)
| OP_set4 -> DVIString of dvi_string (4; parse_string 4 input)
| OP_set_rule -> SetRule of array(2) of uint32
| OP_put1 -> Put1 of uint8
| OP_put2 -> Put2 of uint16
| OP_put3 -> Put3 of uint24
| OP_put4 -> Put4 of uint32
| OP_put_rule -> PutRule of array(2) of uint32
| OP_nop -> NoOperation
| OP_bop -> BeginningOfPage of dvi_bop
| OP_eop -> EndOfPage
| OP_push -> Push
| OP_pop -> Pop
| OP_right1 -> Right1 of int8
| OP_right2 -> Right2 of int16
| OP_right3 -> Right3 of int24
| OP_right4 -> Right4 of int32
| OP_w0 -> W0
| OP_w1 -> W1 of int8
| OP_w2 -> W2 of int16
| OP_w3 -> W3 of int24
| OP_w4 -> W4 of int32
| OP_x0 -> X0
| OP_x1 -> X1 of int8
| OP_x2 -> X2 of int16
| OP_x3 -> X3 of int24
| OP_x4 -> X4 of int32
| OP_down1 -> Down1 of int8
| OP_down2 -> Down2 of int16
| OP_down3 -> Down3 of int24
| OP_down4 -> Down4 of int32
| OP_y0 -> Y0
| OP_y1 -> Y1 of int8
| OP_y2 -> Y2 of int16
| OP_y3 -> Y3 of int24
| OP_y4 -> Y4 of int32
| OP_z0 -> Z0
| OP_z1 -> Z1 of int8
| OP_z2 -> Z2 of int16
| OP_z3 -> Z3 of int24
| OP_z4 -> Z4 of int32
| OP_Opcode 171 -> FntNum1
| OP_Opcode 172 -> FntNum2
| OP_Opcode 173 -> FntNum3
| OP_Opcode 174 -> FntNum4
| OP_Opcode 175 -> FntNum5
| OP_Opcode 176 -> FntNum6
| OP_Opcode 177 -> FntNum7
| OP_Opcode 178 -> FntNum8
| OP_Opcode 179 -> FntNum9
| OP_Opcode 180 -> FntNum10
| OP_Opcode 181 -> FntNum11
| OP_Opcode 182 -> FntNum12
| OP_Opcode 183 -> FntNum13
| OP_Opcode 184 -> FntNum14
| OP_Opcode 185 -> FntNum15
| OP_Opcode 186 -> FntNum16
| OP_Opcode 187 -> FntNum17
| OP_Opcode 188 -> FntNum18
| OP_Opcode 189 -> FntNum19
| OP_Opcode 190 -> FntNum20
| OP_Opcode 191 -> FntNum21
| OP_Opcode 192 -> FntNum22
| OP_Opcode 193 -> FntNum23
| OP_Opcode 194 -> FntNum24
| OP_Opcode 195 -> FntNum25
| OP_Opcode 196 -> FntNum26
| OP_Opcode 197 -> FntNum27
| OP_Opcode 198 -> FntNum28
| OP_Opcode 199 -> FntNum29
| OP_Opcode 200 -> FntNum30
| OP_Opcode 201 -> FntNum31
| OP_Opcode 202 -> FntNum32
| OP_Opcode 203 -> FntNum33
| OP_Opcode 204 -> FntNum34
| OP_Opcode 205 -> FntNum35
| OP_Opcode 206 -> FntNum36
| OP_Opcode 207 -> FntNum37
| OP_Opcode 208 -> FntNum38
| OP_Opcode 209 -> FntNum39
| OP_Opcode 210 -> FntNum40
| OP_Opcode 211 -> FntNum41
| OP_Opcode 212 -> FntNum42
| OP_Opcode 213 -> FntNum43
| OP_Opcode 214 -> FntNum44
| OP_Opcode 215 -> FntNum45
| OP_Opcode 216 -> FntNum46
| OP_Opcode 217 -> FntNum47
| OP_Opcode 218 -> FntNum48
| OP_Opcode 219 -> FntNum49
| OP_Opcode 220 -> FntNum50
| OP_Opcode 221 -> FntNum51
| OP_Opcode 222 -> FntNum52
| OP_Opcode 223 -> FntNum53
| OP_Opcode 224 -> FntNum54
| OP_Opcode 225 -> FntNum55
| OP_Opcode 226 -> FntNum56
| OP_Opcode 227 -> FntNum57
| OP_Opcode 228 -> FntNum58
| OP_Opcode 229 -> FntNum59
| OP_Opcode 230 -> FntNum60
| OP_Opcode 231 -> FntNum61
| OP_Opcode 232 -> FntNum62
| OP_Opcode 233 -> FntNum63
| OP_Opcode 234 -> FntNum64
| OP_fnt1 -> Fnt1 of uint8
| OP_fnt2 -> Fnt2 of uint16
| OP_fnt3 -> Fnt3 of uint24
| OP_fnt4 -> Fnt4 of uint32
| OP_xxx1 -> Comment1 of string[uint8]
| OP_xxx2 -> Comment2 of string[uint16]
| OP_xxx3 -> Comment3 of string[uint24]
| OP_xxx4 -> Comment4 of string[uint32]
| OP_fnt_def1 -> FntDef of fnt_def[1]
| OP_fnt_def2 -> FntDef of fnt_def[2]
| OP_fnt_def3 -> FntDef of fnt_def[3]
| OP_fnt_def4 -> FntDef of fnt_def[4]
| OP_pre -> Preamble of dvi_pre
| OP_post -> Postamble of dvi_post
| OP_post_post -> EndOfPostamble of dvi_post_post
| OP_Opcode c -> DVIString of dvi_string(0; String.make 1 (char_of_int c))


struct dvi_command = {
  opcode : opcode;
  command : dvi_command_detail (opcode);
}

alias dvi_file = list of dvi_command
