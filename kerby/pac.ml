open Parsifal
open BasePTypes
open PTypes
open Asn1PTypes
open Asn1Engine


type align = unit
let parse_align n input =
  (*Printf.printf "ALIGN: %d\n" input.cur_offset;*)
  drop_bytes ((n - (input.cur_offset mod n)) mod n) input

(* FIXME: duplicated *)
type 'a cspe = 'a
let parse_cspe n parse_fun input = parse_asn1 (C_ContextSpecific, true, T_Unknown n) parse_fun input
let dump_cspe n dump_fun buf o = dump_asn1 (C_ContextSpecific, true, T_Unknown n) dump_fun buf o
let value_of_cspe = BasePTypes.value_of_container

let signature_length = function
  | 0xf -> 12
  | 0x10 -> 12
  | 0xffffff76 -> 16
  | _ -> 0

struct pac_signature_data = {
  signature_type : uint32le;
  signature_value : binstring(signature_length signature_type);
  optional rodcidentifier : uint16le;
  optional junk : binstring
}

(* Adapt date print, seems we have a loss in precision in microseconds ? *)
let date_string_of_tm tm =
  Printf.sprintf "%d/%2.2d/%2.2d %d:%2.2d:%2.2d"
    (1900 + tm.Unix.tm_year)
    tm.Unix.tm_mon
    tm.Unix.tm_mday
    tm.Unix.tm_hour
    tm.Unix.tm_min
    tm.Unix.tm_sec

(* Ugly Windows time conversion *)
let convert_time low high =
    if ((low <> 0xffffffff) && (high <> 0x7fffffff)) then
    let windows_tick = Big_int.big_int_of_int 10000000 in
    let sec_to_unix_epoch = Big_int.big_int_of_int 11644473600 in
    let bigl = Big_int.big_int_of_int low in
    let bigh = Big_int.big_int_of_int high in
    let tmp = Big_int.shift_left_big_int bigh 32 in
    let res = Big_int.add_big_int tmp bigl in
    let time = Big_int.sub_big_int (Big_int.div_big_int res windows_tick) sec_to_unix_epoch in
    let gtime = Unix.gmtime (Big_int.float_of_big_int time) in
    (date_string_of_tm gtime);
    else
      "Unspecified date";
    
(* FILETIME should be transformed into usable time repr. *)
struct filetime = {
  ftime_low : uint32le;
  ftime_high : uint32le;
}

(* Custom print of date *)
let value_of_filetime s =
  match value_of_filetime s with
  | VRecord l -> VRecord (("@string_of", VString ((convert_time s.ftime_low s.ftime_high), false))::l)
  | v -> v (* TODO: Throw an exception? *)

(* Custom function to split using sep *)
let rec split_char sep str =
  try
    let i = String.index str sep in
    String.sub str 0 i ::
      split_char sep (String.sub str (i+1) (String.length str - i - 1))
  with Not_found ->
    [str]

(* Ugly split for UTF16 strings, we remove \x00 char and hope it works *)
type utf16_string = string
let parse_utf16_string len input =
  let saved_offset = input.cur_offset in
  let s = parse_string len input in
  try
    let res = split_char '\x00' s in

    if List.length res = 1
    then emit_parsing_exception false (CustomException "Unclean UTF16 String")
      { input with cur_offset = saved_offset };

    String.concat "" res;
  with Not_found -> s

let dump_utf16_string _ _ _ = not_implemented "dump_utf16_string"

let value_of_utf16_string s = VString (s, false)

struct pac_client_info = {
  client_id : filetime;
  name_length : uint16le;
  name : utf16_string(name_length);
}

(* UPN buffer *)
type upn_buffer = string

let parse_upn_buffer start offset size input =
  PTypes.parse_seek_offset (offset + start) input;
      let parsed_buffer = parse_utf16_string size input in
  (parsed_buffer)

let dump_upn_buffer _ _ = not_implemented "dump_upn_buffer"
let value_of_upn_buffer s = VString (s, false)

struct upn_dns_info = {
  parse_checkpoint upn_start : PTypes.save_offset;
  upn_length : uint16le;
  upn_offset : uint16le;
  dns_domain_name_length : uint16le;
  dns_domain_name_offset : uint16le;
  flags : uint32le;
  upn : upn_buffer(upn_start; upn_offset; upn_length);
  dns_domain_name : upn_buffer(upn_start; dns_domain_name_offset; dns_domain_name_length);
  upn_dns_info_FIXME : binstring (* spec does not indicate what follows *)
}

struct unicode_string = {
  length : uint16le;
  max_length : uint16le;
  lpointer : uint32le;
}

struct group_membership = {
  relative_id : uint32le;
  attribute_id : uint32le;
}

(* supposedly currently unused *)
struct user_session_key = {
  cipher_block : binstring(16);
}


(* used to read a utf16_string following the kerb_validation_info *)
struct read_string = {
  total_chars : uint32le;
  unused_chars : uint32le;
  used_chars : uint32le;
  skip : binstring(unused_chars*2); (* WTF *)
  value : utf16_string(used_chars*2);
}

let value_of_read_string s =
  match value_of_read_string s with
  | VRecord l -> VRecord (("@string_of", VString (s.value, false))::l)
  | v -> v (* TODO: Throw an exception? *)


struct rpc_sid_identifier_authority = {
  blork : magic("\x00\x00"); (* TODO: Sordid hack. This should be a uint48... *)
  value : uint32;
}

struct pi_sid = {
  revision : uint8;
  sub_authority_count : uint8;
  identifier_authority : rpc_sid_identifier_authority;
  sub_authority : list(sub_authority_count) of uint32le;
}

(* used to read a SID following the kerb_validation_info *)
struct read_sid = {
  parse_checkpoint : align(4);
  sid_size : uint32le;
  sid_value : pi_sid;
}

let string_of_read_sid sid =
  Printf.sprintf "S-%d-%d-%s"
    sid.sid_value.revision
    sid.sid_value.identifier_authority.value
    (String.concat "-" (List.map string_of_int sid.sid_value.sub_authority))

let value_of_read_sid sid =
  match value_of_read_sid sid with
  | VRecord l -> VRecord (("@string_of", VString (string_of_read_sid sid, false))::l)
  | v -> v (* TODO: Throw an exception? *)

(* used to read a KERB_SID_AND_ATTRIBUTES following the kerb_validation_info *)
struct read_kerb_sid_and_attributes = {
  pointer: uint32le;
  attributes: uint32le;
}

struct kerb_validation_info = {
  skip : binstring(20);
  logon_time : filetime;
  logoff_time : filetime;
  kickoff_time : filetime;
  password_last_set : filetime;
  password_can_change : filetime;
  password_must_change : filetime;
  effective_name : unicode_string; (* field1 *)
  full_name : unicode_string;
  logon_script : unicode_string;
  profile_path : unicode_string;
  home_directory : unicode_string;
  home_directory_drive : unicode_string;
  logon_count : uint16le;
  bad_password_count : uint16le;
  user_id : uint32le;
  primary_group_id : uint32le;
  group_count : uint32le;
  group_ids_pointer : uint32le;
  user_flags : uint32le;
  user_session_key : user_session_key; (* seems to be reserved *)
  logon_server : unicode_string;
  logon_domain_name : unicode_string;
  logon_domain_id_pointer : uint32le;
  skip1: binstring(8);
  user_account_control : uint32le;
  skip2: binstring(28);
  sid_count : uint32le;
  extra_sids_pointer : uint32le;
  resource_group_domain_sid_pointer : uint32le;
  resource_group_count : uint32le;
  resource_group_ids_pointer : uint32le; (* End of kerb_validation_info structure *)
  (* Here the real value are parsed *)
  effective_name_real : conditional_container (effective_name.lpointer > 0) of read_string; (* field1 real value *)
  full_name_real : conditional_container (full_name.lpointer > 0) of read_string;
  logon_script_real : conditional_container (logon_script.lpointer > 0 ) of read_string;
  profile_path_real : conditional_container (profile_path.lpointer > 0) of read_string;
  home_directory_real : conditional_container (home_directory.lpointer > 0) of read_string;
  home_directory_drive_real : conditional_container (home_directory_drive.lpointer > 0) of read_string;
  group_count_real : conditional_container (group_count > 0) of uint32le;
  group_ids_real : conditional_container (group_count > 0) of list(group_count) of group_membership;
  logon_server_real : conditional_container (logon_server.lpointer > 0) of read_string;
  logon_domain_name_real : conditional_container (logon_domain_name.lpointer > 0) of read_string;
  logon_domain_id_real : conditional_container ( logon_domain_id_pointer <> 0) of read_sid;
  extra_sids_count : conditional_container (extra_sids_pointer <> 0) of uint32le; (* should check if it match sid_count *)
  extra_sids_real : conditional_container (extra_sids_pointer <> 0) of list(pop_opt 0 extra_sids_count) of read_kerb_sid_and_attributes;
  extra_sids_real_values : conditional_container (extra_sids_pointer <> 0) of list(pop_opt 0 extra_sids_count) of read_sid;
  parse_checkpoint : align(8);
  resource_group_domain_sid_real : conditional_container (resource_group_count > 0) of read_sid;
  resource_group_count_real : conditional_container (resource_group_count > 0) of uint32le; (* should check if it match resource_group_count *)
  resource_group_ids_real : conditional_container (resource_group_count > 0) of list(resource_group_count) of group_membership;
}

union pactype_buffer [enrich] (UnparsedPactypeBuffer) =
| 0x1 -> LogonInformation of kerb_validation_info
| 0x6 -> ServerChecksum of pac_signature_data
| 0x7 -> KDCChecksum of pac_signature_data
| 0xa -> ClientNameAndTicketingInfo of pac_client_info
| 0xc -> UPNAndDNSInfo of upn_dns_info


type 'a sordid_container = 'a

let parse_sordid_container base offset size name parse_fun input =
  let saved_offset = PTypes.parse_save_offset input in
  PTypes.parse_seek_offset (base + offset) input;
  let res = parse_container size name parse_fun input in
  PTypes.parse_seek_offset saved_offset input;
  res

let dump_sordid_container _ _ _ = not_implemented "dump_sordid_container"

let value_of_sordid_container = value_of_container

struct pac_info_buffer [param pactype_start] = {
  ulType : uint32le;
  cbBufferSize : uint32le;
  offset : uint32le;
  hi_offset : uint32le;
  content : sordid_container(pactype_start;offset;cbBufferSize) of pactype_buffer(ulType)
}

struct ad_win2k_pac = {
  parse_checkpoint pactype_start : PTypes.save_offset;
  cBuffers : uint32le;
  version : uint32le;
  pac_info_buffers : list(cBuffers) of pac_info_buffer(pactype_start);
  parse_checkpoint : binstring;
}

(* KERB_AUTH_DATA_TOKEN_RESTRICTION-> 141 PARSING *)
enum lsap_token_integrity_flag_type (32, UnknownVal UnknownRestrictedFlag) =
  | 0  -> FULL_TOKEN
  | 1  -> UAC_RESTRICTED_TOKEN

(* 0x... values should be LittleEndian, reversed here *)
enum integrity_level (32, UnknownVal UnknownIntegrityLevel) =
  | 0x00000000  -> UNTRUSTED
  | 0x00100000  -> LOW
  | 0x00200000  -> MEDIUM
  | 0x00300000  -> HIGH
  | 0x00400000  -> SYSTEM
  | 0x00500000  -> PROTECTED_PROCESS

struct lsap_token_integrity = {
  flags : lsap_token_integrity_flag_type;
  token_integrity_level : integrity_level; (* client integrity level, flags should be parsed *)
  machine_id : binstring(32); (* random string identifing machine, should not be used *)
}

struct kerb_ad_restriction_entry_content = {
  restriction_type : cspe[0] of der_smallint;
  restriction : cspe[1] of octetstring_container of lsap_token_integrity;
}
asn1_alias kerb_ad_restriction_entries = seq_of kerb_ad_restriction_entry_content
asn1_alias kerb_ad_restriction_entry = seq_of kerb_ad_restriction_entries

(* KERB_LOCAL-> 142 PARSING *)
struct kerb_local = {
  kerb_local_value : binstring; (* deprectated since Win2k *)
}

(* AD_AUTH_DATA_AP_OPTIONS-> 143 PARSING *)
(* 0x... values should be LittleEndian, reversed here *)
enum ad_data_value (32, UnknownVal UnknownAdDataApOptions) =
  | 0x00400000 -> KERB_AP_OPTIONS_CBT

struct ad_auth_data_ap_options = {
  ad_data : ad_data_value;
}
