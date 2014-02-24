open BasePTypes

struct answer_dump [top] = {
  ad_ip : PTypes.ipv4;
  ad_port : uint16;
  ad_name : string[uint16];
  ad_client_hello_type : uint8;
  ad_msg_type : uint8;
  ad_content : binstring[uint32]
}


type error = unit
let parse_error err_msg _ = Parsifal.not_implemented err_msg
let dump_error _ () = Parsifal.not_implemented "error"
let value_of_error () = Parsifal.not_implemented "error"

union ipv4_or_6 [enrich] (UnparsedIPType of error("UnparsedIPType")) =
  | 4 -> AD_IPv4 of PTypes.ipv4
  | 6 -> AD_IPv6 of PTypes.ipv6

struct answer_dump_v2 [top] = {
  ip_type : uint8;
  ip_addr : ipv4_or_6(ip_type);
  port : uint16;
  name : string[uint16];
  campaign : uint32;
  msg_type : uint8;   (* This field has been kept for compatibility reasons *)
  timestamp : uint64;
  content : binstring[uint32]
}



let v2_of_v1 ?timestamp a = {
  ip_type = 4;
  ip_addr = AD_IPv4 a.ad_ip;
  port = a.ad_port;
  name = a.ad_name;
  campaign = a.ad_client_hello_type;
  timestamp = Parsifal.pop_opt Int64.zero timestamp;
  msg_type = a.ad_msg_type;
  content = a.ad_content;
}

let v1_of_v2 a = match a with
  | { ip_addr = AD_IPv4 ip } ->
    {
      ad_ip = ip;
      ad_port = a.port;
      ad_name = a.name;
      ad_client_hello_type = a.campaign;
      ad_msg_type = a.msg_type;
      ad_content = a.content;
    }
  | _ -> failwith "Unsupported IP type for v1 answer dump."


let string_of_v2_ip = function
  | AD_IPv4 ipv4 -> PTypes.string_of_ipv4 ipv4
  | AD_IPv6 ipv6 -> PTypes.string_of_ipv6 ipv6
  | UnparsedIPType _ -> "Unsupported_IP_type"
