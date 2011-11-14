(* Guillaume Valadon <guillaume.valadon@ssi.gouv.fr *)
(* Olivier Levillain <olivier.levillain@ssi.gouv.fr> *)

(* * * *

  Data that is found in MRT dumps that we parsed so far.

  The MRT format is described in the following IETF draft:
    http://tools.ietf.org/html/draft-ietf-grow-mrt

  BGP messages are described in RFC4721

  BGP attributes are listed in
    http://www.iana.org/assignments/bgp-parameters/bgp-parameters.xml

 * * * *)


exception MRTParsingError of string
exception MRTPrintingError of string
exception SubError of string


type ip_address = IPv4 of string     (* binary: 4 bytes *)
                | IPv6 of string     (* binary: 16 bytes *)
		| UnknownIP of int


type prefix = Prefix of ip_address * int


type asn = ASN16 of int32
         | ASN32 of int32


type peer_entry = PeerEntry of string * ip_address * asn  (* TODO OL: Should the string be an ip address ? *)
                | UnknownPeerEntry of int


type path_segment = AS_SET of asn list
                  | AS_SEQUENCE of asn list
		  | Unknown_AS_PATH_TYPE of int


type afi_type = INET
              | INET6
	      | UnknownAFI of int


type safi_type = UNICAST_FORWARDING
               | MULTICAST_FORWARDING
	       | UnknownSAFIType of int


(** The declaration order is the sort order. *)
type bgp_attributes = BGPAttributeORIGIN of int * int                                          (*  1 *)
                    | BGPAttributeAS_PATH of int * path_segment list                           (*  2 *)
                    | BGPAttributeAS4_PATH of int * path_segment list                          (* 17 *)
                    | BGPAttributeNEXT_HOP of int * string                                     (*  3 *)  (* TODO OL: Should the string be an ip address ? *)
                    | BGPAttributeMULTI_EXIT_DISC of int * int                                 (*  4 *)
		    | BGPAttributeATOMIC_AGGREGATE of int                                      (*  6 *)
                    | BGPAttributeAGGREGATOR of int * int * string                             (*  7 *)  (* TODO OL: Should the string be an ip address ? *)
                    | BGPAttributeMP_REACH_NLRI of int * afi_type * safi_type * ip_address list * prefix list (* 14 *)
                    | BGPAttributeMP_REACH_NLRI_abbreviated of int * ip_address list           (* 14 *)
                    | BGPAttributeMP_UNREACH_NLRI of int * afi_type * safi_type * prefix list (* 15 *)
                    | BGPAttributeCOMMUNITY of int * (int * int) list                          (*  8 *)
                    | BGPAttributeUnknown of int * int


type rib_entry = RIBEntry of int * int * int * bgp_attributes list


type table_dump_v2 = PEER_INDEX_TABLE of string * string * peer_entry list (* 13 1 *)  (* TODO OL: Should the first string be an ip address ? *)
	           | RIB_IPV4_UNICAST of int * prefix * rib_entry list     (* 13 2 *)
	           | RIB_IPV6_UNICAST of int * prefix * rib_entry list     (* 13 4 *)


type bgp_messages = BGP_UPDATE of prefix list * bgp_attributes list * prefix list (* 2 *)
                  | BGP_KEEPALIVE                                                 (* 4 *)
                  | BGP_UNKNOWN of int


type bgp4mp = MESSAGE     of asn * asn * int * ip_address * ip_address * bgp_messages (* 16 1 *)
	    | MESSAGE_AS4 of asn * asn * int * ip_address * ip_address * bgp_messages (* 16 4 *)


type mrt_types = TABLE_DUMP_v2 of table_dump_v2 (* 13 *)
	       | BGP4MP of bgp4mp (* 16 *)
               | Unknown of int * int * string


type mrt = MRTHeader of int * mrt_types
