open Parsifal
open BasePTypes
open PTypes

alias association_id = uint16
alias keyid = uint32

alias reference_clock_code [novalueof] = string(4)

let value_of_reference_clock_code refcode =
    let value =
        match refcode with
        | "GOES" -> "GEOS Geosynchroneous Orbit Environment Satellite"
        | "GPS\x00" -> "GPS Global Position System"
        | "GAL\x00" -> "GAL Galileo Positioning System"
        | "PPS\x00" -> "PPS Generic pulse-per-second"
        | "IRIG" -> "IRIG Inter-Range Instrumentation Group"
        | "WWVB" -> "WWVB LF Radio WWVB FR. Collins, CO 60 kHz"
        | "DCF\x00" -> "DCF LF Radio DCF77 Mainflingen, DE 77.5 kHz"
        | "HBG\x00" -> "HBG LF Radio HBG Prangins, HB 75 kHz"
        | "MSF\x00" -> "MSF LF Radio MSF Anthorn, UK 60 kHz"
        | "JJY\x00" -> "JJY LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz"
        | "LORC" -> "LORC MF Radio LORAN C station, 100 kHz"
        | "TDF\x00" -> "TDF MF Radio Allouis, FR 162 kHz"
        | "CHU\x00" -> "CHU HF Radio CHU Ottawa, Ontario"
        | "WWV\x00" -> "WWV HF Radio Ft. Collins, CO"
        | "WWVH" -> "WWVH HF Radio WWVH Kauai, HI"
        | "NIST" -> "NIST NIST telephone modem"
        | "ACTS" -> "ACTS NIST telephone modem"
        | "USNO" -> "USNO USNO telephone modem"
        | "PTB\x00" -> "PTB European telephone modem"
        | _ -> refcode
    in
    VString(value, true)

enum mode_enum (3, UnknownVal ReservedMode) =
| 1 -> SymmetricActiveMode, "1 Symmetric Active"
| 2 -> SymmetricPassiveMode, "2 Symmetric Passive"
| 3 -> ClientMode, "3 Client"
| 4 -> ServerMode, "4 Server"
| 5 -> BroadcastMode, "5 Broadcast"
| 6 -> NTPControlMsgMode, "6 NTP control message"
| 7 -> PrivateUseMode, "7 Reserved for private use"

enum host_mode_enum (8, UnknownVal UnspecifiedMode) =
| 1 -> SymmetricActiveMode, "1 Symmetric Active"
| 2 -> SymmetricPassiveMode, "2 Symmetric Passive"
| 3 -> ClientMode, "3 Client"
| 4 -> ServerMode, "4 Server"
| 5 -> BroadcastMode, "5 Broadcast"
| 6 -> NTPControlMsgMode, "6 NTP control message"
| 7 -> PrivateUseMode, "7 Reserved for private use"
| 8 -> BClientMode, "8 BClient"

(* RFC1305 %B.1 *)
enum opcode(5, UnknownVal ReservedOpcode) =
| 1 -> ReadStatOpCode, "Read status command/response"
| 2 -> ReadVarOpCode, "Read variables command/response"
| 3 -> WriteVarOpCode, "Write variables command/response"
| 4 -> ReadClockVarOpCode, "Read clock variables command/response"
| 5 -> WriteClockVarOpCode, "Write clock variables command/response"
| 6 -> SetTrapOpCode, "Set trap address/port command/response"
| 7 -> TrapOpCode, "Trap response"

(* RFC1305 %B.2.3 *)
enum clock_source (6, UnknownVal ReservedSource) =
| 0 -> UnspecifiedSource
| 1 -> CalibratedAtomicClock, "Calibrated atomic clock (e.g. HP 5061)"
| 2 -> VLFRadio, "VLF (band 4) or LF (band 5) radio (e.g. OMEGA, WWVB)"
| 3 -> HFRadio, "HF (band 7) radio (e.g. CHU, MSF, WWVH)"
| 4 -> UHFSat, "UHF (band 9) satellite (e.g. GOES, GPS)"
| 5 -> LocalNet, "local net (e.g. DCN, TSP, DTS)"
| 6 -> UDPNTP, "UDP/NTP"
| 7 -> UDPTIME, "UDP/TIME"
| 8 -> Manual, "Eyeball and wrist watch"
| 9 -> TelephoneModem, "Telephone modem (e.g. NIST)"

(* RFC1305 %B.2.1 *)
enum evt_code (4, UnknownVal ReservedEvtCode) =
| 0 -> UnspecifiedEvtCode, "Unspecified event"
| 1 -> SysRestart, "System restart"
| 2 -> SysFault, "System or Hardware Fault"
| 3 -> SysNewStatus, "System new status word (leap bits or synchronization change)"
| 4 -> SysNewSyncSource, "System new synchronization source or stratum (sys.peer or sys.stratum change)"
| 5 -> SysClockReset, "System clock reset (offset correction exceeds CLOCK.MAX)"
| 6 -> SysInvalidTime, "System invalid time or date"
| 7 -> SysClockExn, "System clock exception"

enum leap_indicator (2, UnknownVal UnknownLeapIndicator) =
| 0 -> NoWarning, "No warning"
| 1 -> Plus1Sec, "Last minute of the day has 61 seconds"
| 2 -> Minus1Sec, "Last minute of the day has 59 seconds"
| 3 -> UnknownState, "Unknown (clock unsychronized)"

(* RFC1305 %B.2.1 *)
struct system_status_word = {
    leap_indicator: leap_indicator;
    clock_source: clock_source;
    evt_counter: bit_int[4];
    evt_code: evt_code;
}

(* RFC1305 %B.2.2 *)
struct peer_status = {
    peer_config: bit_bool;
    peer_authenable: bit_bool;
    peer_authentic: bit_bool;
    peer_reach: bit_bool;
    reserved: bit_bool;
}

(* RFC1305 %B.2.2 *)
enum peer_selection (3, UnknownVal ReservedPeerSelection) =
| 0 -> RejectedSelection, "Rejected"
| 1 -> PassedSanityChecks, "Passed sanity checks"
| 2 -> PassedCandidateChecks, "Passed candidate checks"
| 3 -> PassedOutlyerChecks, "Passed outlyer checks"
| 4 -> CurrentSyncSourceDistExceeded, "Current synchronization source; max distance exceeded"
| 6 -> CurrentSyncSourceDistOkay, "Current synchronization source; max distance okay"

(* RFC1305 %B.2.2 *)
enum peer_evt_code (4, UnknownVal ReservedEvtCode) =
| 0 -> UnspecifiedEvtCode, "Unspecified"
| 1 -> PeerIPErr, "Peer IP error"
| 2 -> PeerAuthFail, "Peer authentication failure"
| 3 -> PeerUnreach, "Peer unreachable"
| 4 -> PeerReach, "Peer now reachable"
| 5 -> PeerClockExn, "Peer clock exception"

(* RFC1305 %B.2.2 *)
struct peer_status_word = {
    peer_status: peer_status;
    peer_selection: peer_selection;
    peer_evt_counter: bit_int[4];
    peer_evt_code: peer_evt_code;
}

(* RFC1305 %B.2.3 *)
enum clock_status (8, UnknownVal ReservedClockStatus) =
| 0 -> ClockNominalStatus, "Clock operating within nominals"
| 1 -> ReplyTimeoutStatus, "Reply timeout"
| 2 -> BadReplyFormatStatus, "Bad reply format"
| 3 -> HardwareOrSoftwareFault, "Hardware of software fault"
| 4 -> PropagationFailure, "Propagation failure"
| 5 -> BadDateFormatOrVal, "Bad date format or value"
| 6 -> BadTimeFormatOrVal, "Bad time format or value"

(* RFC1305 %B.2.3 *)
struct clock_status_word = {
    clock_status: clock_status;
    clock_evt_code: uint8; (* FM: XXX I don't understand the content of this field. Unparsed at the moment *)
}

(* RFC1305 %B.2.4 *)
enum error_code (8, UnknownVal ReservedError) =
| 0 -> UnspecifiedError, "Unspecified"
| 1 -> AuthFail, "Authentication failure"
| 2 -> InvalidMsgLenOrFormat, "Invalid message length or format"
| 3 -> InvalidOpCode, "Invalid opcoode"
| 4 -> UnknownAssocID, "Unknown association ID"
| 5 -> UnknownVarName, "Unknown variable name"
| 6 -> InvalidVarVal, "Invalid variable value"
| 7 -> AdminProhibited, "Administratively prohibited"

(* RFC1305 %B.2.4 *)
struct error_status_word = {
    error_code: error_code;
    placeholder: uint8;
}

(* RFC1305 %B.2 *)
type status_words = | SystemStatusWord of system_status_word
                    | PeerStatusWord of peer_status_word
                    | ClockStatusWord of clock_status_word
                    | ErrorStatusWord of error_status_word
                    | UnparsedStatusWord of binstring

let parse_status_words response error opcode association_id unparsed_status input =
    let new_input = get_in_container input "status_word_container" unparsed_status in
    match response, error, opcode, association_id with
        | true, false, ReadStatOpCode, 0
        | true, false, ReadVarOpCode, 0 -> SystemStatusWord (parse_system_status_word new_input)
        | true, false, ReadStatOpCode, _
        | true, false, ReadVarOpCode, _
        | true, false, WriteVarOpCode, _ -> PeerStatusWord (parse_peer_status_word new_input)
        | _, false, ReadClockVarOpCode, _
        | _, false, WriteClockVarOpCode, _ -> ClockStatusWord (parse_clock_status_word new_input)
        | true, true, _, _ -> ErrorStatusWord (parse_error_status_word new_input)
        | _ -> (UnparsedStatusWord unparsed_status)

let value_of_status_words v =
    match v with
    | SystemStatusWord x -> value_of_system_status_word x
    | PeerStatusWord x -> value_of_peer_status_word x
    | ClockStatusWord x -> value_of_clock_status_word x
    | ErrorStatusWord x -> value_of_error_status_word x
    | UnparsedStatusWord x -> VString(x, true)

let compute_len_of_data_in_control_packet len input =
    let remlen = input.cur_length - input.cur_offset in
    if len > remlen then
        (* XXX FM: Do we really want to accept that the len is nonesense and still parse it? *)
        remlen
    else
        min 468 len

let compute_padding_len_in_control_packet len =
    let rem = len mod 4 in
    if rem <> 0 then
        4 - rem
    else
        0

(* RFC1305 %B.3 Read status *)
struct assoc_status = {
    association_id: association_id;
    status_word: peer_status_word;
}
alias associations_statuses = list of assoc_status

union control_data [enrich] (UnparsedData of binstring) =
| ReadStatOpCode, 0         -> BinStatusData of associations_statuses
| ReadStatOpCode, _         -> StatusData of string
| ReadVarOpCode, _          -> VariablesRead of string
| WriteVarOpCode, _         -> VariablesWritten of string
| ReadClockVarOpCode, _     -> ClockRead of string
| WriteClockVarOpCode, _    -> ClockWritten of string
| SetTrapOpCode, _          -> SetTrap of string
| TrapOpCode, _             -> GotTrap of string

(* RFC 1305 %B.1 *)
struct control_packet = {
    null_magic: bit_int[2];
    version: bit_int[3];
    mode: mode_enum;
    response: bit_bool;
    error: bit_bool;
    more: bit_bool;
    opcode: opcode;
    sequence: uint16;
    unparsed_status: binstring(2);
    association_id: association_id;
    parse_field status: status_words(response; error; opcode; association_id; unparsed_status);
    offset: uint16;
    len: uint16;
    data: container(compute_len_of_data_in_control_packet len input) of control_data(opcode, association_id);
    optional padding: binstring(compute_padding_len_in_control_packet len);
    optional authenticator: binstring(12);
}

struct authentication_material = {
    keyid: keyid;
    digest: binstring(16);
}

enum implementation_id (8, UnknownVal UnknownImplementation) =
| 0 -> UNIV, "UNIV"
| 2 -> OldXNTPD, "Old NTPd pre IPv6"
| 3 -> XNTPD, "NTPd post IPv6"
| 255 -> ReservedImplId, "Reserved ID"

enum mod7reqcode (8, UnknownVal UnknownReqCode) =
| 0 -> ReqPeerList, "Request Peer List"
| 1 -> ReqPeerListSum, "Request summary of all peers"
| 2 -> ReqPeerInfo, "Request standard peer info"
| 3 -> ReqPeerStats, "Request peer statistics"
| 4 -> ReqSysInfo, "Request peer information"
| 5 -> ReqSysStats, "Request system statistics"
| 6 -> ReqIOStats, "Request I/0 stats"
| 7 -> ReqMemStats, "Request memory statistics"
| 8 -> ReqLoopInfo, "Request information from the loop filter"
| 9 -> ReqTimerStats, "Request time statistics"
| 10 -> ReqConfig, "Request to configure a new peer"
| 11 -> ReqUnconfig, "Request to unconfigure an existing peer"
| 12 -> ReqSetSysFlag, "Request to set system flags"
| 13 -> ReqClearSysFlag, "Request to clear system flags"
| 14 -> ReqMonitor, "Monitor (unused)"
| 15 -> ReqNoMonitor, "No Monitor (unused)"
| 16 -> ReqGetRestrict, "Request restrict list"
| 17 -> ReqResAddFlags, "Request flags addition to restrict list"
| 18 -> ReqResSubFlags, "Request flags removal to restrict list"
| 19 -> ReqUnrestrict, "Request entry removal from retrict list"
| 20 -> ReqMonGetlist, "Return data collected by monitor"
| 21 -> ReqResetStats, "Request reset of statistics counters"
| 22 -> ReqResetPeer, "Request reset of peer statistics counters"
| 23 -> ReqRereadKeys, "Request reread of the encryption key files"
| 24 -> ReqDoDirtyHack, "Do some dirty hack (unused)"
| 25 -> ReqDontDirtyHack, "Dont do some dirty hack (unused)"
| 26 -> ReqTrustKey, "Request a trusted key addition"
| 27 -> ReqUntrustKey, "Request a trusted key removal"
| 28 -> ReqAuthInfo, "Request authentication information"
| 29 -> ReqTraps, "Request currently set traps list"
| 30 -> ReqAddTrap, "Request trap addition"
| 31 -> ReqClearTrap, "Request trap clearance"
| 32 -> ReqRequestKey, "Define a new request keyid"
| 33 -> ReqControlKey, "Define a new control keyid"
| 34 -> ReqGetControlStats, "Get statistics from the control module"
| 35 -> ReqGetLeapInfo, "Get leap info (unused)"
| 36 -> ReqGetClockInfo, "Get clock information"
| 37 -> ReqGetClockFudge, "Get clock fudge factors"
| 38 -> ReqGetKernel, "Get kernel ppl/pps infos"
| 39 -> ReqGetClockBugInfo, "Get clock debugging info"
| 41 -> ReqSetPrecision, "Set precision (unused)"
| 42 -> ReqMonGetList1, "Return collected v1 monitor data"
| 43 -> ReqHostnameAssocID, "Return hostname association id"
| 44 -> ReqIfStats, "Get interface statistics"
| 45 -> ReqIfReload, "Request interface list reloading"


enum mod7errcode (4, UnknownVal UnspecifiedError) =
| 0 -> NoError, "No error"
| 1 -> IncompatibleImplNum, "Incompatible implementation number"
| 2 -> UnimplReqCode, "Unimplemented request code"
| 3 -> FmtErr, "Format error (wrong data items, data size, packet size etc.)"
| 4 -> NoData, "No data available (e.g. request for details on unknown peer)"
| 5 | 6 -> DontKnow, "I don't know"
| 7 -> AuthFail, "Authentication failure"


alias ip4_mask = ipv4
alias ip6_mask = ipv6


(* mod7_peer_info_flags should be 8 bits, but it seeps ntpd developers
   try to have a 9-th flag, iburst (in ntp_request.h, INFO_IBURST_FLAG
   is 0x100... which is out of range of a u_char. This is why we may need
   a 16-bit version of these flags. *)

struct mod7_peer_info_flags [param long_version]= {
    placeholder: conditional_container(long_version) of list(7) of bit_bool;
    iburst: conditional_container(long_version) of bit_bool;
    short_list: bit_bool;
    sel_candidate: bit_bool;
    authenable: bit_bool;
    prefer: bit_bool;
    refclock: bit_bool;
    burst: bit_bool;
    syspeer: bit_bool;
    config: bit_bool;
}

alias mod7_peer_info_flags_16bits = mod7_peer_info_flags(true)
alias mod7_peer_info_flags_8bits = mod7_peer_info_flags(false)


type uint32_boolean = bool
let parse_uint32_boolean input =
    (parse_uint32 input) <> 0

let dump_uint32_boolean buf b =
    dump_uint32 buf (if b then 1 else 0)
let value_of_uint32_boolean b = VBool b

struct mod7_req_peer_list = {
    addr: ipv4;
    port: uint16;
    hmode: host_mode_enum;
    flags: mod7_peer_info_flags_8bits;
    v6_flag: uint32_boolean;
    placeholder: uint32;
    v6addr: ipv6;
}

(* include/ntp_fp.h *)
struct ul_fp = {
    integral_part: uint32;
    fractional_part: uint32;
}
struct sl_fp = {
    integral_part: sint32;
    fractional_part: sint32;
}

alias s_fp = sint32
alias l_fp = ul_fp
alias u_fp = uint32

struct mod7_req_peer_list_sum = {
    dst_addr: ipv4;
    src_addr: ipv4;
    src_port: uint16;
    stratum: uint8;
    host_polling_interval: sint8;
    peer_polling_interval: sint8;
    reachability: uint8;
    flags: mod7_peer_info_flags_8bits;
    hmode: host_mode_enum;
    delay: s_fp;
    offset: l_fp;
    dispersion: u_fp;
    v6_flag: uint32_boolean;
    placeholder: uint32;
    dstv6addr: ipv6;
    srcv6addr: ipv6;
}

struct mod7_req_peer_info = {
    dstaddr: ipv4;
    srcaddr: ipv4;
    src_port: uint16;
    flags: mod7_peer_info_flags_8bits;
    leap: uint8; (* XXX FM: this is a leap_indicator with 6 useless bits *)
    hmode: host_mode_enum;
    pmode: host_mode_enum;
    stratum: uint8;
    peer_polling_interval: uint8;
    host_polling_interval: uint8;
    precision: sint8;
    version: uint8; (* sometimes, it is only a 3 bit long value... *)
    placeholder: uint8;
    reachability: uint8; (* XXX FM Is this a boolean? *)
    unreachability: uint8; (* XXX FM Is this a boolean? *)
    flash: uint8;
    ttl: uint8;
    flash2: uint16;
    association_id: association_id;
    keyid: keyid;
    placeholder_pkeyid: uint32;
    reference_id: reference_clock_code;
    timer: uint32;
    rootdelay: s_fp;
    rootdispersion: u_fp;
    ref_timestamp: l_fp;
    origin_timestamp_org: l_fp;
    receive_timestamp_rec: l_fp;
    transmit_timestamp_xmt: l_fp;
    filtdelay: list(8) of s_fp; (* 8 is the NTP_SHIFT value defined in include/ntp.h from version 4.2.6.p5 *)
    filtoffset: list(8) of l_fp;
    order: list(8) of uint8;
    delay: s_fp;
    dispersion: u_fp;
    offset: l_fp;
    selectdisp: u_fp;
    placeholder2: list(7) of sint32;
    estbdelay: s_fp;
    v6_flag: uint32_boolean;
    placeholder3: uint32;
    dstv6addr: ipv6;
    srcv6addr: ipv6;
}

struct mod7_req_peer_stats = {
    dstaddr: ipv4;
    srcaddr: ipv4;
    src_port: uint16;
    flags: mod7_peer_info_flags_16bits;
    time_reset: uint32;
    time_received: uint32;
    time_tosend: uint32;
    time_reachable: uint32;
    sent: uint32;
    placeholder: uint32;
    processed: uint32;
    placeholder2: uint32;
    badauth: uint32;
    bogus_origin: uint32;
    old_packet: uint32; (* duplicates *)
    placeholder3: list(2) of uint32;
    bad_dispersion: uint32;
    bad_ref_time: uint32;
    placeholder4: uint32;
    candidate: uint8;
    placeholder5: list(3) of uint8;
    v6_flag: uint32_boolean;
    placeholder6: uint32;
    dstv6addr: ipv6;
    srcv6addr: ipv6;
}

struct mod7_loop_info = {
    last_offset: l_fp;
    drift_comp: l_fp;
    compliance: uint32;
    watchdog_timer: uint32;
}

struct mod7_sys_info_flags = {
    pps_sync: bit_bool;
    cal: bit_bool;
    filegen: bit_bool;
    monitor: bit_bool;
    kernel: bit_bool;
    ntp: bit_bool; (* what else? *)
    authenticate: bit_bool;
    bclient: bit_bool; (* XXX FM: broadcast client ? *)
}

struct mod7_sys_info = {
    peer: ipv4;
    peer_mode: host_mode_enum;
    leap: uint8; (* XXX FM : is that the same as the leap indicators but on 8 bits? *)
    stratum: uint8;
    precision: sint8;
    rootdelay: s_fp;
    rootdispersion: u_fp;
    reference_id: reference_clock_code;
    reference_time: l_fp;
    sys_polling_interval: uint32;
    flags: mod7_sys_info_flags;
    placeholder: list(3) of uint8;
    broadcast_offset: s_fp;
    frequency: s_fp;
    authdelay: ul_fp;
    stability: u_fp;
    v6_flag: uint32_boolean;
    placeholder2: uint32;
    peer_v6_addr: ipv6;
}

struct mod7_sys_stats = {
    time_since_restart: uint32;
    time_since_reset: uint32;
    access_denied_cnt: uint32;
    old_version_pckt_cnt: uint32;
    new_version_pckt_cnt: uint32;
    unknown_version_pckt_cnt: uint32;
    bad_len_or_format_cnt: uint32;
    processed_pckt_cnt: uint32;
    bad_auth_cnt: uint32;
    received_pckt_cnt: uint32;
    rate_exceeded_cnt: uint32;
}

struct mod7_mem_stats = {
    time_since_reset: uint32;
    total_peer_mem: uint16;
    free_peer_mem: uint16;
    find_peer_calls: uint32;
    allocations: uint32;
    demobilizations: uint32;
    hash_count: list(128) of uint8; (* 128 is from NTP_HASH_SIZE defined in include/ntp.h *)
}

struct mod7_io_stats = {
    time_since_reset: uint32;
    total_recv_bufs: uint16;
    free_recv_bufs: uint16;
    full_recv_bufs: uint16;
    low_water: uint16; (* number of times we've added buffers ; comment extracted from source code *)
    dropped_pckt_cnt: uint32;
    ignored_pckt_cnt: uint32;
    received_pckt_cnt: uint32;
    sent_pckt_cnt: uint32;
    not_sent_pckt_cnt: uint32;
    interrupts_cnt: uint32;
    int_received: uint32;
}

struct mod7_timer_stats = {
    time_since_reset: uint32;
    alarms_cnt: uint32;
    overflows_cnt: uint32;
    xmt_calls: uint32;
}

struct mod7_conf_flags = {
    placeholder: list(2) of bit_bool; (* two highest flags are undefined in ntp 4.2.6.p5 *)
    skey: bit_bool;
    noselect: bit_bool;
    iburst: bit_bool;
    burst: bit_bool;
    prefer: bit_bool;
    authenable: bit_bool;
}

struct mod7_conf_peer = {
    peer_addr: ipv4;
    hmode: host_mode_enum;
    version: uint8; (* sometimes it is only 3 bit long... *)
    min_host_polling_interval: uint8;
    max_host_polling_interval: uint8;
    flags: mod7_conf_flags;
    ttl: uint8;
    placeholder: uint16;
    keyid: keyid;
    pubkey_filename: string(256);
    v6_flag: uint32_boolean;
    placeholder2: uint32;
    peer_v6_addr: ipv6;
}

struct mod7_conf_unpeer = {
    peer_addr: ipv4;
    v6_flag: uint32_boolean;
    peer_v6_addr: ipv6;
}

struct mod7_sys_flags = {
    placeholder: list(24) of bit_bool; (* undefined flags *)
    cal: bit_bool;
    auth: bit_bool;
    filegen: bit_bool;
    monitor: bit_bool;
    kernel: bit_bool;
    ntp: bit_bool; (* what else ? *)
    pps: bit_bool;
    bclient: bit_bool;
}


(* As for mod7_peer_info_flags, some developers of NTPd think that the
   bit field should be 32 bits, others 16 bits... it varies following
   the structure... there is only 13 bits defined anyway... *)

struct mod7_restrict_flags [param four_bytes_version] = {
    placeholder: conditional_container(four_bytes_version) of list(16) of bit_bool;
    placeholder2: list(3) of bit_bool;
    timeout: bit_bool; (* timeout this entry *)
    ms_sntp: bit_bool; (* enable ms-sntp authentication *)
    kod: bit_bool; (* send kiss of death packet *)
    lp_trap: bit_bool; (* low priority trap *)
    no_trap: bit_bool; (* set trap denied *)
    no_modify: bit_bool;  (* modify denied *)
    no_query: bit_bool; (* mod 6/7 denied *)
    limited: bit_bool; (* rate limited *)
    no_peer: bit_bool; (* new association denied *)
    version: bit_bool; (* version mismatch *)
    auth_required: bit_bool; (* called in code source DONTTRUST *)
    dont_serve: bit_bool; (* access denied *)
    ignore: bit_bool; (* ignore packet *)
}

alias mod7_restrict_flags_16bits = mod7_restrict_flags(false)
alias mod7_restrict_flags_32bits = mod7_restrict_flags(true)


struct mod7_match_flags = {
    placeholder: list(2) of bit_bool;
    ntp_only: bit_bool;
    interface: bit_bool;
    placeholder2: list(12) of bit_bool;
}

struct mod7_info_restrict = {
    addr: ipv4;
    mask: ip4_mask;
    count: uint32;
    flags: mod7_restrict_flags_16bits;
    mflags: mod7_match_flags;
    v6_flag: uint32_boolean;
    placeholder: uint32;
    addr6: ipv6;
    mask6: ip6_mask;
}

struct mod7_set_restrict = {
    addr: ipv4;
    mask: ip4_mask;
    flags: mod7_restrict_flags_16bits;
    mflags: mod7_match_flags;
    v6_flag: uint32_boolean;
    addr6: ipv6;
    mask6: ip6_mask;
}

struct mod7_padded_mode_enum = {
    placeholder: list(5) of bit_bool;
    mode: mode_enum;
}

struct mod7_monlist_gen [param monlist1_version] = {
    last_pckt_timestamp: uint32;
    first_pckt_timestamp: uint32;
    restrict_flags: mod7_restrict_flags_32bits;
    pckt_recv_cnt: uint32;
    host_addr: ipv4;

    dest_addr: conditional_container(monlist1_version) of ipv4;
    (* XXX FM: it could be mod7_peer_info_flags BUT mod7_peer_info_flags
       are only 8 bits long (or 9... it depends... ; so don't know ; don't enrich *)
    flags: conditional_container(monlist1_version) of uint32;

    last_pckt_src_port: uint16;
    last_pckt_mode: mod7_padded_mode_enum;
    version: uint8; (* sometimes it is only 3 bit long... *)
    v6_flag: uint32_boolean;
    placeholder: uint32;
    host_v6_addr: ipv6;

    dest_v6_addr: conditional_container(monlist1_version) of ipv6;
}

alias mod7_monlist = mod7_monlist_gen(false)
alias mod7_monlist_1 = mod7_monlist_gen(true)

struct mod7_reset_flags = {
    placeholder: list(25) of bit_bool;
    ctl: bit_bool;
    auth: bit_bool;
    timer: bit_bool;
    mem: bit_bool;
    sys: bit_bool;
    io: bit_bool;
    all_peers: bit_bool;
}

struct mod7_info_auth = {
    time_reset: uint32;
    keys_cnt: uint32;
    free_keys_cnt: uint32;
    key_lookups_cnt: uint32;
    key_not_found_cnt: uint32;
    encryptions_cnt: uint32;
    decryptions_cnt: uint32;
    expired_keys_cnt: uint32;
    uncached_keys_usage_cnt: uint32;
}

struct mod7_trap_flags = {
    placeholder: list(29) of bit_bool;
    configured: bit_bool;
    non_priority: bit_bool;
    in_use: bit_bool;
}

struct mod7_get_traps = {
    src_addr: ipv4;
    dst_addr: ipv4;
    dst_port: uint16;
    sequence_num: uint16;
    last_set_timestamp: uint32;
    orig_set_timestamp: uint32;
    resets_cnt: uint32;
    flags: mod7_trap_flags;
    v6_flag: uint32_boolean;
    src_addr6: ipv6;
    dst_addr6: ipv6;
}

struct mod7_set_trap = {
    src_addr: ipv4;
    dst_addr: ipv4;
    dst_port: uint16;
    placeholder: uint16;
    v6_flag: uint32_boolean;
    src_addr6: ipv6;
    dst_addr6: ipv6;
}

struct mod7_control_stats = {
    time_reset: uint32;
    req_cnt: uint32;
    bad_pckt_cnt: uint32;
    sent_responses_cnt: uint32;
    sent_fragments_cnt: uint32;
    sent_errors_cnt: uint32;
    too_short_input_cnt: uint32;
    recv_responses_cnt: uint32;
    recv_fragments_cnt: uint32;
    recv_errors_cnt: uint32;
    recv_bad_offset_cnt: uint32;
    recv_bad_version_cnt: uint32;
    recv_too_short_data_cnt: uint32;
    bad_opcode_cnt: uint32;
    sent_async_msg: uint32;
}

struct mod7_clock_info = { (* XXX FM: No information about the fields... TODO *)
    clockadr: uint32;
    clock_type: uint8;
    flags: uint8;
    last_evt: uint8;
    cur_status: uint8;
    polls: uint32;
    noresponse: uint32;
    badformat: uint32;
    baddata: uint32;
    time_started: uint32;
    fudgetime: list(2) of l_fp;
    fudgeval1: sint32;
    fudgeval2: uint32;
}

struct mod7_clock_fudge = { (* XXX FM: no comment... no information to enrich but the source code... *)
    clockadr: uint32;
    which: uint32;
    fudgetime: l_fp;
    flags: uint32;
}

struct mod7_get_kernel = { (* XXX FM: no comment... no information to enrich but the source code... *)
    offset: sint32;
    freq: sint32;
    maxerror: sint32;
    esterror: sint32;
    kernel_status: uint16;
    shift: uint16;
    constant: sint32;
    precision: sint32;
    tolerance: sint32;
    ppsfreq: sint32;
    jitter: sint32;
    stabil: sint32;
    jitcnt: sint32;
    calcnt: sint32;
    errcnt: sint32;
    stbcnt: sint32;
}

struct mod7_clock_bug_info = {
    clockadr: uint32;
    nvalues: uint8;
    ntimes: uint8;
    svalues: uint16;
    stimes: uint32;
    values: list(16) of uint32;
    times: list(32) of l_fp;
}

struct mod7_dns_assoc = {
    peer_addr: ipv4;
    association_id: association_id;
    hostname: string(26); (* sounds soooooo much like a bad idea! *)
}

union mod7_payload [enrich] (UnparsedPayload) =
| ReqPeerList, false -> ReqPeerListPayload of binstring
| ReqPeerList, true -> AnsPeerListPayload of mod7_req_peer_list

| ReqPeerListSum, false -> ReqPeerListSumPayload of binstring
| ReqPeerListSum, true -> AnsPeerListSumPayload of mod7_req_peer_list_sum

(* This type of queries requires a list of peers in input. Therefore
   the payload type is different in a query and in an answer *)
| ReqPeerInfo, false -> ReqPeerInfoPayload of mod7_req_peer_list
| ReqPeerInfo, true -> AnsPeerInfoPayload of mod7_req_peer_info

(* This type of queries requires a list of peers in input. Therefore
   the payload type is different in a query and in an answer *)
| ReqPeerStats, false -> ReqPeerStatsPayload of mod7_req_peer_list
| ReqPeerStats, true -> AnsPeerStatsPayload of mod7_req_peer_stats

| ReqSysInfo, false -> ReqSysInfoPayload of binstring
| ReqSysInfo, true -> AnsSysInfoPayload of mod7_sys_info

| ReqSysStats, false -> ReqSysStatsPayload of binstring
| ReqSysStats, true -> AnsSysStatsPayload of mod7_sys_stats

| ReqIOStats, false -> ReqIOStatsPayload of binstring
| ReqIOStats, true -> AnsIOStatsPayload of mod7_io_stats

| ReqMemStats, false -> ReqMemStatsPayload of binstring
| ReqMemStats, true -> AnsMemStatsPayload of mod7_mem_stats

| ReqLoopInfo, false -> ReqLoopInfoPayload of binstring
| ReqLoopInfo, true -> AnsLoopInfoPayload of mod7_loop_info

| ReqTimerStats, false -> ReqTimerStatsPayload of binstring
| ReqTimerStats, true -> AnsTimerStatsPayload of mod7_timer_stats

| ReqConfig, _ -> ReqConfigPayload of mod7_conf_peer
| ReqUnconfig, _ -> ReqUnconfigPayload of mod7_conf_unpeer
| ReqSetSysFlag, _ -> ReqSetSysFlagsPayload of mod7_sys_flags
| ReqClearSysFlag, _ -> ReqClearSysFlagsPayload of mod7_sys_flags
(*
| ReqMonitor ->
| ReqNoMonitor ->
*)
| ReqGetRestrict, _ -> ReqGetRestrictPayload of mod7_info_restrict (* XXX Verify the parameter if this is a query *)
| ReqResAddFlags, _ -> ReqResAddFlagsPayload of mod7_set_restrict (* XXX Verify the parameter if this is a query *)
| ReqResSubFlags, _ -> ReqResSubFlagsPayload of mod7_set_restrict (* XXX Verify the parameter if this is a query *)
(*| ReqUnrestrict -> *) (* has no payload *)
| ReqMonGetlist, _ -> ReqMonGetListPayload of mod7_monlist
| ReqResetStats, _ -> ReqResetStatsPayload of mod7_reset_flags(* XXX Verify the parameter if this is a query *)
(*
| ReqResetPeer ->
| ReqRereadKeys ->
| ReqDoDirtyHack ->
| ReqDontDirtyHack ->
| ReqTrustKey ->
| ReqUntrustKey ->
*)
| ReqAuthInfo, _ -> ReqAuthInfoPayload of mod7_info_auth (* XXX Verify the parameter if this is a query *)
| ReqTraps, _ -> ReqTrapsPayload of mod7_get_traps (* XXX Verify the parameter if this is a query *)
| ReqAddTrap, _ -> ReqAddTrapPayload of mod7_set_trap (* XXX Verify the parameter if this is a query *)
| ReqClearTrap, _ -> ReqClearTrapPayload of mod7_set_trap (* XXX Verify the parameter if this is a query *)
(*
| ReqRequestKey ->
| ReqControlKey ->
*)
| ReqGetControlStats, _ -> ReqGetControlStatsPayload of mod7_control_stats (* XXX Verify the parameter if this is a query *)
(*
| ReqGetLeapInfo ->
*)
(* This type of queries requires a list of peers in input. Therefore
   the payload type is different in a query and in an answer *)
| ReqGetClockInfo, false -> ReqGetClockInfoPayload of mod7_req_peer_list
| ReqGetClockInfo, true -> AnsGetClockInfoPayload of mod7_clock_info

| ReqGetClockFudge, false -> ReqGetClockFudgePayload of binstring
| ReqGetClockFudge, true -> AnsGetClockFudgePayload of mod7_clock_fudge

| ReqGetKernel, false -> ReqGetKernelPayload of binstring
| ReqGetKernel, true -> AnsGetKernelPayload of mod7_get_kernel

(* This type of queries requires a list of peers in input. Therefore
   the payload type is different in a query and in an answer *)
| ReqGetClockBugInfo, false -> ReqGetClockBugInfoPayload of mod7_req_peer_list
| ReqGetClockBugInfo, true -> AnsGetClockBugInfoPayload of mod7_clock_bug_info
(*
| ReqSetPrecision ->
*)
| ReqMonGetList1, _ -> ReqMonGetList1Payload of mod7_monlist_1

(*
(* commented because I cannot find actual code to handle this in ntpd source *)
| ReqHostnameAssocID -> ReqHostnameAssocIDPayload of mod7_dns_assoc
| ReqIfStats -> ReqIfStatsPayload of mod7_if_stats (* cannot be parsed...  because of the use of union*)
| ReqIfReload ->
*)

(* Specific NTPd; Source du format : Qualys*)
struct ntpd_private_packet = {
    response: bit_bool;
    more: bit_bool;
    version: bit_int[3];
    mode: mode_enum;
    authenticated: bit_bool;
    sequence: bit_int[7];
    implementation: implementation_id;
    reqcode: mod7reqcode;
    errcode: mod7errcode;
(*    parse_checkpoint XXX Check that errcode=0 if response values false *)
    data_item_count: bit_int[12];
    mbz: bit_magic(mk_list 4 false);
    data_item_len: bit_int[12];
    data: list(data_item_count) of container(data_item_len) of mod7_payload(reqcode,response);
    authentication_material: conditional_container(response && authenticated) of authentication_material;
}

(* RFC5905 *)
struct extension_fields = {
    field_type: uint16;
    field_len: uint16;
    value: binstring(field_len);
}

alias kiss_of_death_code [novalueof] = string(4)

let value_of_kiss_of_death_code kod =
    let value =
        match kod with
        | "ACST" -> "ACST Association belongs to a unicast server"
        | "AUTH" -> "AUTH Server authentication failed"
        | "AUTO" -> "AUTO Autokey sequence failed"
        | "BCST" -> "BCST Association belongs to a broadcast server"
        | "CRYP" -> "CRYP Cryptographic authentication or identification failed"
        | "DENY" -> "DENY Access denied by remote server"
        | "DROP" -> "DROP Lost peer in symmetric mode"
        | "RSTR" -> "RSTR Access denied due to local policy"
        | "INIT" -> "INIT Association not yet synchronized"
        | "MCST" -> "MCST Association belongs to a dynamically discovered server"
        | "NKEY" -> "NKEY No key found"
        | "RATE" -> "RATE Rate exceeded"
        | "RMOT" -> "RMOT Alteration of association from a remote host running ntpdc"
        | "STEP" -> "STEP Step changed in sys time has occured but the association has not yet resynchronized"
        | _ -> kod
    in
    VString(value, true)

union reference [enrich] (UnparsedReference) =
    | 0 -> KoDPacket of kiss_of_death_code
    | 1 -> ReferenceClock of reference_clock_code

(* This struct expects to be enclosed in a container or to be the last thing to parse in the document *)
struct time_packet = {
    leap_indicator: leap_indicator;
    version: bit_int[3];
    mode: mode_enum;
    stratum: uint8;
    poll: uint8;
    precision: uint8;
    root_delay: uint32;
    root_dispersion: uint32;
    reference_id: reference(stratum);
    reference_timestamp: uint64;
    origin_timestamp: uint64;
    receive_timestamp: uint64;
    transmit_timestamp: uint64;
    optional extension_fields: container(input.cur_length - input.cur_offset - 20) of list of extension_fields;
        (* 20 corresponds to the len of key_id + digest that are mandatory if extensions are in use) *)
    authentication_material: conditional_container(extension_fields <> None) of authentication_material;
}


type ntp_packet = TimePacket of time_packet
                | ControlPacket of control_packet
                | NTPDPrivatePacket of ntpd_private_packet

let parse_ntp_packet input =
    let fst_byte = peek_uint8 input in
    let mode = fst_byte land 0x7 in
    match mode with
        | 0 | 1 | 2 | 3 | 4 | 5 -> TimePacket (parse_time_packet input)
        | 6 -> ControlPacket (parse_control_packet input)
        | 7 -> NTPDPrivatePacket (parse_ntpd_private_packet input)
        | _ -> failwith "Should not happen as value is coded on 3 bit"

let dump_ntp_packet buf = function
    | TimePacket p -> dump_time_packet buf p
    | ControlPacket p -> dump_control_packet buf p
    | NTPDPrivatePacket p -> dump_ntpd_private_packet buf p

let value_of_ntp_packet =  function
    | TimePacket p -> value_of_time_packet p
    | ControlPacket p -> value_of_control_packet p
    | NTPDPrivatePacket p -> value_of_ntpd_private_packet p

