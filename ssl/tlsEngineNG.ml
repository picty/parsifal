open BasePTypes
open PTypes
open Lwt
open TlsEnums
open Tls
open TlsCrypto
open TlsDatabase
open Ssl2
open Parsifal


(**********************)
(* Record preparation *)
(**********************)

let mk_rec ct v content = { content_type = ct; record_version = v; record_content = content }

let extract_first_record enrich ctx recs =
  (* produce_raw_first_record only hands out records when the integrity bool is true *)
  let rec produce_raw_first_record accu recs =
    match accu, recs with
    | _, [] -> accu, []
    | None, (false, _)::_ -> None, recs
    | None, (true, r)::rs ->
      let content = POutput.create () in
      dump_record_content content r.record_content;
      let new_accu = Some (r.content_type, r.record_version, content) in
      (* CCS and Heartbeat messages should never be split/merged *)
      (* For Alert messages, it is debatable: for the moment, let's say they cannot be split/merged *)
      if r.content_type = CT_Handshake || r.content_type = CT_ApplicationData
      then produce_raw_first_record new_accu rs
      else new_accu, rs
    | Some (ct, v, content), (integrity, r)::rs ->
      if integrity && r.content_type = ct && r.record_version = v
      then begin
        dump_record_content content r.record_content;
        produce_raw_first_record accu rs
      end else accu, recs
  in

  match produce_raw_first_record None recs with
  | None, rs -> rs
  | Some (ct, v, content), rs ->
    let input_name = "Merged " ^ (string_of_tls_content_type ct) ^ " records"
    and rec_content = POutput.contents content in

    (* Here, we try to enrich the first record from the merged messages *)
    let new_input = input_of_string ~verbose:false ~enrich:enrich input_name rec_content in
    let saved_offset = parse_save_offset new_input in
    let res = match try_parse ~report:false (parse_record_content ctx ct) new_input with
      | None ->
        let first = mk_rec ct v (Unparsed_Record rec_content) in
        (true, first)::rs
      | Some res ->
	begin
	  match ctx, ct with
	  | Some context, CT_Handshake ->
	    let handshake_str = get_raw_value saved_offset new_input in
	    POutput.add_string context.future.f_handshake_messages handshake_str
	  | _ -> ()
	end;
        let first = mk_rec ct v res in
        let next =
          if (eos new_input)
          then rs
          else begin
            (* If we have not used all the contents of the merged records,
	       what to do depends of the content type: for AppData and HS,
	       we keep it; for CCS, Alert (this is debatable) and HB, we
	       throw an error *)
	    if ct = CT_Handshake || ct = CT_ApplicationData then begin
              let rem = parse_rem_binstring new_input in
              let next_record = mk_rec ct v (Unparsed_Record rem) in
              (true, next_record)::rs
	    end else failwith "Multiple messages in a record: this should only happen with Handshake and ApplicationData content types"
          end
        in (true, first)::next
    in
    res



(******************)
(* Global context *)
(******************)

type tls_global_context = {
  certs : X509.certificate list;
}



(********************)
(* Simple functions *)
(********************)

let update_with_client_hello ctx ch =
  (* TODO: Take the record version into account? *)
  ctx.future.proposed_versions <- (V_SSLv3, ch.client_version);
  ctx.future.f_client_random <- ch.client_random;
  ctx.future.f_session_id <- ch.client_session_id;
  ctx.future.proposed_ciphersuites <- ch.ciphersuites;
  ctx.future.proposed_compressions <- ch.compression_methods;
  (* TODO: extensions *)
  match ch.client_extensions with
  | None | Some [] -> ()
  | _ -> () (* For now, all extensions are ignored *)

let update_with_server_hello ctx sh =
  (* Checks? *)
  ctx.future.proposed_versions <- (sh.server_version, sh.server_version);
  ctx.current_version <- sh.server_version;
  ctx.future.proposed_ciphersuites <- [sh.ciphersuite];
  ctx.future.proposed_compressions <- [sh.compression_method];
  ctx.future.f_server_random <- sh.server_random;
  ctx.future.f_session_id <- sh.server_session_id;
  (* TODO: exts *)
  match sh.server_extensions with
  | None | Some [] -> ()
  | _ -> () (* "Extensions not supported for now" *)

let update_with_certificate ctx certs =
  ctx.future.f_certificates <- certs

let update_with_server_key_exchange ctx ske =
  ctx.future.f_server_key_exchange <- ske


(* Move the core of the function in TlsCrypto *)
let update_with_CCS dir ctx =
  match ctx.future.proposed_versions,
    ctx.future.proposed_ciphersuites,
    ctx.future.proposed_compressions with
    | (v1, v2), [cs_enum], [cm] ->
      if v1 <> v2 (* TODO *)
      then failwith "CCS received too early? version negotiation not done yet";
      ctx.current_version <- v1;
      let cs = find_csdescr cs_enum
      and randoms = (ctx.future.f_client_random, ctx.future.f_server_random) in
      ctx.current_ciphersuite <- cs;
      ctx.current_compression_method <- cm;
      ctx.current_randoms <- randoms;
      let prf = choose_prf v1 cs.prf in
      ctx.current_prf <- prf;
      let master_secret = match mk_master_secret prf randoms ctx.future.secret_info with
        | Tls.MasterSecret ms ->
          ctx.current_master_secret <- ms;
          Some ms
        | _ -> None
      in
      begin
        match master_secret, cs.enc, cs.mac, cm with
        | Some ms, ENC_Stream (SC_RC4, 128), MAC_HMAC hash_name, CM_Null ->
	  let hash_fun, hash_size = hmac_fun_of_name hash_name and key_material_length = 16 in
          begin
            match dir, ctx.direction, mk_key_block prf ms randoms [hash_size; hash_size; key_material_length; key_material_length] with
            | ClientToServer, _, [client_write_MAC_secret; _; client_write_key; _] ->
              (* TODO: Have something more efficient? *)
              ctx.current_c2s_seq_num := 0L;
              let c2s = rc4_decrypt hash_fun hash_size client_write_MAC_secret client_write_key ctx.current_c2s_seq_num
              and s2c = ctx.decrypt ServerToClient in
              ctx.decrypt <- (fun dir -> if dir = ClientToServer then c2s else s2c);
              let c2s = rc4_encrypt hash_fun hash_size client_write_MAC_secret client_write_key ctx.current_c2s_seq_num
              and s2c = ctx.encrypt ServerToClient in
              ctx.encrypt <- fun dir -> if dir = ClientToServer then c2s else s2c
            | ServerToClient, None, [_; server_write_MAC_secret; _; server_write_key] ->
              ctx.current_s2c_seq_num := 0L;
              let s2c = rc4_decrypt hash_fun hash_size server_write_MAC_secret server_write_key ctx.current_s2c_seq_num
              and c2s = ctx.decrypt ClientToServer in
              ctx.decrypt <- fun dir -> if dir = ServerToClient then s2c else c2s
            | _ -> () (* TODO: Other cases *)
          end
        | Some ms, ENC_CBC (BC_AES, key_bitlen), MAC_HMAC hash_name, CM_Null ->
          let hash_fun, hash_size = hmac_fun_of_name hash_name
	  and key_material_length = key_bitlen / 8 and iv_length = 16 in
          begin
            match dir, ctx.direction, mk_key_block prf ms randoms
              [hash_size; hash_size; key_material_length; key_material_length; iv_length; iv_length] with
              | ClientToServer, None, [client_write_MAC_secret; _; client_write_key; _; client_iv; _] ->
                (* TODO: Have something more efficient? *)
               ctx.current_c2s_seq_num := 0L;
               let c2s = aes_cbc_implicit_decrypt hash_fun hash_size client_write_MAC_secret client_iv client_write_key ctx.current_c2s_seq_num
                and s2c = ctx.decrypt ServerToClient in
                ctx.decrypt <- fun dir -> if dir = ClientToServer then c2s else s2c
              | ServerToClient, None, [_; server_write_MAC_secret; _; server_write_key; _; server_iv] ->
                ctx.current_s2c_seq_num := 0L;
                let s2c = aes_cbc_implicit_decrypt hash_fun hash_size server_write_MAC_secret server_iv server_write_key ctx.current_s2c_seq_num
                and c2s = ctx.decrypt ClientToServer in
                ctx.decrypt <- fun dir -> if dir = ServerToClient then s2c else c2s
              | _ -> () (* TODO: Other cases *)
          end
        | _ -> (* TODO *)
          match dir with
          | ClientToServer ->
            (* TODO: Have something more efficient? *)
            let c2s = unknown_decrypt ClientToServer
            and s2c = ctx.decrypt ServerToClient in
            ctx.decrypt <- (fun dir -> if dir = ClientToServer then c2s else s2c);
            ctx.current_c2s_seq_num := 0L
          | ServerToClient ->
            let s2c = unknown_decrypt ServerToClient
            and c2s = ctx.decrypt ClientToServer in
            ctx.decrypt <- (fun dir -> if dir = ServerToClient then s2c else c2s);
            ctx.current_s2c_seq_num := 0L
      end;
    | _, _::_, _ -> (* TODO *)
      failwith "CCS received too early? ciphersuite negotiation not done yet"
    | _, _, _::_ -> (* TODO *)
      failwith "CCS received too early? compression method negotiation not done yet"
    | _, _, _ -> (* TODO *)
      failwith "TODO"

let mk_alert_msg ctx alert_level alert_type = {
  content_type = CT_Alert;
  record_version = ctx.current_version;
  record_content = Alert {
    alert_level = alert_level;
    alert_type = alert_type;
  }
}

let mk_handshake_msg ctx hs_type hs_msg = {
  content_type = CT_Handshake;
  record_version = ctx.current_version;
  record_content = Handshake {
    handshake_type = hs_type;
    handshake_content = hs_msg
  }
}

let mk_ccs_msg ctx = {
  content_type = CT_ChangeCipherSpec;
  record_version = ctx.current_version;
  record_content = ChangeCipherSpec { change_cipher_spec_value = CCS_ChangeCipherSpec };
}


let mk_sni_client_ext accu ctx = match ctx.preferences.send_SNI, ctx.preferences.server_names with
  | false, _ | _, [] -> accu
  | true, ns ->
    let mk_name n = {sni_name_type = NT_HostName; sni_name = HostName n} in
    let sni = {
      extension_type = HE_ServerName;
      extension_data = ServerName (ClientServerName (List.map mk_name ns))
    } in
    sni::accu

(* TODO: Add support for Elliptic Curves *)
let mk_client_exts ctx =
  mk_sni_client_ext [] ctx

let mk_client_hello ctx =
  ctx.future.proposed_versions <- ctx.preferences.acceptable_versions;
  ctx.future.proposed_ciphersuites <- ctx.preferences.acceptable_ciphersuites;
  ctx.future.proposed_compressions <- ctx.preferences.acceptable_compressions;
  let client_random = String.make 32 '\x00' in (* TODO! *)
  let extensions =
    if ctx.preferences.use_extensions
    then begin
      match mk_client_exts ctx with
      | [] -> None    (* This is debatable *)
      | es -> Some es
    end else None
  in
  let ch = {
    client_version = snd ctx.future.proposed_versions;
    client_random = client_random;
    client_session_id = ""; (* TODO? *)
    ciphersuites = ctx.future.proposed_ciphersuites;
    compression_methods = ctx.future.proposed_compressions;
    client_extensions = extensions
  } in
  update_with_client_hello ctx ch;
  mk_handshake_msg ctx HT_ClientHello (ClientHello ch)

let rec find_first_match preferred_list other_list =
  match preferred_list with
  | [] -> None
  | x::xs ->
    if List.mem x other_list
    then Some x
    else find_first_match xs other_list

let mk_server_hello ctx =
  let pref_cs, other_cs, pref_cm, other_cm =
    if ctx.preferences.directive_behaviour
    then ctx.preferences.acceptable_ciphersuites, ctx.future.proposed_ciphersuites,
      ctx.preferences.acceptable_compressions, ctx.future.proposed_compressions
    else ctx.future.proposed_ciphersuites, ctx.preferences.acceptable_ciphersuites,
      ctx.future.proposed_compressions, ctx.preferences.acceptable_compressions
  in
  let cs = match find_first_match pref_cs other_cs with
    | None -> failwith "TODO: Incompatible lists!"
    | Some suite -> suite
  and cm = match find_first_match pref_cm other_cm with
    | None -> failwith "TODO: Incompatible lists!"
    | Some compression -> compression
  in

  let sh = {
    server_version = snd ctx.future.proposed_versions;
    server_random = ctx.future.f_client_random; (* TODO! *)
    server_session_id = ""; (* TODO! *)
    ciphersuite = cs;
    compression_method = cm;
    server_extensions = None (* TODO! *)
  } in
  update_with_server_hello ctx sh;
  mk_handshake_msg ctx HT_ServerHello (ServerHello sh)

let mk_certificate_msg ctx = mk_handshake_msg ctx HT_Certificate (Certificate [])

let mk_server_hello_done ctx = mk_handshake_msg ctx HT_ServerHelloDone ServerHelloDone

let mk_client_key_exchange ctx =
  let kx = match ctx.future.proposed_ciphersuites with
    | [cs] -> (find_csdescr cs).kx
    | _ -> failwith "mk_client_hello: Internal inconsistency"
  in
  match kx, ctx.future.f_certificates, ctx.future.f_server_key_exchange with
  | KX_RSA, server_cert_opt::_, _ ->
    let server_cert = match server_cert_opt with
      | Parsed (_, c) -> c
      | Unparsed c_str -> X509.parse_certificate (input_of_string ~verbose:false "Server certificate" c_str)
    in
    let n, e = match server_cert.X509.tbsCertificate.X509.subjectPublicKeyInfo.X509.subjectPublicKey with
      | X509.RSA x -> x.Pkcs1.p_modulus, x.Pkcs1.p_publicExponent
      | _ -> failwith "mk_client_hello: no RSA key..."
    in
    let rng = ctx.preferences.random_generator in
    let version = exact_dump dump_tls_version (snd ctx.preferences.acceptable_versions) 
    and pms = RandomEngine.random_string rng 46 in
    ctx.future.secret_info <- PreMasterSecret (version ^ pms);
    (* TODO: Use a higher-level function (Pkcs1.pkcs1_container in cke_rsa_params) ? *)
    let encrypted_pms = Pkcs1.encrypt rng 2 (version ^ pms) n e in
    mk_handshake_msg ctx HT_ClientKeyExchange (ClientKeyExchange (CKE_RSA encrypted_pms))
  | kx, _, _ -> not_implemented ("CKE with kx=" ^ (string_of_kx kx))

let mk_finished ctx =
  let hs_msgs = POutput.contents ctx.future.f_handshake_messages in
  (* TODO: This is actually TLS version-dependent *)
  let finished_pre_content = (CryptoUtil.md5sum hs_msgs) ^ (CryptoUtil.sha1sum hs_msgs)
  and finished_label = match ctx.direction with
    | Some ClientToServer -> "client finished"
    | Some ServerToClient -> "server finished"
    | None -> failwith "mk_finished depends on ctx.direction: it can not be None"
  in
  let finished_content = ctx.current_prf ctx.current_master_secret finished_label finished_pre_content 12 (* TODO *) in
  mk_handshake_msg ctx HT_Finished (Finished finished_content)


(************************)
(* Automata description *)
(************************)

exception ConnectionTimeout

type automata_input =
  | InputSSL2Msg of ssl2_record
  | InputTlsMsg of tls_record
  | Timeout
  | InternalMsgIn of string
  | Nothing
  | EndOfFile

type tls_client_state =
  | ClientNil
  | ClientHelloSent
  | ServerHelloReceived
  | CertificateReceived
  | SKEReceived
  | SHDReceived

type tls_server_state =
  | ServerNil
  | ClientHelloReceived

type automata_output =
  | Abort
  | Wait
  | OutputSSL2Msgs of (unit -> ssl2_record) list
  | OutputTlsMsgs of (unit -> tls_record) list
  | InternalMsgOut of string
  | FatalAlert of tls_alert_type



(************************************)
(* Automata input/output generators *)
(************************************)

let catch_eof = function
  | ParsingException (OutOfBounds, _)
  | End_of_file -> return EndOfFile
  | e -> fail e


type connection_options = {
  timeout : float option;
  plaintext_chunk_size : int;
}
let default_options = {
  timeout = Some 5.0;
  plaintext_chunk_size = 16384;
}

type connection = {
  socket : Lwt_unix.file_descr;
  options : connection_options;
  mutable input : string_input;
  (* TODO: Handle SSLv2 records? *)
  mutable input_records : (bool * tls_record) list;
  mutable output : string;
}

type server_socket = {
  s_socket : Lwt_unix.file_descr;
  s_options : connection_options;
}


let resolve hostname port =
  let exn_catcher = function
    | Not_found -> return (None, hostname, port)
    | e -> fail e
  and normal_ending res = return (Some res, hostname, port)
  and main_t () =
    Lwt_unix.gethostbyname hostname >>= fun host_entry ->
    let ip = host_entry.Unix.h_addr_list.(0) in
    return ip
  in try_bind main_t normal_ending exn_catcher


let init_client_connection ?options (ip_opt, hostname, port) =
  match ip_opt with
  | Some ip ->
    let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0
    and addr = Unix.ADDR_INET (ip, port) in
    let t = Lwt_unix.connect s addr in
    let timed_t = match options with
      | None | Some { timeout = None } -> t
      | Some { timeout = Some timeout_val } ->
	pick [t; Lwt_unix.sleep timeout_val >>= fun () -> fail ConnectionTimeout]
    in
    let peer_name = hostname^":"^(string_of_int port) in
    timed_t >>= fun () -> return {
      socket = s;
      options = pop_opt default_options options;
      input = input_of_string ~verbose:false ~enrich:NeverEnrich peer_name ""; input_records = [];
      output = "";
    }
  | None -> raise Not_found


let init_server_connection ?options ?bind_address:(bind_addr=None) ?backlog:(backlog=1024) port =
  let s = Lwt_unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let inet_addr = match bind_addr with
    | Some a -> Unix.inet_addr_of_string a
    | None -> Unix.inet_addr_any
  in
  let local_addr = Unix.ADDR_INET (inet_addr, port) in
  Lwt_unix.setsockopt s Unix.SO_REUSEADDR true;
  Lwt_unix.bind s local_addr;
  Lwt_unix.listen s backlog;
  { s_socket = s; s_options = pop_opt default_options options }

let accept_client s =
  Lwt_unix.accept s.s_socket >>= fun (sock, peer_info) ->
  let peer_name = match peer_info with
    | Unix.ADDR_INET (a, p) -> (Unix.string_of_inet_addr a)^":"^(string_of_int p)
    | _ -> "Unknown peer info"
  in
  let i = input_of_string ~enrich:NeverEnrich peer_name ""
  and o = "" in
  return { socket = sock; options = s.s_options;
           input = i; input_records = [];
           output = o }


let get_next_automata_input ctx c =
  let dir = pop_opt ClientToServer ctx.direction in
  let timeout_t = match c.options.timeout with
    | None -> []
    | Some t -> [Lwt_unix.sleep t >>= fun () -> return Timeout]
  in

  let rec input_fun () =
    (* TODO: 4096 should be adjustable *)
    let buf = String.make 4096 ' ' in
    Lwt_unix.read c.socket buf 0 4096 >>= fun n_read ->
    if n_read = 0 then raise End_of_file;
    c.input <- append_to_input c.input (String.sub buf 0 n_read);
    let rec parse_new_records new_record =
      (* TODO: In fact, we are stuck if input enriches too much here  *)
      (* TODO: Should we check for that? *)
      match try_parse (parse_tls_record None) c.input with
      | None -> new_record
      | Some ({ record_content = Unparsed_Record ciphertext } as r) ->
        c.input <- drop_used_string c.input;
        let integrity, plaintext = match ctx.decrypt dir r.content_type r.record_version ciphertext with
          | true, content -> true, ctx.expand dir content
          | false, content -> false, content
        in
        c.input_records <- c.input_records@[integrity, {r with record_content = Unparsed_Record plaintext}];
        parse_new_records true
      | Some _ -> failwith "get_next_automata_input: unexpected early parsed record"
    in
    enrich_new_records (parse_new_records false)

  and enrich_new_records new_record_pending =
    if new_record_pending then begin
      (* TODO: Should it really be AlwaysEnrich here? *)
      match extract_first_record AlwaysEnrich (Some ctx) c.input_records with
      | [] | [ true, { record_content = Unparsed_Record _ } ] -> input_fun ()
      | (false, _)::_ -> failwith "Unable to check the integrity" (* TODO *)
      | (true, r)::rs ->
        c.input_records <- rs;
        return (InputTlsMsg r)
    end else input_fun ()
  in

  let output_fun () =
    let len = String.length c.output in
    Lwt_unix.write c.socket c.output 0 len >>= fun n_written ->
    c.output <- String.sub c.output n_written (len - n_written);
    return Nothing
  in

  match c.input_records with
    | [] | (true, { record_content = Unparsed_Record _ })::_ ->
      let input_t = if c.input_records = [] then [input_fun ()] else [enrich_new_records true] in
      let rec output_t =
        if c.output = ""
        then []
        else [output_fun ()]
      in
      try_bind (fun () -> pick (input_t@output_t@timeout_t)) return catch_eof

    | (false, _)::_ -> failwith "Unable to check the integrity" (* TODO *)
    | (true, r)::rs ->
      c.input_records <- rs;
      return (InputTlsMsg r)



let output_record ctx conn r_fun =
  let dir = pop_opt ServerToClient ctx.direction in
  let size =
    if conn.options.plaintext_chunk_size > 0
    then conn.options.plaintext_chunk_size
    else 16384
  in
  let r = r_fun () in
  let ct = r.content_type
  and v = r.record_version
  and content = exact_dump_record_content r.record_content in
  let len = String.length content in
  let result = POutput.create () in
  POutput.add_string result conn.output;

  let rec mk_records offset =
    if offset < len then begin
      let next_offset =
        if offset + size >= len
        then len
        else offset + size
      in
      let plaintext = String.sub content offset (next_offset - offset) in
      let ciphertext = ctx.encrypt dir ct v (ctx.compress dir plaintext) in
      let next = { content_type = ct;
                   record_version = v;
                   record_content = Unparsed_Record ciphertext } in
      dump_tls_record result next;
      mk_records next_offset
    end
  in

  mk_records 0;
  begin
    match ct with
    | CT_Handshake -> POutput.add_string ctx.future.f_handshake_messages content
    | CT_ChangeCipherSpec -> update_with_CCS dir ctx
    | _ -> ()
  end;
  conn.output <- POutput.contents result



(************)
(* Automata *)
(************)

let client_automata state input _global_ctx ctx =
  match state, input with
  | ClientHelloSent, InputTlsMsg { record_content = Handshake { handshake_content = ServerHello sh } } ->
    update_with_server_hello ctx sh;
    ServerHelloReceived, Wait
  | ServerHelloReceived, InputTlsMsg { record_content = Handshake { handshake_content = Certificate certs } } ->
    update_with_certificate ctx certs;
    CertificateReceived, Wait
  | CertificateReceived, InputTlsMsg { record_content = Handshake { handshake_content = ServerKeyExchange ske } } ->
    update_with_server_key_exchange ctx ske;
    SKEReceived, Wait
  | (CertificateReceived | SKEReceived),
    InputTlsMsg { record_content = Handshake { handshake_content = ServerHelloDone } } ->
    (* TODO: Optionaly send a Certificate message *)
    let cke () = mk_client_key_exchange ctx in
    (* TODO: Optionaly send a CertificateVerify message *)
    let ccs () = mk_ccs_msg ctx in
    let finished () = mk_finished ctx in
    (* TODO: Handle alerts *)
    SHDReceived, OutputTlsMsgs [cke; ccs; finished]
  | _, Timeout -> ClientNil, FatalAlert AT_CloseNotify
  | _, Nothing -> state, Wait
  | _ -> ClientNil, FatalAlert AT_HandshakeFailure

let server_automata state input _global_ctx ctx =
  match state, input with
  | ServerNil, InputTlsMsg { record_content = Handshake { handshake_content = ClientHello ch } } ->
(*    let ctx = empty_crypto_context () in *)
    update_with_client_hello ctx ch;
    let sh () = mk_server_hello ctx in
    let cert () = mk_certificate_msg ctx in
    let shd () = mk_server_hello_done ctx in
    ClientHelloReceived, OutputTlsMsgs [sh; cert; shd]
  | _, Timeout -> ServerNil, FatalAlert AT_CloseNotify
  | _, Nothing -> state, Wait
  | _ -> ServerNil, FatalAlert AT_HandshakeFailure



let rec run_automata automata state global_ctx ctx sock =
  get_next_automata_input ctx sock >>= fun automata_input ->
  let next_state, action = automata state automata_input global_ctx ctx in
  let again = match action with
    | OutputTlsMsgs rs ->
      List.iter (output_record ctx sock) rs;
      true
    | FatalAlert at ->
      let r = mk_alert_msg ctx AL_Fatal at in
      sock.output <- sock.output ^ (exact_dump_tls_record r);
      false
    | Wait -> true
    | Abort -> false

    | OutputSSL2Msgs _
    | InternalMsgOut _ -> print_endline "Something else to do"; false
  in
  if again
  then run_automata automata next_state global_ctx ctx sock
  else return next_state



(**************************)
(* Offline record parsing *)
(**************************)

let update_with_record dir ctx = function
  | { record_content = Handshake { handshake_content = ClientHello ch } } -> update_with_client_hello ctx ch
  | { record_content = Handshake { handshake_content = ServerHello sh } } -> update_with_server_hello ctx sh
  | { record_content = Handshake { handshake_content = Certificate certs } } -> update_with_certificate ctx certs
  | { record_content = Handshake { handshake_content = ServerKeyExchange ske } } -> update_with_server_key_exchange ctx ske
  | { record_content = Handshake { handshake_content = _ } } -> () (* TODO *)
  | { record_content = ChangeCipherSpec _ } ->
    begin
      try
        update_with_CCS dir ctx;
      with Failure f -> prerr_endline ("FAILURE: " ^ f)
    end
  | { record_content = Unparsed_Record _ } -> ()
  | { record_content = ApplicationData _ } -> ()
  | { record_content = Alert _ } -> ()
  | { record_content = Heartbeat _ } -> ()


type unauth_records =
| RecordsToHandle of Tls.tls_record list
| LostRecords of Tls.tls_record list

type enrich_struct = {
  clear_recs : Tls.tls_record list;
  unauth_recs : unauth_records;
}

type enrich_status = NoMoreContent | NewContent of string | AuthError

let parse_all_records dir ctx input =
  let rec parse_raw_records accu i =
    if eos i
    then List.rev accu, None
    else begin
      match try_parse (parse_tls_record None) i with
      | Some next -> parse_raw_records (next::accu) i
      | None -> List.rev accu, Some (parse_rem_binstring i)
    end
  in

  let rec enrich_records dir ctx accu recs =
    let decrypt, expand = match ctx with
      | None -> unknown_decrypt, null_compress
      | Some real_ctx -> real_ctx.decrypt, real_ctx.expand
    in
    let rec decrypt_recs clr_content recs = match clr_content, recs.unauth_recs with
      | None, (RecordsToHandle [] | LostRecords []) -> recs
      | Some (cur_ct, cur_v, cur_content), (RecordsToHandle [] | LostRecords []) ->
        let new_clear_rec = { content_type = cur_ct; record_version = cur_v;
                              record_content = Unparsed_Record (Buffer.contents cur_content) } in
        { recs with clear_recs = new_clear_rec::(recs.clear_recs) }
      | _, LostRecords _ -> failwith "decrypt_recs: unexpected case (lost records are no use now)"

      | _, RecordsToHandle (r::rs) ->
        let proceed = match clr_content with
          | None -> true
          | Some (cur_ct, cur_v, _) ->
	    (* Only merge Handshake and AppData records *)
	    (cur_ct = CT_Handshake || cur_ct = CT_ApplicationData) &&
            cur_ct = r.content_type && cur_v = r.record_version
        in
        let status = match proceed, r.record_content with
          | true, Unparsed_Record ciphertext ->
            begin
              match decrypt dir r.content_type r.record_version ciphertext with
              | true, content -> NewContent (expand dir content)
              | false, _ -> AuthError (* TODO: Alert? Change decrypt? *)
            end
          | true, _ -> failwith "decrypt_recs: unexpected early parsed record"
          | false, _ -> NoMoreContent
        in
        match clr_content, status with
        | None, AuthError -> { recs with unauth_recs = LostRecords (r::rs) }
        | None, NewContent content ->
          let buf = Buffer.create 4096 in
          Buffer.add_string buf content;
          decrypt_recs
            (Some (r.content_type, r.record_version, buf))
            {recs with unauth_recs = RecordsToHandle rs }
        | None, NoMoreContent -> failwith "decrypt_recs: unexpected case"

        | Some (cur_ct, cur_v, cur_content), AuthError ->
          let new_clear_rec = { content_type = cur_ct; record_version = cur_v;
                                record_content = Unparsed_Record (Buffer.contents cur_content) } in
          { clear_recs = new_clear_rec::(recs.clear_recs);
            unauth_recs = LostRecords (r::rs) }
        | Some (cur_ct, cur_v, cur_content), NoMoreContent ->
          let new_clear_rec = { content_type = cur_ct; record_version = cur_v;
                                record_content = Unparsed_Record (Buffer.contents cur_content) } in
          { recs with clear_recs = new_clear_rec::(recs.clear_recs) }
        | Some (_, _, cur_content), NewContent content ->
          Buffer.add_string cur_content content;
          decrypt_recs clr_content {recs with unauth_recs = RecordsToHandle rs }
    in

    match recs with
    | { clear_recs = []; unauth_recs = LostRecords rs } -> List.rev_append accu rs
    | { clear_recs = []; unauth_recs = RecordsToHandle [] } -> List.rev accu
    | { clear_recs = []; unauth_recs = RecordsToHandle _ } ->
      enrich_records dir ctx accu (decrypt_recs None recs)
    | { clear_recs = clr_rec::clr_recs } ->
      match extract_first_record input.enrich ctx [true, clr_rec] with
      | (true, r)::rs ->
        begin
          match ctx with
          | None -> ()
          | Some real_ctx -> update_with_record dir real_ctx r
        end;
        enrich_records dir ctx (r::accu) { recs with clear_recs = (List.map snd rs)@clr_recs }
      | (false, _)::_ | [] -> failwith "enrich_records: unexpected value returned by extract_first_record"
  in

  let saved_enrich = input.enrich in
  input.enrich <- NeverEnrich;
  let recs, remaining = parse_raw_records [] input in
  input.enrich <- saved_enrich;
  let parsed_recs = enrich_records dir ctx [] { clear_recs = []; unauth_recs = RecordsToHandle recs } in
  parsed_recs, remaining
