open Parsifal
open BasePTypes
open PTypes

(*open Big_int*)

(* §3.3 *)
(* type does not define the parse_* functions *)
alias pgp_keyid = uint64

(* §3.2 *)
type mpint = string

let parse_mpint input =
    let n = parse_uint16 input in
    let bytes_count = (n + 7)/8 in
    parse_string bytes_count input

let dump_mpint buf i =
    let strlen = String.length i in
    let fst_char = int_of_char (String.get i 0) in
    let order_of_fst_char = int_of_float (ceil (log (float_of_int fst_char)) /. (log 2.) )  in
    let bit_counter = ((strlen - 1) * 8) + order_of_fst_char in
    dump_uint16 buf bit_counter ;
    dump_string buf i

let value_of_mpint i =
    VBigInt (i, BigEndian)

(* §3.5 *)
alias timefield = uint32

let value_of_timefield t =
    let value = (Unix.localtime (float_of_int t)) in
    VString( (Printf.sprintf "%02d/%02d/%04d %02d:%02d:%02d" value.Unix.tm_mday value.Unix.tm_mon (value.Unix.tm_year + 1900) value.Unix.tm_hour value.Unix.tm_min value.Unix.tm_sec), false)

(* §9.1 *)
enum pubkey_algo (8, UnknownVal UnknownPubKeyAlgo) =
    | 1     ->  RSAEncryptAndSign_PubKeyAlgo, "RSA Encrypt and Sign"
    | 2     ->  RSAEncryptOnly_PubKeyAlgo, "RSA Encrypt Only"
    | 3     ->  RSASignOnly_PubKeyAlgo, "RSA Sign Only"
    | 16    ->  Elgamal_PubKeyAlgo, "Elgamal"
    | 17    ->  DSA_PubKeyAlgo, "DSA"
    | 18    ->  EllipticCurve_PubKeyAlgo, "Elliptic Curve (Reserved)" (* Reserved only *)
    | 19    ->  ECDSA_PubKeyAlgo, "ECDSA (Reserved)" (* Reserved only *)
    | 20    ->  OldElgamal_PubKeyAlgo, "Elgamal (formerly Elgamal Encrypt or Sign)" (* formerly Elgamal Encrypt or Sign *)
    | 21    ->  DH_PubKeyAlgo, "Diffie-Hellman (X9.42)" (* Reserved only, X9.42 *)
(* TODO no longer handling Private algorithm ; should implement that in the various pubkey_* enum types *)

(* §9.1 *)
enum pubkey_signonly_algo (8, UnknownVal NotSignOnlyAlgo) =
    | 3     ->  RSASignOnly_SigOnlyAlgo, "RSA Sign Only"
    | 17    ->  DSA_SignOnlyAlgo, "DSA"
    | 18    ->  EllipticCurve_SigOnlyAlgo, "Elliptic Curve (Reserved)" (* Reserved only *)
    | 19    ->  ECDSA_SignOnlyAlgo, "ECDSA (Reserved)" (* Reserved only *)

(* §9.1 *)
enum pubkey_enconly_algo (8, UnknownVal NotEncOnlyAlgo) =
    | 2     ->  RSAEncryptOnly_EncOnlyAlgo, "RSA Encrypt Only"
    | 16    ->  Elgamal_EncOnlyAlgo, "Elgamal"
    | 21    ->  DH_EncOnlyAlgo, "Diffie-Hellman (X9.42)" (* Reserved only, X9.42 *)

(* §9.1 *)
enum pubkey_unspecifiedusage_algo (8, UnknownVal UnknownPubkeyAlgo) =
    | 1     ->  RSAEncryptAndSign_UnspecAlgo, "RSA Encrypt and Sign"
    | 20    ->  OldElgamal_UnspecAlgo, "Elgamal (formerly Elgamal Encrypt or Sign)" (* formerly Elgamal Encrypt or Sign *)

(* §9.1 *)
enum pubkey_sig_algo (8, UnknownVal UnknownPubKeySigAlgo) =
    | 3     ->  RSASignOnly_SigAlgo, "RSA Sign Only"
    | 17    ->  DSA_SigAlgo, "DSA"
    | 18    ->  EllipticCurve_SigAlgo, "Elliptic Curve (Reserved)" (* Reserved only *)
    | 19    ->  ECDSA_SigAlgo, "ECDSA (Reserved)" (* Reserved only *)
    | 1     ->  RSAEncryptAndSign_SigAlgo, "RSA Encrypt and Sign"
    | 20    ->  OldElgama_SiglAlgo, "Elgamal (formerly Elgamal Encrypt or Sign)" (* formerly Elgamal Encrypt or Sign *)

(* §9.1 *)
enum pubkey_enc_algo (8, UnknownVal UnknownPubKeyEncAlgo) =
    | 2     ->  RSAEncryptOnly_EncAlgo, "RSA Encrypt Only"
    | 16    ->  Elgamal_EncAlgo, "Elgamal"
    | 21    ->  DH_EncAlgo, "Diffie-Hellman (X9.42)" (* Reserved only, X9.42 *)
    | 1     ->  RSAEncryptAndSign_EncAlgo, "RSA Encrypt and Sign"
    | 20    ->  OldElgamal_EncAlgo, "Elgamal (formerly Elgamal Encrypt or Sign)" (* formerly Elgamal Encrypt or Sign *)

(*
(* §9.1 *)
type pubkey_algo =
    | PubkeySignOnlyAlgo of pubkey_signonly_algo
    | PubkeyEncOnlyAlgo of pubkey_enconly_algo
    | PubkeyUnspecifiedUsageAlgo of pubkey_unspecifiedusage_algo
    | PubkeyPrivateOrExperimentalAlgo of uint8

(* §9.1 *)
let parse_pubkey_algo input =
    let value = parse_uint8 input in
    if (value >= 100 && value <= 110) then
        PubkeyPrivateOrExperimentalAlgo value
    else
        let signonly_algo = pubkey_signonly_algo_of_int value in
        match signonly_algo with
        | NotSignOnlyAlgo _ ->
            let enconly_algo = pubkey_enconly_algo_of_int value in
            (
                match enconly_algo with
                | NotEncOnlyAlgo _ -> PubkeyUnspecifiedUsageAlgo (pubkey_unspecifiedusage_algo_of_int value)
                | _ -> PubkeyEncOnlyAlgo enconly_algo
            )
        | _ -> PubkeySignOnlyAlgo signonly_algo

(* §9.1 *)
let dump_pubkey_algo buf i =
    match i with
    | PubkeyPrivateOrExperimentalAlgo x -> dump_uint8 buf x
    | PubkeySignOnlyAlgo x -> dump_pubkey_signonly_algo buf x
    | PubkeyEncOnlyAlgo x -> dump_pubkey_enconly_algo buf x
    | PubkeyUnspecifiedUsageAlgo x -> dump_pubkey_unspecifiedusage_algo buf x


(* §9.1 *)
let value_of_pubkey_algo i =
    match i with
    | PubkeyPrivateOrExperimentalAlgo x -> VSimpleInt x
    | PubkeySignOnlyAlgo x -> value_of_pubkey_signonly_algo x
    | PubkeyEncOnlyAlgo x -> value_of_pubkey_enconly_algo x
    | PubkeyUnspecifiedUsageAlgo x -> value_of_pubkey_unspecifiedusage_algo x




(* §9.1 *)
type pubkey_sig_algo =
    | PubkeySigSignOnlyAlgo of pubkey_signonly_algo
    | PubkeySigUnspecifiedUsageAlgo of pubkey_unspecifiedusage_algo
    | PubkeySigPrivateOrExperimentalAlgo of uint8


(* §9.1 *)
let parse_pubkey_sig_algo input =
    let value = parse_pubkey_algo input in
    match value with
    | PubkeyEncOnlyAlgo _ -> failwith "DIE" (* TODO *)
    | PubkeySignOnlyAlgo x -> PubkeySigSignOnlyAlgo x
    | PubkeyUnspecifiedUsageAlgo x -> PubkeySigUnspecifiedUsageAlgo x
    | PubkeyPrivateOrExperimentalAlgo x -> PubkeySigPrivateOrExperimentalAlgo x

(* §9.1 *)
let dump_pubkey_sig_algo buf i =
    match i with
    | PubkeySigSignOnlyAlgo x -> dump_pubkey_signonly_algo buf x
    | PubkeySigUnspecifiedUsageAlgo x -> dump_pubkey_unspecifiedusage_algo buf x
    | PubkeySigPrivateOrExperimentalAlgo x -> dump_uint8 buf x

(* §9.1 *)
let value_of_pubkey_sig_algo i =
    match i with
    | PubkeySigSignOnlyAlgo x -> value_of_pubkey_signonly_algo x
    | PubkeySigUnspecifiedUsageAlgo x -> value_of_pubkey_unspecifiedusage_algo x
    | PubkeySigPrivateOrExperimentalAlgo x -> VSimpleInt x



(* §9.1 *)
type pubkey_enc_algo =
    | PubkeyEncEncOnlyAlgo of pubkey_enconly_algo
    | PubkeyEncUnspecifiedUsageAlgo of pubkey_unspecifiedusage_algo
    | PubkeyEncPrivateOrExperimentalAlgo of uint8

(* §9.1 *)
let parse_pubkey_enc_algo input =
    let value = parse_pubkey_algo input in
    match value with
    | PubkeyEncOnlyAlgo x -> PubkeyEncEncOnlyAlgo x
    | PubkeySignOnlyAlgo _ -> failwith "DIE" (* TODO *)
    | PubkeyUnspecifiedUsageAlgo x -> PubkeyEncUnspecifiedUsageAlgo x
    | PubkeyPrivateOrExperimentalAlgo x -> PubkeyEncPrivateOrExperimentalAlgo x

(* §9.1 *)
let dump_pubkey_enc_algo buf i =
    match i with
    | PubkeyEncEncOnlyAlgo x -> dump_pubkey_enconly_algo buf x
    | PubkeyEncUnspecifiedUsageAlgo x -> dump_pubkey_unspecifiedusage_algo buf x
    | PubkeyEncPrivateOrExperimentalAlgo x -> dump_uint8 buf x

(* §9.1 *)
let value_of_pubkey_enc_algo i =
    match i with
    | PubkeyEncEncOnlyAlgo x -> value_of_pubkey_enconly_algo x
    | PubkeyEncUnspecifiedUsageAlgo x -> value_of_pubkey_unspecifiedusage_algo x
    | PubkeyEncPrivateOrExperimentalAlgo x -> VSimpleInt x
*)

(* §9.2 *)
enum privkey_algo (8, UnknownVal UnknownPrivKeyAlgo) =
    | 0     ->  PlainTextAlgo, "Plain Text"
    | 1     ->  IDEAAlgo, "IDEA" (* Required by PGP <= 2.6 *)
    | 2     ->  TripleDESAlgo, "DES-EDE" (* Must implement *)
    | 3     ->  CAST5Algo, "CAST5" (* Should implement *)
    | 4     ->  BlowfishAlgo, "Blowfish"
    | 5     ->  ReservedAlgo
    | 6     ->  ReservedAlgo
    | 7     ->  AES128Algo, "AES-128" (* Should implement *)
    | 8     ->  AES192Algo, "AES-192"
    | 9     ->  AES256Algo, "AES-256"
    | 10    ->  TwofishAlgo, "Twofish"
    | 11    ->  Camellia128Algo, "CAMELLIA-128" (* RFC5581 §3 *)
    | 12    ->  Camellia192Algo, "CAMELLIA-192" (* RFC5581 §3 *)
    | 13    ->  Camellia256Algo, "CAMELLIA-256" (* RFC5581 §3 *)
    | 100   ->  PrivateAlgo
    | 101   ->  PrivateAlgo
    | 102   ->  PrivateAlgo
    | 103   ->  PrivateAlgo
    | 104   ->  PrivateAlgo
    | 105   ->  PrivateAlgo
    | 106   ->  PrivateAlgo
    | 107   ->  PrivateAlgo
    | 108   ->  PrivateAlgo
    | 109   ->  PrivateAlgo
    | 110   ->  PrivateAlgo

let get_privkeyalgo_block_size = function
    | IDEAAlgo | TripleDESAlgo | CAST5Algo | BlowfishAlgo ->  8
    | AES128Algo | AES192Algo | AES256Algo | TwofishAlgo | Camellia128Algo | Camellia192Algo | Camellia256Algo -> 16
    | _ -> 0

(* §9.3 *)
enum compression_algo (8, UnknownVal UnknownCompressionAlgo) =
    | 0     ->  UncompressedAlgo, "Uncompressed"
    | 1     ->  ZIPAlgo, "ZIP"
    | 2     ->  ZLIBAlgo, "ZLIB"
    | 3     ->  BZIP2Algo, "BZip2"
    | 100   ->  PrivateAlgo
    | 101   ->  PrivateAlgo
    | 102   ->  PrivateAlgo
    | 103   ->  PrivateAlgo
    | 104   ->  PrivateAlgo
    | 105   ->  PrivateAlgo
    | 106   ->  PrivateAlgo
    | 107   ->  PrivateAlgo
    | 108   ->  PrivateAlgo
    | 109   ->  PrivateAlgo
    | 110   ->  PrivateAlgo

(* §9.4 *)
enum hash_algo (8, UnknownVal UnknownHashAlgo) =
    | 1     ->  MD5Algo, "MD5" (* Deprecated *)
    | 2     ->  SHA1Algo, "SHA-1" (* Must implement *)
    | 3     ->  RIPEMD160Algo, "RIPEMD160"
    | 4     ->  ReservedAlgo
    | 5     ->  ReservedAlgo
    | 6     ->  ReservedAlgo
    | 7     ->  ReservedAlgo
    | 8     ->  SHA256Algo, "SHA-256"
    | 9     ->  SHA384Algo, "SHA-384"
    | 10    ->  SHA512Algo, "SHA-512"
    | 11    ->  SHA224Algo, "SHA-224"
    | 100   ->  PrivateAlgo
    | 101   ->  PrivateAlgo
    | 102   ->  PrivateAlgo
    | 103   ->  PrivateAlgo
    | 104   ->  PrivateAlgo
    | 105   ->  PrivateAlgo
    | 106   ->  PrivateAlgo
    | 107   ->  PrivateAlgo
    | 108   ->  PrivateAlgo
    | 109   ->  PrivateAlgo
    | 110   ->  PrivateAlgo

let get_hash_len algo input = match algo with
    | MD5Algo                       ->  16
    | SHA1Algo | RIPEMD160Algo      ->  20
    | SHA224Algo                    ->  28
    | SHA256Algo                    ->  32
    | SHA384Algo                    ->  48
    | SHA512Algo                    ->  64
    | _                             ->  raise (ParsingException (CustomException "Invalid hashing algorithm", _h_of_si input))

alias digest [param algo] = binstring (get_hash_len algo input)

(* §3.7.1.1 *)
struct simple_s2k_payload = {
    algo    :   hash_algo;
    digest  :   digest(algo);
}

(* §3.7.1.2 *)
struct salted_s2k_payload = {
    algo    :   hash_algo;
    salt    :   string(8); (* §3.7.1.{2,3}: salt are 8 bytes long *)
    digest  :   digest(algo)
}

(* §3.7.1.3 *)
type iteration_counter = uint32

let parse_iteration_counter input =
    let c = parse_byte input in
    let expbias = 6 in
    (16 + (c land 15)) lsl ((c lsr 4) + expbias)

let dump_iteration_counter buf iteration_counter =
    let expbias = 6 in
    let unbiased_it_cnt = iteration_counter lsr expbias in
    let order_of_cnt = int_of_float (ceil (log (float_of_int unbiased_it_cnt) /. (log 2.) ) ) in
    let exponent = max 0 (order_of_cnt - 5) in
    let c = (exponent lsl 4) lor ((unbiased_it_cnt lsr exponent) land 0xf) in
    dump_uint8 buf c

let value_of_iteration_counter iteration_counter =
  VSimpleInt iteration_counter

(* §3.7.1.3 *)
struct iterated_salted_s2k_payload = {
    algo    :   hash_algo;
    salt    :   binstring(8); (* §3.7.1.{2,3}: salt are 8 bytes long *)
    counter :   iteration_counter;
    digest  :   digest(algo)
}

(* From the reversed source-code of GnuPG v1.4 g10/parse-packet.c *)
struct private_or_experimental_s2k_101_payload = {
    alleged_hash_algo        : uint8;
    gnu_extension            : magic("GNU");
    s2k_gnu_protected_mode   : magic("\x02"); (* Called "gnu-divert-to-card" *)
    serial_number_len        : uint8;
    serial_number            : binstring(serial_number_len)
}

(* §3.7.1 *)
enum s2k_type (8, UnknownVal UnknownS2KType) =
    | 0     -> SimpleS2K,                   "Simple S2K" (* Not recommended §3.7.2 *)
    | 1     -> SaltedS2K,                   "Salted S2K"
    | 3     -> IteratedSaltedS2K,           "Iterated and Salted S2K"
    | 100   -> PrivateOrExperimentalS2K100, "Private or Experimental S2K 100"
    | 101   -> PrivateOrExperimentalS2K101, "Private or Experimental S2K 101"
    | 102   -> PrivateOrExperimentalS2K102, "Private or Experimental S2K 102"
    | 103   -> PrivateOrExperimentalS2K103, "Private or Experimental S2K 103"
    | 104   -> PrivateOrExperimentalS2K104, "Private or Experimental S2K 104"
    | 105   -> PrivateOrExperimentalS2K105, "Private or Experimental S2K 105"
    | 106   -> PrivateOrExperimentalS2K106, "Private or Experimental S2K 106"
    | 107   -> PrivateOrExperimentalS2K107, "Private or Experimental S2K 107"
    | 108   -> PrivateOrExperimentalS2K108, "Private or Experimental S2K 108"
    | 109   -> PrivateOrExperimentalS2K109, "Private or Experimental S2K 109"
    | 110   -> PrivateOrExperimentalS2K110, "Private or Experimental S2K 110"

(* §3.7.1 *)
union s2k_payload [enrich] (UnparsedS2KPayload) =
    | SimpleS2K -> SimpleS2KPayload of simple_s2k_payload
    | SaltedS2K -> SaltedS2KPayload of salted_s2k_payload
    | IteratedSaltedS2K -> IteratedSaltedS2KPayload of iterated_salted_s2k_payload
    | PrivateOrExperimentalS2K101 -> PrivateOrExperimentalS2K101Payload of private_or_experimental_s2k_101_payload

(* String-to-key §3.7 *)
struct s2k_specifier = {
    s2ktype : s2k_type;
    s2kpayload : s2k_payload(s2ktype)
}


type bit_magic = bool
let parse_bit_magic expected_value input =
    let v = parse_bit_bool input in
    if v = expected_value then v
    else raise (ParsingException (CustomException ("invalid magic (\"" ^
                  (string_of_bool v) ^ "\")"), _h_of_si input))
let dump_bit_magic = dump_bit_bool
let value_of_bit_magic = value_of_bit_bool


(* §4.2 & §4.3 *)
enum packet_type_enum (8, UnknownVal UnknownPacketType) =
    | 0  ->  ReservedPacketType, "Reserved Packet Type"
    | 1  ->  PublicKeyEncryptedSessionKeyPacketType, "Public Key-Encrypted Session Key Packet"
    | 2  ->  SignaturePacketType, "Signature Packet"
    | 3  ->  SymmetricKeyEncryptedSessionKeyPacketType, "Symmetric Key-Encrypted Session Key Packet"
    | 4  ->  OnePassSignaturePacketType, "One-Pass Signature Packet"
    | 5  ->  SecretKeyPacketType, "Secret Key Packet"
    | 6  ->  PublicKeyPacketType, "Public Key Packet"
    | 7  ->  SecretSubKeyPacketType, "Secret Subkey Packet"
    | 8  ->  CompressedDataPacketType, "Compressed Data Packet"
    | 9  ->  SymmetricallyEncryptedDataPacketType, "Symmetrically-encrypted Data Packet"
    | 10 ->  MarkerPacketType, "Marker Packet"
    | 11 ->  LiteralDataPacketType, "Literal Data Packet"
    | 12 ->  TrustPacketType, "Trust Packet"
    | 13 ->  UserIDPacketType, "UserID Packet"
    | 14 ->  PublicSubKeyPacketType, "Public Subkey Packet"
    | 17 ->  UserAttributePacketType, "User Attribute Packet"
    | 18 ->  SymmetricallyEncryptedAndIntegrityProtectedPacketType, "Symmetrically-encrypted and integrity-protected packet"
    | 19 ->  ModificationDetectionCodePacketType, "Modification Detection Packet"
    | 60 ->  PrivatePacketType, "Private Packet Type"
    | 61 ->  PrivatePacketType, "Private Packet Type"
    | 62 ->  PrivatePacketType, "Private Packet Type"
    | 63 ->  PrivatePacketType, "Private Packet Type"


(* §4.2 & §4.3 *)
type packet_type = packet_type_enum

(* §4.2 & §4.3 *)
let parse_packet_type packet_version input =
    let n = if packet_version then 6 else 4 in
    packet_type_enum_of_int (parse_bit_int n input)

(* §4.2 & §4.3 *)
let dump_packet_type packet_version buf packet_type =
    let n = if packet_version then 6 else 4 in
    dump_bit_int n buf (int_of_packet_type_enum packet_type)

(* §4.2 & §4.3 *)
let value_of_packet_type =  value_of_packet_type_enum

alias packet_version = bit_bool

(*
let value_of_packet_version packet_version =
    match packet_version with
    | false -> VString("Old-style Packet", false)
    | true -> VString("New-style Packet", false)
*)

(* §4.2 & §4.3 *)
struct packet_tag = {
    packet_magic : bit_magic (true);
    packet_version : packet_version;
    packet_type : packet_type(packet_version; DUMP packet_tag.packet_version);   (* TODO OL: Fix this *)
    packet_length_type : conditional_container(not packet_version) of bit_int[2];
}

(* §4.2.1 & §4.2.2 *)
type packet_len =
    | FixedLen of uint32
    | UndeterminateLen
    | PartialLen of uint32

let parse_packet_len packet_tag input =
    match packet_tag.packet_version, packet_tag.packet_length_type with
    | false, Some 0 -> FixedLen (parse_uint8 input)
    | false, Some 1 -> FixedLen (parse_uint16 input)
    | false, Some 2 -> FixedLen (parse_uint32 input)
    | false, Some 3 -> UndeterminateLen
    | true, None ->
        let first = parse_uint8 input in
        if first <= 191 then FixedLen (first)
        else if first <= 223 then FixedLen ((((first - 192) lsl 8) lor (parse_uint8 input)) + 192)
        else if first = 255 then FixedLen (parse_uint32 input)
        (*XXX else PartialLen (1 lsl (first land 0x1F))*)
        else PartialLen (1 lsl (first land 0x1F))
    | _ -> failwith "Inconsistent values for version/length type"

let dump_packet_len packet_tag buf packet_len =
    match packet_len with
    | UndeterminateLen -> ()
    | FixedLen len     ->
        (
            match packet_tag.packet_version with
            | false -> (* Old-stype Len Format *)
                if len <= ((2 lsl 8) - 1) then
                    dump_uint8 buf len
                else if len <= ((2 lsl 16) - 1) then
                    dump_uint16 buf len
                else
                    dump_uint32 buf len
            | true -> (* New-style Len Format *)
                if len <= 191 then
                    dump_uint8 buf len
                else if len <= 8383 then
                        let sublen = len - 192 in
                        let value = ((sublen land 0xFF00) + (192 lsl 8)) lor (sublen land 0xFF) in
                        dump_uint16 buf value
                else begin
                    dump_uint8 buf 255 ;
                    dump_uint32 buf (len land 0xFFFFFFFF)
                end
        )
    | PartialLen len    ->
        dump_uint8 buf (224 + (int_of_float (ceil (log (float_of_int len) /. (log 2.) ) ) ) )


let value_of_packet_len l =
    match l with
    | FixedLen x | PartialLen x -> VString(string_of_int x, false)
    | UndeterminateLen          -> VString("Undeterminate len", false)


union public_key_encrypted_data [enrich] (UnparsedPublicKeyEncryptedData) =
    | RSAEncryptOnly_EncAlgo     ->    RSAEncryptedData of mpint
    | RSAEncryptAndSign_EncAlgo  ->    RSAEncryptedData of mpint
    | Elgamal_EncAlgo            ->    ElgamalEncryptedData of list(2) of mpint

union signed_data [enrich] (UnparsedSignedData) =
    | RSASignOnly_SigAlgo       ->  RSASignedData of mpint
    | RSAEncryptAndSign_SigAlgo ->  RSASignedData of mpint
    | DSA_SigAlgo               ->  DSASignedData of list(2) of mpint

(* §5.1 *)
struct public_key_encrypted_session_key_packet_content = {
    version :   magic("\x03");
    keyid   :   pgp_keyid;
    cipher  :   pubkey_enc_algo;
    key     :   public_key_encrypted_data(cipher)
}

(* §5.2.3.1 *)
type subpacket_len = uint32

let parse_subpacket_len input =
    let first = parse_uint8 input in
    if first <= 191 then first
    else if first <= 254 then (((first - 192) lsl 8) lor (parse_uint8 input)) + 192
    else parse_uint32 input

let dump_subpacket_len buf subpacket_len =
    if subpacket_len <= 191 then
        dump_uint8 buf subpacket_len
    else if subpacket_len <= 16319 then (* 16319 is [254;255], the maximum value encoded on two bytes with this format *)
        let sublen = subpacket_len - 192 in
        let value = ((sublen land 0xFF00) + (192 lsl 8)) lor (sublen land 0xFF) in
        dump_uint16 buf value
    else begin
        dump_uint8 buf 255 ;
        dump_uint32 buf (subpacket_len land 0xFFFFFFFF)
    end

let value_of_subpacket_len l = VSimpleInt l


(* §5.2.3.1 *)
enum subpacket_type (7, UnknownVal UnknownSubpacketType) =
    | 0     -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 1     -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 8     -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 13    -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 14    -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 15    -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 17    -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 18    -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 19    -> ReservedSubpacketType, "Reserved Subpacket Type"
    | 2     -> SigCreationTime, "Signature Creation Time"
    | 3     -> SigExpirationTime, "Signature Expiration Time"
    | 4     -> ExportableCertif, "Exportable Certification"
    | 5     -> TrustSig, "Trust Signature"
    | 6     -> RegExp, "Regular Expression"
    | 7     -> Revocable, "Revocable"
    | 9     -> KeyExpirationTime, "Key Expiration Time"
    | 10    -> PlaceHolder, "Placeholder for backward compatibility"
    | 11    -> PrefPrivkeyAlgo, "Preferred Symmetric Algorithms"
    | 12    -> RevocationKey, "Revocation Key"
    | 16    -> Issuer, "Issuer"
    | 20    -> NotationData, "Notation Data"
    | 21    -> PrefHashAlgo, "Preferred Hash Algorithms"
    | 22    -> PrefCompressAlgo, "Preferred Compression Algorithms"
    | 23    -> KeyServerPrefs, "Key Server Preferences"
    | 24    -> PrefKeyServer, "Preferred Key Server"
    | 25    -> PrimaryUserID, "Primary User ID"
    | 26    -> PolicyURI, "Policy URI"
    | 27    -> KeyFlags, "Key Flags"
    | 28    -> SignerUserID, "Signer's User ID"
    | 29    -> RevocReason, "Reason for Revocation"
    | 30    -> Features, "Features"
    | 31    -> SigTarget, "Signature Target"
    | 32    -> EmbeddedSig, "Embedded Signature"
    | 100   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 101   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 102   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 103   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 104   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 105   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 106   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 107   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 108   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 109   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"
    | 110   -> PrivateOrExperimental, "Private or Experimenal Subpacket Type"

type byte_boolean = bool
let parse_byte_boolean input =
    match (parse_uint8 input) with
        | 0 -> false
        | _ -> true
let dump_byte_boolean buf b =
    dump_uint8 buf (if b then 1 else 0)
let value_of_byte_boolean b = VBool b

struct subpacket_trust_signature_data = {
    depth        : uint8;
    trust_amount : uint8
}

(* §5.2.3.14 *)
alias subpacket_regular_expression_data = cstring

(* §5.2.3.15 *)
struct subpacket_revocation_key_data = {
    srkd_magic1         : bit_magic(true);
    sensitive           : bit_bool;
    srkd_unparsed_flags : bit_int[6];
    sig_algo            : pubkey_sig_algo;
    fingerprint         : binstring(get_hash_len SHA1Algo input)
}

(* §5.2.3.16 *)
struct subpacket_notation_data_data = {
    human_readable      : bit_bool;
    sndd_placeholder    : bit_int[31];
    namelen             : uint16;
    vallen              : uint16;
    name                : string(namelen);
    value               : string(vallen);
}

(* §5.2.3.18 *)

struct subpacket_key_server_prefs_data = {
  no_modify             : bit_bool;
  skspd_placeholder     : list(7) of bit_magic(false); (* TODO OL: bit_int_magic(length, expected_value) *)
  skspd_placeholder2    : binstring;
}


(* §5.2.3.21 *)
struct subpacket_key_flags_data = {
    groupPrivKey            : bit_bool; (* XXX TODO should be placed only on direct sign of self-sig *)
    skfd_placeholder        : bit_bool;
    authOKKey               : bit_bool;
    splitPrivKey            : bit_bool; (* XXX TODO should be placed only on direct sign of self-sig *)
    storageEncUsage         : bit_bool;
    communicationEncUsage   : bit_bool;
    signUsage               : bit_bool;
    certificationUsage      : bit_bool;
}

(* §5.2.3.23 *)
enum revocation_code (8, UnknownVal UnknownRevocCode) =
    | 0     ->  NoReason, "No Reason Specified"
    | 1     ->  KeySuperseded, "Key is superseded"
    | 2     ->  KeyCompromised, "Key was compromised"
    | 3     ->  KeyRetired, "Key is retired"
    | 32    ->  UserIDObsoleted, "UserID is no longer valid"
    | 100   ->  PrivateUse
    | 101   ->  PrivateUse
    | 102   ->  PrivateUse
    | 103   ->  PrivateUse
    | 104   ->  PrivateUse
    | 105   ->  PrivateUse
    | 106   ->  PrivateUse
    | 107   ->  PrivateUse
    | 108   ->  PrivateUse
    | 109   ->  PrivateUse
    | 110   ->  PrivateUse

(* §5.2.3.23 *)
struct subpacket_revocation_reason_data = {
    code : revocation_code;
    reason : string
}

(* §5.2.3.24 *)
struct subpacket_features_data = {
    sfd_placeholder         : bit_int[7];
    modification_detection  : bit_bool;
    sfd_placeholder2        : binstring;
}

(* §5.2.3.25 *)
struct subpacket_signature_target_data = {
    sig_algo    : pubkey_sig_algo;
    hash_algo   : hash_algo;
    digest      : string(get_hash_len hash_algo input)
}

(* §5.2.3.1 *)
union subpacket_data [enrich] (UnparsedSubpacketData) =
    | SigCreationTime   -> SigCreationTimeData of timefield
    | SigExpirationTime -> SigExpirationTimeData of timefield
    | ExportableCertif  -> ExportableCertifData of byte_boolean
    | TrustSig          -> TrustSigData of subpacket_trust_signature_data
    | RegExp            -> RegExpData of subpacket_regular_expression_data
    | Revocable         -> RevocableData of byte_boolean
    | KeyExpirationTime -> KeyExpirationTimeData of timefield
    | PrefPrivkeyAlgo   -> PrefPrivkeyAlgoData of list of privkey_algo
    | RevocationKey     -> RevocationKeyData of subpacket_revocation_key_data
    | Issuer            -> IssuerData of pgp_keyid
    | NotationData      -> NotationDataData of subpacket_notation_data_data
    | PrefHashAlgo      -> PrefHashAlgoData of list of hash_algo
    | PrefCompressAlgo  -> PrefCompressAlgoData of list of compression_algo
    | KeyServerPrefs    -> KeyServerPrefsData of subpacket_key_server_prefs_data
    | PrefKeyServer     -> PrefKeyServerData of string
    | PrimaryUserID     -> PrimaryUserIDData of byte_boolean
    | PolicyURI         -> PolicyURIData of string
    | KeyFlags          -> KeyFlagsData of subpacket_key_flags_data
    | SignerUserID      -> SignerUserIDData of string
    | RevocReason       -> RevocReasonData of subpacket_revocation_reason_data
    | Features          -> FeaturesData of subpacket_features_data
    | SigTarget         -> SigTargetData of subpacket_signature_target_data
    | EmbeddedSig       -> EmbeddedSigData of binstring (* TODO OL signature_packet_content récursif : howto ? *)

(* §5.2.3.1 *)
struct signature_subpacket = {
    pcktLen     : subpacket_len; (* data len is this len minus the subpacket_type len *)
    critical    : bit_bool;
    pcktType    : subpacket_type;
    data        : container(pcktLen - 1) of subpacket_data(pcktType)
}

(* §5.2.1 *)
enum signature_type (8, UnknownVal UnknownSignatureType) =
    | 0x0   ->  BinaryDocumentSig, "Signature of a binary document"
    | 0x1   ->  TextDocumentSig, "Signature of a canonical text document"
    | 0x2   ->  StandAloneSig, "Standalone signature"
    | 0x10  ->  GenericCertif, "Generic certification of a User ID and Public Key packet"
    | 0x11  ->  PersonaCertif, "Persona certification of a User ID and Public Key packet"
    | 0x12  ->  CasualCertif, "Casual certification of a User ID and Public Key packet"
    | 0x13  ->  PositiveCertif, "Positive certification of a User ID and Public Key packet"
    | 0x18  ->  SubkeyBindingSig, "Subkey Binding Signature"
    | 0x19  ->  PrimaryKeyBindingSig, "Primary Key Binding Signature"
    | 0x1F  ->  DirectKeySig, "Signature directly on a key"
    | 0x20  ->  KeyRevocSig, "Key revocation signature"
    | 0x28  ->  SubKeyRevocSig, "Subkey revocation signature"
    | 0x30  ->  CertifRevocSig, "Certification revocation signature"
    | 0x40  ->  TimestampSig, "Timestamp signature"
    | 0x50  ->  TrdPartyConfirmSig, "Third-Party Confirmation signature"

(* §5.2.2 *)
struct signature_packet_content_version_3 = {
    hash_material_len       : magic("\x05");
    sig_type                : signature_type;
    creation_time           : timefield;
    keyid                   : pgp_keyid;
    sig_algo                : pubkey_sig_algo;
    hash_algo               : hash_algo;
    signed_hash_val_check   : uint16;
    signature               : signed_data(sig_algo);
}

(* §5.2.3 *)
let no_sig_creation_time l =
    let new_l = List.filter (fun sp -> sp.pcktType = SigCreationTime) l in
    new_l = []

(* §5.2.3 *)
struct signature_packet_content_version_4 = {
    sig_type                : signature_type;
    sig_algo                : pubkey_sig_algo;
    hash_algo               : hash_algo;
    hashed_subpackets_len   : uint16;
    hashed_subpackets       : container(hashed_subpackets_len) of list of signature_subpacket;
    parse_checkpoint _check_sig_creation_time : stop_if (no_sig_creation_time hashed_subpackets); (* at least one SigCreationTime Subpacket must be in the hashed_subpackets *)
    unhashed_subpackets_len : uint16;
    unhashed_subpackets     : container(unhashed_subpackets_len) of list of signature_subpacket;
    signed_hash_val_check   : uint16;
    signature               : signed_data(sig_algo);
}

(* §5.2.2 & §5.2.3 *)
union signature_packet_content_version [enrich] (UnparsedSignaturePacketContent) =
    | 3 -> V3SignaturePacket of signature_packet_content_version_3
    | 4 -> V4SignaturePacket of signature_packet_content_version_4

(* §5.2 *)
struct signature_packet_content = {
    version     : uint8;
    signature   : signature_packet_content_version(version);
}

(* §5.3 *)
struct symmetric_key_encrypted_session_key_packet_content = {
    version         : magic("\x04");
    cipher          : privkey_algo;
    s2kspecifier    : s2k_specifier;
    key             : binstring;
}

(* §5.4 *)
struct one_pass_signature_packet_content = {
    version     : magic("\x03");
    sig_type    : signature_type;
    hash_algo   : hash_algo;
    sig_algo    : pubkey_sig_algo;
    keyid       : pgp_keyid;
    not_nested  : byte_boolean;
}

(* §5.5.2 *)
struct public_key_packet_content_version3 = {
    date_created : timefield;
    lifetime     : uint16; (* number of days of validity *)
    v3_algo      : pubkey_algo;
    rsa_modulus  : mpint;
    rsa_exponent : mpint;
}

(* §5.5.2 *)
struct rsa_public_key_elements = {
    modulus  : mpint;
    exponent : mpint;
}

(* §5.5.2 *)
struct dsa_public_key_elements = {
    p : mpint;
    q : mpint;
    g : mpint;
    y : mpint;
}

(* §5.5.2 *)
struct elgamal_public_key_elements = {
    p : mpint;
    g : mpint;
    y : mpint;
}

(* §5.5.2 *)
union public_key [enrich] (UnparsedPublicKey) =
    | RSAEncryptAndSign_PubKeyAlgo -> RSAPublicKey of rsa_public_key_elements
    | RSAEncryptOnly_PubKeyAlgo    -> RSAPublicKey of rsa_public_key_elements
    | RSASignOnly_PubKeyAlgo       -> RSAPublicKey of rsa_public_key_elements
    | Elgamal_PubKeyAlgo           -> ElgamalPublicKey of elgamal_public_key_elements
    | DSA_PubKeyAlgo               -> DSAPublicKey of dsa_public_key_elements


(* §5.5.2 *)
struct public_key_packet_content_version4 = {
    date_created : timefield;
    v4_algo      : pubkey_algo;
    key          : public_key(v4_algo);

}

(* §5.5.2 *)
union public_key_packet_content2 [enrich] (UnparsedPublicKeyPacketContent) =
    | 3 -> PublicKeyPacketContentVersion3 of public_key_packet_content_version3
    | 4 -> PublicKeyPacketContentVersion4 of public_key_packet_content_version4

let get_algo_from_public_key_packet_content2 = function
    | PublicKeyPacketContentVersion3 p3 -> p3.v3_algo
    | PublicKeyPacketContentVersion4 p4 -> p4.v4_algo
    | _ -> failwith "Should not happen ?"


(* §5.5.1.1 *)
struct public_key_packet_content = {
    version : uint8;
    content : public_key_packet_content2(version);
}

(* §5.5.1.2 *)
alias public_sub_key_packet_content = public_key_packet_content

(* §5.5.1.3 *)
union checksum_or_digest_of_secret_key [enrich] (TwoBytesChecksum of uint16) =
    | 254   -> SHA1Checksum of binstring(get_hash_len SHA1Algo input) (* SHA-1 checksum *)

(* %5.5.3 *)
struct rsa_private_key_elements = {
    d : mpint;
    p : mpint;
    q : mpint;
    u : mpint;
}

(* §5.5.3 *)
union private_key [enrich] (UnparsedPrivateKey) =
    | RSAEncryptAndSign_PubKeyAlgo -> RSAPublicKey of rsa_private_key_elements
    | RSAEncryptOnly_PubKeyAlgo    -> RSAPublicKey of rsa_private_key_elements
    | RSASignOnly_PubKeyAlgo       -> RSAPublicKey of rsa_private_key_elements
    | Elgamal_PubKeyAlgo           -> ElgamalPublicKey of mpint
    | DSA_PubKeyAlgo               -> DSAPublicKey of mpint



(* Secret-Key Encryption § 3.7.2.1 *)
alias iv [param cipher] = binstring(get_privkeyalgo_block_size cipher)


(* Secret-Key Encryption § 3.7.2.1 *)
struct s2k_and_secret_data = {
    cipher        : privkey_algo;
    s2kspecifier  : s2k_specifier;
    data          : binstring; (* TODO ciphered_secret_data(cipher); *)
    iv            : iv(cipher);
}

(* Secret-Key Encryption § 3.7.2.1 *)
enum secret_key_encryption_algo (8, UnknownVal PrivKeyAlgo) =
    | 0     ->  UnencryptedSecretData
    | 254   ->  S2K
    | 255   ->  S2K

union secret_key_encryption_data [enrich; exhaustive] (UnparsedSecretKeyEncryptionData) =
    | UnencryptedSecretData  ->  SymmetricEncryptedSessionKeyPacket of symmetric_key_encrypted_session_key_packet_content
    | S2K                    ->  S2KAndSecretData of s2k_and_secret_data
    | PrivKeyAlgo _algorithm ->  CipheredSecretData of binstring (* TODO ciphered_secret_data(privkey_algo_of_int _algorithm) *)

struct secret_key_encryption = {
    algorithm   : secret_key_encryption_algo;
    data        : secret_key_encryption_data(algorithm);
}


(* §5.5.1.3 *)
struct secret_key_packet_content = {
    version     : uint8;
    pubkey      : public_key_packet_content2(version);
    ske_method  : secret_key_encryption;
    checksum    : checksum_or_digest_of_secret_key(int_of_secret_key_encryption_algo ske_method.algorithm);
    privkey     : private_key(get_algo_from_public_key_packet_content2 pubkey);
}

(* §5.5.1.4 *)
alias secret_sub_key_packet_content = secret_key_packet_content

(* §5.6 *)
union compressed_data [enrich] (UnparsedCompressedData) =
    | ZIPAlgo -> ZipCompressedData of ZLib.deflate_container of binstring (* TODO: recursive (list of packet) *)
    | ZLIBAlgo -> ZlibCompressedData of ZLib.zlib_container of binstring (* TODO: recursive (list of packet) *)
(*  TODO   | BZIP2Algo -> BZip2CompressedData of container(bzip2) of binstring (* TODO: recursive (list of packet) *) *)

(* §5.6 *)
struct compressed_data_packet_content = {
    algo : compression_algo;
    data : compressed_data(algo);
}

(* §5.9 *)
enum literal_data_format (8, UnknownVal UnknownLiteralDataFormat) =
    | 0x62  ->  BinaryLiteralDataFormat, "Binary format"
    | 0x74  ->  ASCIITextLiteralDataFormat, "ASCII text format"
    | 0x75  ->  UTF8LiteralDataFormat, "UTF-8 text format"
    | 0x6c  ->  LocalMachineEncodingLiteralDataFormat, "Machine-local conversions format"
    | 0x31  ->  LocalMachineEncodingLiteralDataFormat, "Machine-local conversions format" (* TODO OL: Simplify this into 0x6C | 0x31 -> *)

struct literal_data_packet_content = {
    data_format     : literal_data_format;
    filename_len    : uint8;
    filename        : string(filename_len);
    time_value      : timefield;
    data            : string;
}

(* §5.12 *)
enum user_attribute_subpacket_type(8, UnknownVal UnknownUserAttributeSubpacketType) =
    | 1     ->  ImageAttribute, "Image Attribute"
    | 100   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 101   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 102   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 103   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 104   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 105   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 106   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 107   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 108   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 109   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"
    | 110   ->  PrivateOrExperimental, "Private or Experimental User Attribute Subpacket"


(* §5.12.1 *)
enum user_attribute_image_header_1_encoding(8, UnknownVal UnknownUserAttributeImageHeader1Encoding) =
    | 1     -> UserAttributeImageHeader1EncodingJPEG, "User Attribute Image Header => JPEG"
    | 100   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 101   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 102   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 103   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 104   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 105   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 106   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 107   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 108   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 109   -> PrivateOrExperimental, "Private or Experimental Encoding"
    | 110   -> PrivateOrExperimental, "Private or Experimental Encoding"

(* §5.12.1 *)
struct user_attribute_image_header_1 = {
    encoding    : user_attribute_image_header_1_encoding;
    placeholder : list(12) of magic("\x00");
}

(* §5.12.1 *)
enum user_attribute_image_header_version (8, UnknownVal UnknownUserAttributeImageHeaderVersion) =
    | 1 -> ImageHeaderVersion1

(* §5.12.1 *)
union user_attribute_image_header_content [enrich] (UnparsedUserAttributeImageHeaderContent) =
    | ImageHeaderVersion1 -> ImageHeader1 of user_attribute_image_header_1

(* §5.12.1 *)
struct user_attribute_image_subpacket = {
    parse_checkpoint structure_start : save_offset;
    len             : uint16le;
    header_version  : user_attribute_image_header_version;
    header          : container(len - (input.cur_offset - structure_start)) of user_attribute_image_header_content(header_version); (* len includes its own length... *)
    image           : binstring;
}

(* §5.12 *)
union user_attribute_subpacket_content [enrich] (UnparsedUserAttributeSubpacketContent) =
    | ImageAttribute -> ImageAttributeData of user_attribute_image_subpacket

(* §5.12 *)
struct user_attribute_subpacket = {
    len             : subpacket_len;
    subpacket_type  : user_attribute_subpacket_type;
    data            : container(len) of user_attribute_subpacket_content(subpacket_type);
}

(* §5.13 *)
struct symmetrically_encrypted_and_integrity_protected_packet_content = {
    version : magic("\x01");
    data    : binstring; (* Contains a ciphered list of packets, the last one having to be a Modification Detection Code packet *)
}

(* §4.3 *)
union packet_content [enrich] (UnparsedPacket) =
    | PublicKeyEncryptedSessionKeyPacketType                    ->  PublicKeyEncryptedSessionKeyPacketContent of public_key_encrypted_session_key_packet_content
    | SignaturePacketType                                       ->  SignaturePacketContent of signature_packet_content
    | SymmetricKeyEncryptedSessionKeyPacketType                 ->  SymmetricKeyEncryptedSessionKeyPacketContent of symmetric_key_encrypted_session_key_packet_content
    | OnePassSignaturePacketType                                ->  OnePassSignaturePacketContent of one_pass_signature_packet_content
    | SecretKeyPacketType                                       ->  SecretKeyPacketContent of secret_key_packet_content
    | PublicKeyPacketType                                       ->  PublicKeyPacketContent of public_key_packet_content
    | SecretSubKeyPacketType                                    ->  SecretSubKeyPacketContent of secret_sub_key_packet_content
    | CompressedDataPacketType                                  ->  CompressedDataPacketContent of compressed_data_packet_content
    | SymmetricallyEncryptedDataPacketType                      ->  SymmetricallyEncryptedDataPacketContent of binstring (* §5.7 *) (* TODO code a CFB container to actually decrypt the content of the string ; have a context to know how to decrypt it from a previous SymmetricKeyEncryptedSessionKeyPacketType or PublicKeyEncryptedSessionKeyPacketType *)
    | MarkerPacketType                                          ->  MarkerPacketContent of magic("PGP") (* §5.8 *)
    | LiteralDataPacketType                                     ->  LiteralDataPacketContent of literal_data_packet_content
    | TrustPacketType                                           ->  TrustPacketContent of binstring (* §5.10 *) (* TODO Is just an opaque implementation-dependant blob ; see if this is used by some softwares like GnuPG and reverse the format *)
    | UserIDPacketType                                          ->  UserIDPacketContent of string (* §5.11 *)
    | PublicSubKeyPacketType                                    ->  PublicSubKeyPacketContent of public_sub_key_packet_content
    | UserAttributePacketType                                   ->  UserAttributePacketContent of list of user_attribute_subpacket (* §5.12 *)
    | SymmetricallyEncryptedAndIntegrityProtectedPacketType     ->  SymmetricallyEncryptedAndIntegrityProtectedPacketContent of symmetrically_encrypted_and_integrity_protected_packet_content
    | ModificationDetectionCodePacketType                       ->  ModificationDetectionCodePacketContent of binstring(get_hash_len SHA1Algo input) (* §5.14 *) (* SHA1 is hardcoded in the RFC... *)


type 'a partial_len_container = 'a

let parse_partial_len_container tag first_partial_len name parse_fun input =
    let rec gather_residual_content buf input =
        match (parse_packet_len tag input) with
        | FixedLen x -> begin
(*    Printf.printf "Got last len of %d (%d) \n" x (POutput.length buf); *)
            POutput.add_string buf (parse_string x input) ;
            POutput.contents buf
            end
        | PartialLen x -> begin
(*    Printf.printf "Got intermediate len of %d (%d) \n" x (POutput.length buf); *)
            POutput.add_string buf (parse_string x input) ;
            gather_residual_content buf input
            end
        | UndeterminateLen ->
            POutput.add_string buf (parse_rem_string input) ;
            POutput.contents buf
    in
    let buf = POutput.create () in
    let str = parse_string first_partial_len input in
(*    Printf.printf "Got initial partial len of %d\n" first_partial_len; *)
    POutput.add_string buf str ;
    let new_input = get_in_container input name (gather_residual_content buf input) in
    let res = parse_fun tag.packet_type new_input in
    check_empty_input true new_input;
    res


let dump_partial_len_container (* _tag _first_partial_len *) _dump_fun _buf _o =
    not_implemented "yeah, sure, someday"

let value_of_partial_len_container = value_of_container

(* §4.2 *)
union packet_content_container [param tag ; enrich ; exhaustive] (UnparsedPacketContentContainer) =
    | FixedLen length   -> PacketContentContainer of container(length) of packet_content(tag.packet_type)
    | PartialLen length -> PacketContentContainer of partial_len_container(tag ; length) of packet_content
    | UndeterminateLen  -> PacketContentOfIndeterminateLen of packet_content(tag.packet_type)

(* §4.2 *)
struct packet_len_and_content [both_param tag] = {
    len     : packet_len[tag];
    content : packet_content_container(tag ; len);
}

(* § 4.1 *)
struct packet = {
    tag                     : packet_tag;
    len_and_content         : packet_len_and_content(tag ; DUMP packet.tag);
            (* TODO OL (partial body lengths) list of packet_len_and_content(tag); *)
            (* TODO First Partial Body Len MUST NOT be less than 512 *)
            (* TODO Last Length cannot by Partial Body Len *)
}

(* §4.1 *)
(* TODO §5.1 "0 or more public key encrypted session key packets and/or symmetric key encrypted session key packet may precede symmetrically encrypted data packet" *)
alias openpgp_message = list of packet


(* XXX TODO develop radix-64 and ASCII Armoring containers *)


alias junk_to_armor = string

let parse_junk_to_armor input =
    let rec locate_armor offset input = (* returns the offset of the opening banner *)
        if String.sub input.str offset 5 = "-----" then
            offset
        else begin
            let next_offset =
                try
                    1 + String.index_from input.str offset '\n'
                with Not_found ->
                    raise (ParsingException (CustomException "Cannot find start of armor before end of buffer", _h_of_si input))
            in
            locate_armor next_offset input
        end
    in
    let waste_length = (locate_armor input.cur_offset input) - input.cur_offset in
    parse_string waste_length input

alias conditional_string = string
let parse_conditional_string predicate input =
    let rec parse_ignored_string_aux acc predicate input =
        let next_char = (peek_uint8 input) in
        if (predicate next_char) then begin
            POutput.add_char acc (char_of_int (parse_uint8 input)) ;
            parse_ignored_string_aux acc predicate input
        end else
           POutput.contents acc
    in
    let buf = POutput.create () in
    parse_ignored_string_aux buf predicate input

alias whitespace = conditional_string(fun x -> match x with | 0x20 | 0x9 -> true | _ -> false)

alias message_type = string

let parse_message_type input =
    let rtrim s =
        let rec rtrim_aux pos s =
            if pos < 0 then
                ""
            else
                let chr = String.get s pos in
                match int_of_char chr with
                | 0x20 | 0x9 -> rtrim_aux (pos - 1) s
                | _ -> Str.string_before s (pos+1)
        in
        rtrim_aux ((String.length s) - 1) s
    in
    try
        let end_offset = String.index_from input.str input.cur_offset '-' in
        let len = end_offset - input.cur_offset in
        let title = String.sub input.str input.cur_offset len in
        let trimmed_title = rtrim title in
        let trimmed_len = String.length trimmed_title in
        parse_string trimmed_len input
    with Not_found ->
        failwith "Incomplete header"

struct opening_title_banner = {
    dash1           : magic("-----");
    ws1             : whitespace;
    begin_pgp       : magic("BEGIN PGP ");
    msg_type_begin  : message_type;
    ws2             : whitespace;
    dash2           : magic("-----");
    ws3             : whitespace;
    lf              : magic("\x0A");
}

struct ending_title_banner [param title] = {
    dash1       : magic("-----");
    ws1         : whitespace;
    end_pgp     : magic("END PGP ");
    msg_type_end: message_type;
    parse_checkpoint : stop_if(title.msg_type_begin <> msg_type_end);
    ws2         : whitespace;
    dash2       : magic("-----");
    ws3         : whitespace;
    lf          : magic("\x0A");
}

type 'a radix64_body_container = 'a

let parse_radix64_body_container name parse_fun input =
    let checksum_pattern = Str.regexp "\n=" in
    let pattern_offset =
        try
            Str.search_forward checksum_pattern input.str input.cur_offset
        with Not_found ->
            raise (ParsingException (CustomException "Cannot find checksum magic before end of input", _h_of_si input))
    in
    let new_input = get_in_container input name (parse_string (pattern_offset - input.cur_offset) input) in
    let res = parse_fun new_input in
    check_empty_input true new_input ;
    res

let dump_radix64_body_container dump_fun buf i =
    dump_fun buf i

let value_of_radix64_body_container val_fun i =
    val_fun i

alias radix64_checksum = uint32

let parse_radix64_checksum input =
    let rec build_list_val cnt l input =
        if cnt <= 0 then
            l
        else
            let c = parse_uint8 input in
            let v = Base64.reverse_base64_chars.(c) in
            build_list_val (cnt - 1) (v::l) input
    in
    let buf = POutput.create () in
    let listval = (build_list_val 4 [] input) in
    let _ = Base64.decode_rev_chunk buf listval in
    ((POutput.byte_at buf 0) lsl 16) lor ((POutput.byte_at buf 1) lsl 8) lor (POutput.byte_at buf 2)

let dump_radix64_checksum _buf _radix64_checksum = not_implemented "yeah"

alias base64_openpgp_message = openpgp_message (* TODO: Why not directly base64_container of message? *)
let parse_base64_openpgp_message input =
    Base64.parse_base64_container Base64.NoHeader "base64_openpgp_message" parse_openpgp_message input

alias armor_header_name = conditional_string((fun x -> not (x = 0x3a))) (* parse until ':' *)

alias armor_header_value = conditional_string((fun x -> not (x = 0xa))) (* parse until lf *)

struct armor_header = {
    parse_checkpoint : stop_if( (peek_uint8 input) = (int_of_char '\n') ) ; (* detect a empty line *)
    name : armor_header_name;
    separator : magic(": ");
    value : armor_header_value;
    eol : magic("\n");
}

struct armored_openpgp_message = {
    placeholder : junk_to_armor ;
    title : opening_title_banner ;
    headers : list of armor_header;
    headers_sep : magic("\n");
    body : radix64_body_container of base64_openpgp_message ;
    body_sep : magic("\x0A=");
    checksum : radix64_checksum ;
    checksum_sep : magic("\x0A");
    trailer : ending_title_banner(title) ;
    placeholder2 : rem_binstring
}

let _ =
    try
        let input = string_input_of_filename Sys.argv.(1) in
        let msg = parse_armored_openpgp_message input in
        print_endline (Json.json_of_value (value_of_armored_openpgp_message msg))
    with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
