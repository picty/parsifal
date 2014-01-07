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
    | 0  ->  ReservedPacketType
    | 1  ->  PublicKeyEncryptedSessionKeyPacketType
    | 2  ->  SignaturePacketType
    | 3  ->  SymmetricKeyEncryptedSessionKeyPacketType
    | 4  ->  OnePassSignaturePacketType
    | 5  ->  SecretKeyPacketType
    | 6  ->  PublicKeyPacketType
    | 7  ->  SecretSubKeyPacketType
    | 8  ->  CompressedDataPacketType
    | 9  ->  SymmetricallyEncryptedDataPacketType
    | 10 ->  MarkerPacketType
    | 11 ->  LiteralDataPacketType
    | 12 ->  TrustPacketType
    | 13 ->  UserIDPacketType
    | 14 ->  PublicSubKeyPacketType
    | 17 ->  UserAttributePacketType
    | 18 ->  SymmetricallyEncryptedAndIntegrityProtectedPacketType
    | 19 ->  ModificationDetectionCodePacketType
    | 60 ->  PrivatePacketType
    | 61 ->  PrivatePacketType
    | 62 ->  PrivatePacketType
    | 63 ->  PrivatePacketType


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
let value_of_packet_type packet_type =
    VEnum (string_of_packet_type_enum packet_type,
           int_of_packet_type_enum packet_type, 0, Parsifal.BigEndian)

(* §4.2 & §4.3 *)
struct packet_tag = {
    packet_magic : bit_magic (true);
    packet_version : bit_bool;
    packet_type : packet_type(packet_version; DUMP packet_tag.packet_version);   (* TODO OL: Fix this *)
    packet_length_type : conditional_container(not packet_version) of bit_int[2];
}


(*type packet_tag =
    | UnknownPacketType of uint8
    | ReservedPacketType of uint8
    | PublicKeyEncryptedSessionKeyPacketType of uint8
    | SignaturePacketType of uint8
    | SymmetricKeyEncryptedSessionKeyPacketType of uint8
    | OnePassSignaturePacketType of uint8
    | SecretKeyPacketType of uint8
    | PublicKeyPacketType of uint8
    | SecretSubKeyPacketType of uint8
    | CompressedDataPacketType of uint8
    | SymmetricallyEncryptedDataPacketType of uint8
    | MarkerPacketType of uint8
    | LiteralDataPacketType of uint8
    | TrustPacketType of uint8
    | UserIDPacketType of uint8
    | PublicSubKeyPacketType of uint8
    | UserAttributePacketType of uint8
    | SymmetricallyEncryptedAndIntegrityProtectedPacketType of uint8
    | ModificationDetectionCodePacketType of uint8
    | PrivatePacketType of uint8


let parse_packet_tag input =
    let ptag = parse_byte input in
    if (ptag land 0x80) != 0 then
        (* bit_magic? *)
        raise (ParsingException (CustomException "Packet Tag 0x80 bit must be one", _h_of_si input)) ;
    let ptype =
        if (ptag land 0x40) != 0 then
            (* New format *)
            ptag land 0x3f
        else
            (* Old format *)
            ((ptag lsr 2) land 0x0F)
    in
    match ptype with
    | 0  ->  raise(ParsingException (CustomException "Packet Type 0 is reserved and MUST NOT be used", _h_of_si input))
    | 1  ->  PublicKeyEncryptedSessionKeyPacketType ptag
    | 2  ->  SignaturePacketType ptag
    | 3  ->  SymmetricKeyEncryptedSessionKeyPacketType ptag
    | 4  ->  OnePassSignaturePacketType ptag
    | 5  ->  SecretKeyPacketType ptag
    | 6  ->  PublicKeyPacketType ptag
    | 7  ->  SecretSubKeyPacketType ptag
    | 8  ->  CompressedDataPacketType ptag
    | 9  ->  SymmetricallyEncryptedDataPacketType ptag
    | 10 ->  MarkerPacketType ptag
    | 11 ->  LiteralDataPacketType ptag
    | 12 ->  TrustPacketType ptag
    | 13 ->  UserIDPacketType ptag
    | 14 ->  PublicSubKeyPacketType ptag
    | 17 ->  UserAttributePacketType ptag
    | 18 ->  SymmetricallyEncryptedAndIntegrityProtectedPacketType ptag
    | 19 ->  ModificationDetectionCodePacketType ptag
    | 60 | 61 | 62 | 63 ->  PrivatePacketType ptag
    | _ -> UnknownPacketType ptag
*)

(* §4.2.1 & §4.2.2 *)
type packet_len = uint32

let parse_packet_len packet_tag input =
    match packet_tag.packet_version, packet_tag.packet_length_type with
    | false, Some 0 -> parse_uint8 input
    | false, Some 1 -> parse_uint16 input
    | false, Some 2 -> parse_uint32 input
    | false, Some 3 -> failwith "DIE!"
    | true, None ->
        let first = parse_uint8 input in
        if first <= 191 then first
        else if first <= 223 then (((first - 192) lsl 8) lor (parse_uint8 input)) + 192
        else if first = 255 then parse_uint32 input
        else not_implemented "Partial Body Lengths 4.2.2.4"
            (* 1 lsl ( land 0x1F) *)
            (* TODO First Partial Body Len MUST NOT be less than 512 *)
            (* TODO Last Length cannot by Partial Body Len *)
    | _ -> failwith "Inconsistent values for version/length type"

let dump_packet_len _buf _ = not_implemented "dump_packet_len" (* TODO *)

let value_of_packet_len l = VSimpleInt l


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

let dump_subpacket_len _buf _ = not_implemented "dump_subpacket_len" (* TODO *)

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
    srkd_magic1 : bit_magic(true);
    sensitive   : bit_bool;
    srkd_stuff  : bit_int[6];
    sig_algo    : pubkey_sig_algo;
    fingerprint : binstring(get_hash_len SHA1Algo input)
}

(* §5.2.3.16 *)
struct subpacket_notation_data_data = {
    human_readable : bit_bool;
    sndd_placeholder : bit_int[31];
    namelen : uint16;
    vallen  : uint16;
    name    : string(namelen);
    value   : string(vallen);
}

(* §5.2.3.18 *)

struct subpacket_key_server_prefs_data = {
  no_modify : bit_bool;
  skspd_placeholder : list(7) of bit_magic(false); (* TODO OL: bit_int_magic(length, expected_value) *)
  skspd_placeholder2 : binstring;
}


(* §5.2.3.21 *)
struct subpacket_key_flags_data = {
    groupPrivKey : bit_bool; (* XXX TODO should be placed only on direct sign of self-sig *)
    skfd_placeholder : bit_bool;
    authOKKey : bit_bool;
    splitPrivKey : bit_bool; (* XXX TODO should be placed only on direct sign of self-sig *)
    storageEncryptionUsage : bit_bool;
    communicationEncryptionUsage : bit_bool;
    signUsage : bit_bool;
    certificationUsage : bit_bool;
}

(* §5.2.3.23 *)
enum revocation_code (8, UnknownVal UnknownRevocCode) =
    | 0     ->  NoReason
    | 1     ->  KeySuperseded
    | 2     ->  KeyCompromised
    | 3     ->  KeyRetired
    | 32    ->  UserIDObsoleted
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
    sfd_placeholder : bit_int[7];
    modification_detection : bit_bool;
    sfd_placeholder2 : binstring;
}

(* §5.2.3.25 *)
struct subpacket_signature_target_data = {
    sig_algo    :   pubkey_sig_algo;
    hash_algo   :   hash_algo;
    digest      :   string(get_hash_len hash_algo input)
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

struct signature_packet_content_version_4 = {
    sig_type                : signature_type;
    sig_algo                : pubkey_sig_algo;
    hash_algo               : hash_algo;
    hashed_subpackets_len   : uint16;
    hashed_subpackets       : container(hashed_subpackets_len) of list of signature_subpacket;
(*    parse_checkpoint _check_sig_creation_time : stop_if (no_sig_creation_time hashed_subpackets); *)
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
(* XXX This type is an alias of public_key_packet_content as they have the exact same definition in the RFC and are told to be duplicates on purpose. I choose to create an alias just in case of future changes and to keep "inline" the different meaning *)
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



(* TODO: Move this somewhere relevant? *)

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
(* XXX On a le droit d'utiliser un constructeur d'enum comme UnknownVal ? *)
enum secret_key_encryption_algo (8, UnknownVal PrivKeyAlgo) =
    | 0     ->  UnencryptedSecretData
    | 254   ->  S2K
    | 255   ->  S2K

union secret_key_encryption_data [enrich; exhaustive] (UnparsedSecretKeyEncryptionData) =
    | UnencryptedSecretData  ->  SymmetricEncryptedSessionKeyPacket of symmetric_key_encrypted_session_key_packet_content (* (PlainTextAlgo) (*XXX cipher null, trouver comment passer une constante*) *)
    | S2K                    ->  S2KAndSecretData of s2k_and_secret_data
    | PrivKeyAlgo _algorithm ->  CipheredSecretData of binstring (* TODO ciphered_secret_data(privkey_algo_of_int _algorithm) *)

struct secret_key_encryption = {
    algorithm   : secret_key_encryption_algo;
    data        : secret_key_encryption_data(algorithm);
}

(* TODO: End of move *)



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
    | 1     ->  ImageAttribute
    | 100   ->  PrivateOrExperimental
    | 101   ->  PrivateOrExperimental
    | 102   ->  PrivateOrExperimental
    | 103   ->  PrivateOrExperimental
    | 104   ->  PrivateOrExperimental
    | 105   ->  PrivateOrExperimental
    | 106   ->  PrivateOrExperimental
    | 107   ->  PrivateOrExperimental
    | 108   ->  PrivateOrExperimental
    | 109   ->  PrivateOrExperimental
    | 110   ->  PrivateOrExperimental


(* §5.12.1 *)
enum user_attribute_image_header_1_encoding(8, UnknownVal UnknownUserAttributeImageHeader1Encoding) =
    | 1     -> UserAttributeImageHeader1EncodingJPEG
    | 100   -> PrivateOrExperimental
    | 101   -> PrivateOrExperimental
    | 102   -> PrivateOrExperimental
    | 103   -> PrivateOrExperimental
    | 104   -> PrivateOrExperimental
    | 105   -> PrivateOrExperimental
    | 106   -> PrivateOrExperimental
    | 107   -> PrivateOrExperimental
    | 108   -> PrivateOrExperimental
    | 109   -> PrivateOrExperimental
    | 110   -> PrivateOrExperimental

(* §5.12.1 *)
struct user_attribute_image_header_1 = {
    encoding    : user_attribute_image_header_1_encoding;
    placeholder : magic("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
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
    header          : container(len - (input.cur_offset - structure_start)) of user_attribute_image_header_content(header_version);
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
    | UserIDPacketType                                          ->  UserIDPacketContent of string (* §5.11 *) (* XXX UTF-8 : is there a specific data type *)
    | PublicSubKeyPacketType                                    ->  PublicSubKeyPacketContent of public_sub_key_packet_content
    | UserAttributePacketType                                   ->  UserAttributePacketContent of list of user_attribute_subpacket (* §5.12 *)
    | SymmetricallyEncryptedAndIntegrityProtectedPacketType     ->  SymmetricallyEncryptedAndIntegrityProtectedPacketContent of symmetrically_encrypted_and_integrity_protected_packet_content
    | ModificationDetectionCodePacketType                       ->  ModificationDetectionCodePacketContent of binstring(get_hash_len SHA1Algo input) (* §5.14 *) (* SHA1 is hardcoded in the RFC... *)

(* §4.2 *)
struct packet_len_and_content [param tag] = {
    len     : packet_len(tag);
    content : container(len) of packet_content(tag.packet_type);
}

(* § 4.1 *)
struct packet = {
    tag             : packet_tag;
    lenAndContent   : packet_len_and_content(tag); (* TODO OL (partial body lengths) list of packet_len_and_content(tag); *)
}

(* §4.1 *)
(* TODO §5.1 "0 or more public key encrypted session key packets and/or symmetric key encrypted session key packet may precede symmetrically encrypted data packet" *)
alias openpgp_message = list of packet



(* XXX TODO develop radix-64 and ASCII Armoring containers *)

let _ =
    try
        let input = string_input_of_filename Sys.argv.(1) in
        let msg = parse_packet input in
        print_endline (print_value (value_of_packet msg))
    with
    | ParsingException (e, h) -> prerr_endline (string_of_exception e h); exit 1
    | e -> prerr_endline (Printexc.to_string e); exit 1
