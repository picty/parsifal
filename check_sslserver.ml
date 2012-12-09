(* check_sslserver: TODO

Probe should take as an input a CH and return a result after trying to establish a complete connexion.

Protocol Versions:
 - check the accepted SSL version
 - determine the preferred version (with different stimuli (SSLv2 CH, other TLS CH)
 - check the version intolerance (for example a CH 0x03ff)
 - check the coherency between record_version and clienthello_version
 - check the tolerance to various (record_version/clienthello_version)
 - check the consistency of the record_version during a session
 - check the tolerance to inconsistency of record_version during a session

Ciphersuites:
 - check the accepted ciphersuites
 - determine the preferred ciphersuites (with different stimuli)
 - determine the choice algorithm (directive or courteous)

Compression Methods:
 - check the accepted comrpession methods

Extensions:
 - determine the accepted extensions
 - check for extension intolerance
 - SNI support
 - Secure Renego support
 - insecure renego tolerance
 - support for client-initiated renego

Random:
 - check for the ServerRandom quality (is it constant? does it depend on the ClientRandom?)

Session resumption
 - check wether session resumption works (session id, session ticket)

SKE:
 - quality of the DHE group
 - quality of the DHE element (is it random? is it used only once?)
 - quality of the ECDHE group
 - quality of the ECDHE element (is it random? is it used only once?)
 - support for EC

CKE:
 - check whether the CKE anti-downgrade mechanism is checked
   * the first time
   * in case of renegotiation or session resumption
 - check the different versions to write 0 in DHE
 - check the server avoids DHE values in {-1;0;1}

Record protocol
 - one Handshake message spanning over several records
 - several Handshake messages inside one record
 - messages split in 10-byte records, in (2^14 + 1)-byte records
 - tolerance to empty records (HS, CCS, Alert, App)
 - tolerance to 1-byte records (HS, Alert, App)
 - tolerance to a warning Alert between two Handhake messages
 - tolerance to a warning Alert in the middle of a Handhake message
 - misplacement/removal of CCS messages
 - tolerance to warning/fatal Alerts
 - reaction to AppData received during a Handshake (the first one or subsequent renegos)

Certificates
 - Serial numbers
 - Duplicate certificates
 - Unused certificates
 - Missing certificates
 - Algorithms/Key sizes
 - X.509 extensions
   * BasicConstraints
   * Key Usage, ExtendedKeyUsage, NSCertType
   * CertificatePolicies, EV
   * SKI, AKI
 - DN qulity
 - Correct denomination of the server (CN + SAN)
 - Validity dates
 - Revocation state *)

