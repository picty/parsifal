external md5sum : string -> string = "md5sum"
external sha1sum : string -> string = "sha1sum"
external sha224_256sum : string -> bool -> string = "sha224_256sum"
external sha384_512sum : string -> bool -> string = "sha384_512sum"

external exp_mod : string -> string -> string -> string = "exp_mod"


let sha224sum s = sha224_256sum s true
let sha256sum s = sha224_256sum s false
let sha384sum s = sha384_512sum s true
let sha512sum s = sha384_512sum s false
