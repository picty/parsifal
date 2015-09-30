let md5sum s = Cryptokit.hash_string (Cryptokit.Hash.md5 ()) s;;
let sha1sum s = Cryptokit.hash_string (Cryptokit.Hash.sha1 ()) s;;
let sha256sum s = Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) s;;
let sha384sum s = Cryptokit.hash_string (Cryptokit.Hash.sha384 ()) s;;
let sha512sum s = Cryptokit.hash_string (Cryptokit.Hash.sha512 ()) s;;
let sha224sum s = Cryptokit.hash_string (Cryptokit.Hash.sha224 ()) s;;

let exp_mod m exp n =
  let key = {
    Cryptokit.RSA.size = (String.length n) * 8;
    Cryptokit.RSA.n = n;
    Cryptokit.RSA.e = exp;
    Cryptokit.RSA.d = "";
    Cryptokit.RSA.p = "";
    Cryptokit.RSA.q = "";
    Cryptokit.RSA.dp = "";
    Cryptokit.RSA.dq = "";
    Cryptokit.RSA.qinv = "";
  } in
  Cryptokit.RSA.encrypt key m
