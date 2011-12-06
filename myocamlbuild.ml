open Ocamlbuild_plugin;;
open Command;;

dispatch begin function
  | After_rules ->
    dep ["link"; "ocaml"; "use_crypto"] ["crypto/libcrypto.a"];
    flag ["link"; "ocaml"; "use_crypto"] (S[A"-cclib"; A"-lgmp"]);

    flag ["c"; "compile"; "crypto_implem"] (S[A"-ccopt"; A"-Icrypto"]);
    dep  ["c"; "compile"; "crypto_implem"] ["crypto/md5.h"; "crypto/sha1.h"; "crypto/sha2.h"; "crypto/sha4.h"];
    flag ["c"; "crypto_implem"; "ocamlmklib"] (S[A"-lgmp"]);

  | _ -> ()
end
