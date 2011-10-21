open Ocamlbuild_plugin;;
open Command;;

dispatch begin function
  | After_rules ->
    dep ["link"; "ocaml"; "use_crypto"] ["crypto/libcrypto.a"];

    flag ["c"; "compile"; "crypto_implem"] (S[A"-ccopt"; A"-Icrypto"]);
    dep  ["c"; "compile"; "crypto_implem"] ["crypto/md5.h"; "crypto/sha1.h"];

  | _ -> ()
end
