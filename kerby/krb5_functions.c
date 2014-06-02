
#include "krb5.h"
#include <krb5.h>
#include <stdlib.h>

//extern int krb5_c_decrypt(void *context, krb5_keyblock *key, int usage, void *cipher_state, krb5_enc_data *enc, krb5_data *plain);

int ML_krb5_c_decrypt(mykrb5_keyblock key, int usage, mykrb5_enc_data enc, mykrb5_data *decrypted){
	decrypted->length = enc.ciphertext.length;
	decrypted->data = malloc(decrypted->length * sizeof (char)); 
        int rv;
	rv = krb5_c_decrypt(NULL, (krb5_keyblock*)&key, usage, NULL, (krb5_enc_data*)&enc, (krb5_data*)decrypted);
/*
	int i;
	printf("\nLen: %d\n", decrypted.length);
	for(i=0; i<decrypted.length ; i++){
		printf("%02x", (unsigned char) decrypted.data[i]);
	}
*/
	return rv;
}
