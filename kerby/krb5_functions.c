
#include "krb5.h"
#include <krb5.h>
#include <stdlib.h>
#include <string.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))
//extern int krb5_c_decrypt(void *context, krb5_keyblock *key, int usage, void *cipher_state, krb5_enc_data *enc, krb5_data *plain);

int ML_krb5_c_decrypt(mykrb5_keyblock key, int usage, mykrb5_enc_data enc, mykrb5_data *decrypted){
	decrypted->length = enc.ciphertext.length;
	decrypted->data = malloc(decrypted->length * sizeof (char)); 
        int rv;
#ifdef HEIMDAL_DEPRECATED
	krb5_keyblock keyblock;

	memcpy(&keyblock, &key, MIN(sizeof(keyblock), sizeof(key)));
	rv = krb5_c_decrypt(NULL, keyblock, usage, NULL, (krb5_enc_data*)&enc, (krb5_data*)decrypted);
#else
	rv = krb5_c_decrypt(NULL, (krb5_keyblock*)&key, usage, NULL, (krb5_enc_data*)&enc, (krb5_data*)decrypted);
#endif
/*
	int i;
	printf("\nLen: %d\n", decrypted.length);
	for(i=0; i<decrypted.length ; i++){
		printf("%02x", (unsigned char) decrypted.data[i]);
	}
*/
	return rv;
}
