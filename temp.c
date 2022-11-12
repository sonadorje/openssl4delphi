#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

unsigned char * aes_oneshot_encrypt( unsigned char * key, int key_len,
                                     unsigned char * salt, int salt_len,
                                     unsigned char * data, int data_len,
                                     int * out_len)
{
   int             nalloc    = 0;
   int             npartial  = 0;
   int             nfinal    = 0;
   unsigned char * encrypted = 0;
   unsigned char   key_buff[SHA256_DIGEST_LENGTH];
   unsigned char   iv_buff[SHA256_DIGEST_LENGTH];

   *out_len = 0;
   
   SHA256( key, key_len, key_buff );
   SHA256( salt, salt_len, iv_buff );

   EVP_CIPHER_CTX ctx;

   EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key_buff, iv_buff);

   nalloc = data_len + EVP_CIPHER_CTX_block_size(&ctx);

   encrypted = malloc( nalloc );

   EVP_EncryptUpdate(&ctx, encrypted, &npartial, data, data_len);

   
   EVP_EncryptFinal_ex(&ctx, encrypted+npartial, &nfinal);

   *out_len = npartial + nfinal;
   
   return encrypted;
}

int main( int argc, char * argv[] )
{
   int             nbytes = 0;
   char *          key    = "foobar";
   char *          salt   = "wallace";
   char *          data   = "abandon all hope ye who enter here";
   unsigned char * enc    = 0;
   FILE *          out;

   enc = aes_oneshot_encrypt( (unsigned char *)key, strlen(key),
                              (unsigned char *)salt, strlen(salt),
                              (unsigned char *)data, strlen(data),
                              &nbytes );

   out = fopen("/tmp/tenc", "wb");
   fwrite( enc, 1, nbytes, out );
   fclose(out);
   
   return 0;
}