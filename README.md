# This project based openssl3.x, c source code is translated to pascal.The project can be compiled by delphi XE7 above and lazarus and codeTyphon in windows. current version only support win64 and provide some test and demo appliction. 
TODO list
{$IFNDEF OPENSSL_NO_ARIA}
    {EVP_add_cipher(EVP_aria_128_ecb);
    EVP_add_cipher(EVP_aria_128_cbc);
    EVP_add_cipher(EVP_aria_128_cfb);
    EVP_add_cipher(EVP_aria_128_cfb1);
    EVP_add_cipher(EVP_aria_128_cfb8);
    EVP_add_cipher(EVP_aria_128_ctr);
    EVP_add_cipher(EVP_aria_128_ofb);
    EVP_add_cipher(EVP_aria_128_gcm);
    EVP_add_cipher(EVP_aria_128_ccm);
    EVP_add_cipher_alias(SN_aria_128_cbc, 'ARIA128');
    EVP_add_cipher_alias(SN_aria_128_cbc, 'aria128');
    EVP_add_cipher(EVP_aria_192_ecb);
    EVP_add_cipher(EVP_aria_192_cbc);
    EVP_add_cipher(EVP_aria_192_cfb);
    EVP_add_cipher(EVP_aria_192_cfb1);
    EVP_add_cipher(EVP_aria_192_cfb8);
    EVP_add_cipher(EVP_aria_192_ctr);
    EVP_add_cipher(EVP_aria_192_ofb);
    EVP_add_cipher(EVP_aria_192_gcm);
    EVP_add_cipher(EVP_aria_192_ccm);
    EVP_add_cipher_alias(SN_aria_192_cbc, 'ARIA192');
    EVP_add_cipher_alias(SN_aria_192_cbc, 'aria192');
    EVP_add_cipher(EVP_aria_256_ecb);
    EVP_add_cipher(EVP_aria_256_cbc);
    EVP_add_cipher(EVP_aria_256_cfb);
    EVP_add_cipher(EVP_aria_256_cfb1);
    EVP_add_cipher(EVP_aria_256_cfb8);
    EVP_add_cipher(EVP_aria_256_ctr);
    EVP_add_cipher(EVP_aria_256_ofb);
    EVP_add_cipher(EVP_aria_256_gcm);
    EVP_add_cipher(EVP_aria_256_ccm);
    EVP_add_cipher_alias(SN_aria_256_cbc, 'ARIA256');
    EVP_add_cipher_alias(SN_aria_256_cbc, 'aria256');}
{$ENDIF}
{$IFNDEF OPENSSL_NO_CAMELLIA}
    {EVP_add_cipher(EVP_camellia_128_ecb);
    EVP_add_cipher(EVP_camellia_128_cbc);
    EVP_add_cipher(EVP_camellia_128_cfb);
    EVP_add_cipher(EVP_camellia_128_cfb1);
    EVP_add_cipher(EVP_camellia_128_cfb8);
    EVP_add_cipher(EVP_camellia_128_ofb);
    EVP_add_cipher_alias(SN_camellia_128_cbc, 'CAMELLIA128');
    EVP_add_cipher_alias(SN_camellia_128_cbc, 'camellia128');
    EVP_add_cipher(EVP_camellia_192_ecb);
    EVP_add_cipher(EVP_camellia_192_cbc);
    EVP_add_cipher(EVP_camellia_192_cfb);
    EVP_add_cipher(EVP_camellia_192_cfb1);
    EVP_add_cipher(EVP_camellia_192_cfb8);
    EVP_add_cipher(EVP_camellia_192_ofb);
    EVP_add_cipher_alias(SN_camellia_192_cbc, 'CAMELLIA192');
    EVP_add_cipher_alias(SN_camellia_192_cbc, 'camellia192');
    EVP_add_cipher(EVP_camellia_256_ecb);
    EVP_add_cipher(EVP_camellia_256_cbc);
    EVP_add_cipher(EVP_camellia_256_cfb);
    EVP_add_cipher(EVP_camellia_256_cfb1);
    EVP_add_cipher(EVP_camellia_256_cfb8);
    EVP_add_cipher(EVP_camellia_256_ofb);
    EVP_add_cipher_alias(SN_camellia_256_cbc, 'CAMELLIA256');
    EVP_add_cipher_alias(SN_camellia_256_cbc, 'camellia256');
    EVP_add_cipher(EVP_camellia_128_ctr);
    EVP_add_cipher(EVP_camellia_192_ctr);
    EVP_add_cipher(EVP_camellia_256_ctr);}
{$ENDIF}
