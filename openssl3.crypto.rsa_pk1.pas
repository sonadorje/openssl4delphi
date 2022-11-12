unit openssl3.crypto.rsa_pk1;

interface
 uses OpenSSL.Api;

 function ossl_rsa_padding_check_PKCS1_type_2_TLS(libctx : POSSL_LIB_CTX; &to : PByte; tlen : size_t;const from : PByte; flen : size_t; client_version, alt_version : integer):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.rand.rand_lib, openssl3.internal.constant_time;

function ossl_rsa_padding_check_PKCS1_type_2_TLS(libctx : POSSL_LIB_CTX; &to : PByte; tlen : size_t;const from : PByte; flen : size_t; client_version, alt_version : integer):integer;
var
  i,
good,
  version_good          : uint32;

    rand_premaster_secret : array[0..(SSL_MAX_MASTER_KEY_LENGTH)-1] of Byte;

    workaround_good       : uint32;
begin
    {
     * If these checks fail then either the message in publicly invalid, or
     * we've been called incorrectly. We can fail immediately.
     }
    if (flen < RSA_PKCS1_PADDING_SIZE + SSL_MAX_MASTER_KEY_LENGTH)
             or  (tlen < SSL_MAX_MASTER_KEY_LENGTH) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_PKCS_DECODING_ERROR);
        Exit(-1);
    end;
    {
     * Generate a random premaster secret to use in the event that we fail
     * to decrypt.
     }
    if RAND_priv_bytes_ex(libctx, @rand_premaster_secret,
                           sizeof(rand_premaster_secret ) , 0) <= 0 then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_INTERNAL_ERROR);
        Exit(-1);
    end;
    good := constant_time_is_zero(from[0]);
    good := good and constant_time_eq(from[1], 2);
    { Check we have the expected padding data }
    for i := 2 to flen - SSL_MAX_MASTER_KEY_LENGTH - 1-1 do
        good := good and (not constant_time_is_zero_8(from[i]));
    good := good and constant_time_is_zero_8(from[flen - SSL_MAX_MASTER_KEY_LENGTH - 1]);
    {
     * If the version in the decrypted pre-master secret is correct then
     * version_good will be $ff, otherwise it'll be zero. The
     * Klima-Pokorny-Rosa extension of Bleichenbacher's attack
     * (http://eprint.iacr.org/2003/052/) exploits the version number
     * check as a 'bad version oracle'. Thus version checks are done in
     * constant time and are treated like any other decryption error.
     }
    version_good := constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH],
                         (client_version  shr  8) and $ff);
    version_good := good and
        constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH + 1],
                         client_version and $ff);
    {
     * The premaster secret must contain the same version number as the
     * ClientHello to detect version rollback attacks (strangely, the
     * protocol does not offer such protection for DH ciphersuites).
     * However, buggy clients exist that send the negotiated protocol
     * version instead if the server does not support the requested
     * protocol version. If SSL_OP_TLS_ROLLBACK_BUG is set then we tolerate
     * such clients. In that case alt_version will be non-zero and set to
     * the negotiated version.
     }
    if alt_version > 0 then
    begin
        workaround_good := constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH],
                             (alt_version  shr  8) and $ff);
        workaround_good := good and
            constant_time_eq(from[flen - SSL_MAX_MASTER_KEY_LENGTH + 1],
                             alt_version and $ff);
        version_good  := version_good  or workaround_good;
    end;
    good := good and version_good;
    {
     * Now copy the result over to the to buffer if good, or random data if
     * not good.
     }
    for i := 0 to SSL_MAX_MASTER_KEY_LENGTH-1 do
    begin
        &to[i] := constant_time_select_8(good,
                                   from[flen - SSL_MAX_MASTER_KEY_LENGTH + i],
                                   rand_premaster_secret[i]);
    end;
    {
     * We must not leak whether a decryption failure occurs because of
     * Bleichenbacher's attack on PKCS #1 v1.5 RSA padding (see RFC 2246,
     * section 7.4.7.1). The code follows that advice of the TLS RFC and
     * generates a random premaster secret for the case that the decrypt
     * fails. See https://tools.ietf.org/html/rfc5246#section-7.4.7.1
     * So, whether we actually succeeded or not, return success.
     }
    Result := SSL_MAX_MASTER_KEY_LENGTH;
end;


end.
