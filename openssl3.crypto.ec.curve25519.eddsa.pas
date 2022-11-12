unit openssl3.crypto.ec.curve25519.eddsa;

interface
uses OpenSSL.Api;

const
   EDDSA_448_PUBLIC_BYTES = 57;
   EDDSA_448_PRIVATE_BYTES = EDDSA_448_PUBLIC_BYTES;
   EDDSA_448_SIGNATURE_BYTES = (EDDSA_448_PUBLIC_BYTES + EDDSA_448_PRIVATE_BYTES);
   COFACTOR = 4;
 function ossl_ed448_sign(ctx : POSSL_LIB_CTX; out_sig : PByte;const _message : PByte; message_len : size_t;const public_key, private_key : PByte{57}; context : PByte; context_len : size_t;const propq : PUTF8Char):integer;

function ossl_c448_ed448_sign(ctx : POSSL_LIB_CTX; signature : PByte;const privkey, pubkey : PByte; _message : PByte; message_len : size_t; prehashed : Byte;const context : PByte; context_len : size_t;const propq : PUTF8Char):c448_error_t;
procedure clamp( secret_scalar_ser : Pbyte);
function hash_init_with_dom(ctx : POSSL_LIB_CTX; hashctx : PEVP_MD_CTX; prehashed, for_prehash : byte;const context : PByte; context_len : size_t;const propq : PUTF8Char):c448_error_t;
function ossl_ed448_verify(ctx : POSSL_LIB_CTX;const _message : PByte; message_len : size_t;const signature, public_key : Pbyte; context : PByte; context_len : size_t;const propq : PUTF8Char):integer;
function oneshot_hash(ctx : POSSL_LIB_CTX; &out : PByte; outlen : size_t;const &in : PByte; inlen : size_t;const propq : PUTF8Char):c448_error_t;
function ossl_c448_ed448_verify(ctx : POSSL_LIB_CTX;const signature, pubkey : Pbyte; _message : PByte; message_len : size_t; prehashed : byte;const context : PByte; context_len : byte;const propq : PUTF8Char):c448_error_t;
function ossl_ed448_public_from_private(ctx : POSSL_LIB_CTX; out_public_key : Pbyte;const private_key : Pbyte; propq : PUTF8Char):integer;
function ossl_c448_ed448_derive_public_key(ctx : POSSL_LIB_CTX; pubkey : Pbyte;const privkey : Pbyte; propq : PUTF8Char):c448_error_t;

implementation
uses openssl3.crypto.evp.digest, openssl3.crypto.ec.curve448.scalar,
    openssl3.crypto.mem,
    openssl3.crypto.ec.curve448, openssl3.crypto.ec.curve448.curve448_tables;






function ossl_c448_ed448_derive_public_key(ctx : POSSL_LIB_CTX; pubkey : Pbyte;const privkey : Pbyte; propq : PUTF8Char):c448_error_t;
var
    secret_scalar_ser : array[0..(EDDSA_448_PRIVATE_BYTES)-1] of byte;

    secret_scalar     : curve448_scalar_t;

    c                 : uint32;

    p                 : curve448_point_t;
begin
    { only this much used for keygen }
    if 0>= Int(oneshot_hash(ctx, @secret_scalar_ser, sizeof(secret_scalar_ser),
                      privkey,
                      EDDSA_448_PRIVATE_BYTES,
                      propq)) then
        Exit(C448_FAILURE);
    clamp(@secret_scalar_ser);
    ossl_curve448_scalar_decode_long(secret_scalar, @secret_scalar_ser,
                                     sizeof(secret_scalar_ser));
    {
     * Since we are going to mul_by_cofactor during encoding, divide by it
     * here. However, the EdDSA base point is not the same as the decaf base
     * point if the sigma isogeny is in use: the EdDSA base point is on
     * Etwist_d/(1-d) and the decaf base point is on Etwist_d, and when
     * converted it effectively picks up a factor of 2 from the isogenies.  So
     * we might start at 2 instead of 1.
     }
    c := 1;
    while (c < C448_EDDSA_ENCODE_RATIO)  do
    begin
        ossl_curve448_scalar_halve(secret_scalar, secret_scalar);
        c := c  shl 1;
    end;
    ossl_curve448_precomputed_scalarmul(p, ossl_curve448_precomputed_base,
                                        secret_scalar);
    ossl_curve448_point_mul_by_ratio_and_encode_like_eddsa(pubkey, p);
    { Cleanup }
    ossl_curve448_scalar_destroy(secret_scalar);
    ossl_curve448_point_destroy(p);
    OPENSSL_cleanse(@secret_scalar_ser, sizeof(secret_scalar_ser));
    Result := C448_SUCCESS;
end;




function ossl_ed448_public_from_private(ctx : POSSL_LIB_CTX; out_public_key : Pbyte;const private_key : Pbyte; propq : PUTF8Char):integer;
begin
    Result := int(ossl_c448_ed448_derive_public_key(ctx, out_public_key, private_key,
                                             propq) = C448_SUCCESS);
end;





function ossl_c448_ed448_verify(ctx : POSSL_LIB_CTX;const signature{57+57}, pubkey{57} : Pbyte; _message : PByte; message_len : size_t; prehashed : byte;const context : PByte; context_len : byte;const propq : PUTF8Char):c448_error_t;

const // 1d arrays
  order : array[0..56] of byte = (
    $F3, $44, $58, $AB, $92, $C2, $78, $23, $55, $8F, $C5, $8D, $72, $C2,
    $6C, $21, $90, $36, $D6, $AE, $49, $DB, $4E, $C4, $E9, $23, $CA, $7C,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF,
    $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF, $3F,
    $00 );
var
  pk_point,
  r_point          : curve448_point_t;

    error            : c448_error_t;

  challenge_scalar,
  response_scalar  : curve448_scalar_t;

    i                : integer;

    hashctx          : PEVP_MD_CTX;

    challenge        : array[0..(2 * EDDSA_448_PRIVATE_BYTES)-1] of byte;
begin
   
    {
     * Check that s (second 57 bytes of the sig) is less than the order. Both
     * s and the order are in little-endian format. This can be done in
     * variable time, since if this is not the case the signature if publicly
     * invalid.
     }
    i := EDDSA_448_PUBLIC_BYTES - 1;
    while (i >= 0) do
    begin
        if signature[i + EDDSA_448_PUBLIC_BYTES] > order[i] then Exit(C448_FAILURE);
        if signature[i + EDDSA_448_PUBLIC_BYTES] < order[i] then break;
        Dec(i);
    end;
    if i < 0 then Exit(C448_FAILURE);
    error := ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point, pubkey);
    if C448_SUCCESS <> error then Exit(error);
    error := ossl_curve448_point_decode_like_eddsa_and_mul_by_ratio(r_point, signature);
    if C448_SUCCESS <> error then Exit(error);
    begin
        { Compute the challenge }
        hashctx := EVP_MD_CTX_new();
        if (hashctx = nil)
                 or  (0>= Int(hash_init_with_dom(ctx, hashctx, prehashed, 0, context,
                                       context_len, propq)) )
                 or  (0>= EVP_DigestUpdate(hashctx, signature, EDDSA_448_PUBLIC_BYTES))
                 or  (0>= EVP_DigestUpdate(hashctx, pubkey, EDDSA_448_PUBLIC_BYTES))
                 or  (0>= EVP_DigestUpdate(hashctx, _message, message_len))
                 or  (0>= EVP_DigestFinalXOF(hashctx, @challenge, sizeof(challenge)))then
        begin
            EVP_MD_CTX_free(hashctx);
            Exit(C448_FAILURE);
        end;
        EVP_MD_CTX_free(hashctx);
        ossl_curve448_scalar_decode_long(challenge_scalar, @challenge,
                                         sizeof(challenge));
        OPENSSL_cleanse(@challenge, sizeof(challenge));
    end;
    ossl_curve448_scalar_sub(challenge_scalar, ossl_curve448_scalar_zero,
                             challenge_scalar);
    ossl_curve448_scalar_decode_long(response_scalar,
                                     @signature[EDDSA_448_PUBLIC_BYTES],
                                     EDDSA_448_PRIVATE_BYTES);
    { pk_point = -c(x(P)) + (cx + k)G = kG }
    ossl_curve448_base_double_scalarmul_non_secret(pk_point,
                                                   response_scalar,
                                                   pk_point, challenge_scalar);
    Result := c448_succeed_if(ossl_curve448_point_eq(pk_point, r_point));
end;

function ossl_ed448_verify(ctx : POSSL_LIB_CTX;const _message : PByte; message_len : size_t;const signature{114}, public_key{57} : Pbyte; context : PByte; context_len : size_t;const propq : PUTF8Char):integer;
begin
    result := int(ossl_c448_ed448_verify(ctx, signature, public_key, _message,
                                  message_len, 0, context,  uint8( context_len),
                                  propq) = C448_SUCCESS);
end;



function hash_init_with_dom(ctx : POSSL_LIB_CTX; hashctx : PEVP_MD_CTX; prehashed, for_prehash : byte;const context : PByte; context_len : size_t;const propq : PUTF8Char):c448_error_t;
var
    dom      : array[0..1] of byte;

    shake256 : PEVP_MD;
{$IFDEF CHARSET_EBCDIC}
    const char dom_s[] = begin $53, $69, $67, $45,
                          $64, $34, $34, $38, $00end;
;
{$ELSE}
    const dom_s: PUTF8Char  = 'SigEd448';
{$ENDIF}
begin

    shake256 := nil;
    if context_len > UINT8_MAX then Exit(C448_FAILURE);
    dom[0] := uint8( (2 - get_result(prehashed = 0 , 1 , 0)
                       - get_result(for_prehash = 0 , 1 , 0)));
    dom[1] := uint8( context_len);
    shake256 := EVP_MD_fetch(ctx, 'SHAKE256', propq);
    if shake256 = nil then
       Exit(C448_FAILURE);
    if (0>= EVP_DigestInit_ex(hashctx, shake256, nil))  or
       (0>= EVP_DigestUpdate(hashctx, dom_s, Length(dom_s)))
             or  (0>= EVP_DigestUpdate(hashctx, @dom, sizeof(dom)))
             or  (0>= EVP_DigestUpdate(hashctx, context, context_len)) then
    begin
        EVP_MD_free(shake256);
        Exit(C448_FAILURE);
    end;
    EVP_MD_free(shake256);
    Result := C448_SUCCESS;
end;



procedure clamp( secret_scalar_ser : Pbyte);
begin
    secret_scalar_ser[0] := secret_scalar_ser[0] and -COFACTOR;
    secret_scalar_ser[EDDSA_448_PRIVATE_BYTES - 1] := 0;
    secret_scalar_ser[EDDSA_448_PRIVATE_BYTES - 2]  := secret_scalar_ser[EDDSA_448_PRIVATE_BYTES - 2]  or $80;
end;

function oneshot_hash(ctx : POSSL_LIB_CTX; &out : PByte; outlen : size_t;const &in : PByte; inlen : size_t;const propq : PUTF8Char):c448_error_t;
var
    hashctx  : PEVP_MD_CTX;
    shake256 : PEVP_MD;
    ret      : c448_error_t;
    label _err;
begin
    hashctx := EVP_MD_CTX_new();
    shake256 := nil;
    ret := C448_FAILURE;
    if hashctx = nil then Exit(C448_FAILURE);
    shake256 := EVP_MD_fetch(ctx, 'SHAKE256', propq);
    if shake256 = nil then goto _err ;
    if (0>= EVP_DigestInit_ex(hashctx, shake256, nil)) or
       (0>= EVP_DigestUpdate(hashctx, &in, inlen))
             or  (0>= EVP_DigestFinalXOF(hashctx, &out, outlen)) then
        goto _err ;
    ret := C448_SUCCESS;
 _err:
    EVP_MD_CTX_free(hashctx);
    EVP_MD_free(shake256);
    Result := ret;
end;



function ossl_c448_ed448_sign(ctx : POSSL_LIB_CTX; signature : PByte;const privkey, pubkey : PByte; _message : PByte; message_len : size_t; prehashed : Byte;const context : PByte; context_len : size_t;const propq : PUTF8Char):c448_error_t;
var
    secret_scalar    : curve448_scalar_t;
    hashctx          : PEVP_MD_CTX;
    ret              : c448_error_t;
    nonce_scalar     : curve448_scalar_t;
    nonce_point      : array[0..(EDDSA_448_PUBLIC_BYTES)-1] of byte;
    c                : uint32;
    challenge_scalar : curve448_scalar_t;
    expanded         : array[0..(EDDSA_448_PRIVATE_BYTES * 2)-1] of byte;
    nonce            : array[0..(2 * EDDSA_448_PRIVATE_BYTES)-1] of byte;
    nonce_scalar_2   : curve448_scalar_t;
    p                : curve448_point_t;
    challenge        : array[0..(2 * EDDSA_448_PRIVATE_BYTES)-1] of byte;
    label _err;
begin
    hashctx := EVP_MD_CTX_new();
    ret := C448_FAILURE;
    FillChar(nonce_point, EDDSA_448_PUBLIC_BYTES, 0 );

    if hashctx = nil then
       Exit(C448_FAILURE);
    begin
        {
         * Schedule the secret key, First EDDSA_448_PRIVATE_BYTES is serialized
         * secret scalar,next EDDSA_448_PRIVATE_BYTES bytes is the seed.
         }
        if 0>= Int(oneshot_hash(ctx, @expanded, sizeof(expanded), privkey,
                          EDDSA_448_PRIVATE_BYTES, propq)) then
            goto _err ;
        clamp(@expanded);
        ossl_curve448_scalar_decode_long(secret_scalar, @expanded,
                                         EDDSA_448_PRIVATE_BYTES);
        { Hash to create the nonce }
        if (0>= Int(hash_init_with_dom(ctx, hashctx, prehashed, 0, context,
                                context_len, propq)))  or
           (0>= EVP_DigestUpdate(hashctx, PByte(@expanded) + EDDSA_448_PRIVATE_BYTES,
                                     EDDSA_448_PRIVATE_BYTES))  or
           (0>= EVP_DigestUpdate(hashctx, _message, message_len))  then
        begin
            OPENSSL_cleanse(@expanded, sizeof(expanded));
            goto _err ;
        end;
        OPENSSL_cleanse(@expanded, sizeof(expanded));
    end;
    { Decode the nonce }
    begin
        if 0>= EVP_DigestFinalXOF(hashctx, @nonce, sizeof(nonce)) then
            goto _err ;
        ossl_curve448_scalar_decode_long(nonce_scalar, @nonce, sizeof(nonce));
        OPENSSL_cleanse(@nonce, sizeof(nonce));
    end;
    begin
        // Scalarmul to create the nonce-point
        ossl_curve448_scalar_halve(nonce_scalar_2, nonce_scalar);
        c := 2;
        while ( c < C448_EDDSA_ENCODE_RATIO) do
        begin
            ossl_curve448_scalar_halve(nonce_scalar_2, nonce_scalar_2);
            c  := c shl 1;
        end;
        ossl_curve448_precomputed_scalarmul(p, ossl_curve448_precomputed_base,
                                            nonce_scalar_2);
        ossl_curve448_point_mul_by_ratio_and_encode_like_eddsa(@nonce_point, p);
        ossl_curve448_point_destroy(p);
        ossl_curve448_scalar_destroy(nonce_scalar_2);
    end;
    begin
        { Compute the challenge }
        if (0>= Int(hash_init_with_dom(ctx, hashctx, prehashed, 0, context, context_len,
                                propq)))
                 or  (0>= EVP_DigestUpdate(hashctx, @nonce_point, sizeof(nonce_point)))
                 or  (0>= EVP_DigestUpdate(hashctx, pubkey, EDDSA_448_PUBLIC_BYTES) )
                 or  (0>= EVP_DigestUpdate(hashctx, _message, message_len))
                 or  (0>= EVP_DigestFinalXOF(hashctx, @challenge, sizeof(challenge))) then
            goto _err ;
        ossl_curve448_scalar_decode_long(challenge_scalar, @challenge,
                                         sizeof(challenge));
        OPENSSL_cleanse(@challenge, sizeof(challenge));
    end;
    ossl_curve448_scalar_mul(challenge_scalar, challenge_scalar, secret_scalar);
    ossl_curve448_scalar_add(challenge_scalar, challenge_scalar, nonce_scalar);
    OPENSSL_cleanse(signature, EDDSA_448_SIGNATURE_BYTES);
    memcpy(signature, @nonce_point, sizeof(nonce_point));
    ossl_curve448_scalar_encode(@signature[EDDSA_448_PUBLIC_BYTES],
                                challenge_scalar);
    ossl_curve448_scalar_destroy(secret_scalar);
    ossl_curve448_scalar_destroy(nonce_scalar);
    ossl_curve448_scalar_destroy(challenge_scalar);
    ret := C448_SUCCESS;
 _err:
    EVP_MD_CTX_free(hashctx);
    Result := ret;
end;


function ossl_ed448_sign(ctx : POSSL_LIB_CTX; out_sig : PByte;const _message : PByte; message_len : size_t;const public_key, private_key : PByte; context : PByte; context_len : size_t;const propq : PUTF8Char):integer;
begin
    Result := int(ossl_c448_ed448_sign(ctx, out_sig, private_key, public_key, _message,
                                message_len, 0, context, context_len,
                                propq) = C448_SUCCESS);
end;


end.
