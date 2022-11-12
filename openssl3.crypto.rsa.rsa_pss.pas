unit openssl3.crypto.rsa.rsa_pss;

interface
uses OpenSSL.Api, SysUtils;

function ossl_rsa_pss_params_30_is_unrestricted(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
function ossl_rsa_pss_params_30_hashalg(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
function ossl_rsa_pss_params_30_maskgenalg(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
function ossl_rsa_pss_params_30_maskgenhashalg(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
function ossl_rsa_pss_params_30_saltlen(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
function ossl_rsa_pss_params_30_trailerfield(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
function ossl_rsa_pss_params_30_set_defaults( rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
function ossl_rsa_pss_params_30_set_hashalg( rsa_pss_params : PRSA_PSS_PARAMS_30; hashalg_nid : integer):integer;
function ossl_rsa_pss_params_30_set_maskgenhashalg( rsa_pss_params : PRSA_PSS_PARAMS_30; maskgenhashalg_nid : integer):integer;
function ossl_rsa_pss_params_30_set_saltlen( rsa_pss_params : PRSA_PSS_PARAMS_30; saltlen : integer):integer;
function ossl_rsa_pss_params_30_copy(&to : PRSA_PSS_PARAMS_30;const from : PRSA_PSS_PARAMS_30):integer;
 function RSA_padding_add_PKCS1_PSS_mgf1(rsa : PRSA; EM : PByte;const mHash : PByte; Hash, mgf1Hash : PEVP_MD; sLen : integer):integer;
 function RSA_verify_PKCS1_PSS_mgf1(rsa : PRSA;const mHash : PByte; Hash, mgf1Hash : PEVP_MD; EM : PByte; sLen : integer):integer;
 function ossl_rsa_pss_params_30_set_trailerfield( rsa_pss_params : PRSA_PSS_PARAMS_30; trailerfield : integer):integer;

 const
   default_RSASSA_PSS_params: TRSA_PSS_PARAMS_30  = (
    hash_algorithm_nid:NID_sha1;                    (* default hashAlgorithm *)
     mask_gen:(
        algorithm_nid:NID_mgf1;                (* default maskGenAlgorithm *)
        hash_algorithm_nid:NID_sha1                 (* default MGF1 hash *)
    );
    salt_len: 20;                          (* default saltLength *)
    trailer_field:1                            (* default trailerField (0xBC) *)
);

var
    pss_params_cmp: TRSA_PSS_PARAMS_30;
const // 1d arrays
  zeroes : array[0..7] of Byte = (0, 0, 0, 0, 0, 0, 0, 0 );

implementation
uses OpenSSL3.Err, openssl3.crypto.evp.evp_lib, openssl3.crypto.bn.bn_lib,
     OpenSSL3.crypto.rsa.rsa_crpt, openssl3.crypto.mem,
     openssl3.crypto.rand.rand_lib, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.evp.digest, OpenSSL3.crypto.rsa.rsa_oaep;


function ossl_rsa_pss_params_30_set_trailerfield( rsa_pss_params : PRSA_PSS_PARAMS_30; trailerfield : integer):integer;
begin
    if rsa_pss_params = nil then
       Exit(0);
    rsa_pss_params.trailer_field := trailerfield;
    Result := 1;
end;


function RSA_verify_PKCS1_PSS_mgf1(rsa : PRSA;const mHash : PByte; Hash, mgf1Hash : PEVP_MD; EM : PByte; sLen : integer):integer;
var
  i,
  ret,
  hLen,
  maskedDBLen,
  MSBits,
  emLen       : integer;
  H,
  DB          : PByte;
  ctx         : PEVP_MD_CTX;
  H_          : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  label _err;
begin
    ret := 0;
    DB := nil;
    ctx := EVP_MD_CTX_new();
    if ctx = nil then goto _err ;
    if mgf1Hash = nil then
       mgf1Hash := Hash;
    hLen := EVP_MD_get_size(Hash);
    if hLen < 0 then goto _err ;
    {-
     * Negative sLen has special meanings:
     *      -1      sLen = hLen
     *      -2      salt length is autorecovered from signature
     *      -3      salt length is maximized
     *      -N      reserved
     }
    if sLen = RSA_PSS_SALTLEN_DIGEST then
    begin
        sLen := hLen;
    end
    else
    if (sLen < RSA_PSS_SALTLEN_MAX) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
        goto _err ;
    end;
    MSBits := (BN_num_bits(rsa.n) - 1) and $7;
    emLen := RSA_size(rsa);
    if (EM[0] and ($FF  shl  MSBits)) > 0 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_FIRST_OCTET_INVALID);
        goto _err ;
    end;
    if MSBits = 0 then
    begin
        Inc(EM);
        Dec(emLen);
    end;
    if emLen < hLen + 2 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        goto _err ;
    end;
    if sLen = RSA_PSS_SALTLEN_MAX then
    begin
        sLen := emLen - hLen - 2;
    end
    else
    if (sLen > emLen - hLen - 2) then
    begin  { sLen can be small negative }
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE);
        goto _err ;
    end;
    if EM[emLen - 1] <> $bc then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_LAST_OCTET_INVALID);
        goto _err ;
    end;
    maskedDBLen := emLen - hLen - 1;
    H := EM + maskedDBLen;
    DB := OPENSSL_malloc(maskedDBLen);
    if DB = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if PKCS1_MGF1(DB, maskedDBLen, H, hLen, mgf1Hash) < 0  then
        goto _err ;
    for i := 0 to maskedDBLen-1 do
        DB[i]  := DB[i] xor (EM[i]);
    if MSBits > 0 then
       DB[0] := DB[0] and ($FF  shr  (8 - MSBits));

    i := 0;
    while (DB[i] = 0) and ( i < maskedDBLen - 1) do
       Inc(i) ;

    if DB[PostInc(i)] <> $1  then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_SLEN_RECOVERY_FAILED);
        goto _err ;
    end;
    if (sLen <> RSA_PSS_SALTLEN_AUTO)  and  (maskedDBLen - i <> sLen)  then
    begin
        ERR_raise_data(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED,
                      Format( 'expected: %d retrieved: %d', [sLen,
                       maskedDBLen - i]));
        goto _err ;
    end;
    if (0>= EVP_DigestInit_ex(ctx, Hash, nil))  or
       (0>= EVP_DigestUpdate(ctx, @zeroes, sizeof(zeroes)) )
         or  (0>= EVP_DigestUpdate(ctx, mHash, hLen))  then
        goto _err ;
    if maskedDBLen - i > 0 then
    begin
        if 0>= EVP_DigestUpdate(ctx, DB + i, maskedDBLen - i) then
            goto _err ;
    end;
    if 0>= EVP_DigestFinal_ex(ctx, @H_, nil) then
        goto _err ;
    if memcmp(@H_, H, hLen) > 0 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE);
        ret := 0;
    end
    else
    begin
        ret := 1;
    end;
 _err:
    OPENSSL_free(Pointer(DB));
    EVP_MD_CTX_free(ctx);
    Exit(ret);
end;


function RSA_padding_add_PKCS1_PSS_mgf1(rsa : PRSA; EM : PByte;const mHash : PByte; Hash, mgf1Hash : PEVP_MD; sLen : integer):integer;
var
  i,
  ret,
  hLen,
  maskedDBLen,
  MSBits,
  emLen       : integer;
  H,
  salt, p        : PByte;
  ctx         : PEVP_MD_CTX;
  label _err;
begin
    ret := 0;
    salt := nil;
    ctx := nil;
    if mgf1Hash = nil then
       mgf1Hash := Hash;
    hLen := EVP_MD_get_size(Hash);
    if hLen < 0 then goto _err ;
    {-
     * Negative sLen has special meanings:
     *      -1      sLen = hLen
     *      -2      salt length is maximized
     *      -3      same as above (on signing)
     *      -N      reserved
     }
    if sLen = RSA_PSS_SALTLEN_DIGEST then
    begin
        sLen := hLen;
    end
    else
    if (sLen = RSA_PSS_SALTLEN_MAX_SIGN) then
    begin
        sLen := RSA_PSS_SALTLEN_MAX;
    end
    else
    if (sLen < RSA_PSS_SALTLEN_MAX) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_SLEN_CHECK_FAILED);
        goto _err ;
    end;
    MSBits := (BN_num_bits(rsa.n) - 1) and $7;
    emLen := RSA_size(rsa);
    if MSBits = 0 then
    begin
        PostInc(EM)^ :=  0;
        Dec(emLen);
    end;
    if emLen < hLen + 2 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto _err ;
    end;
    if sLen = RSA_PSS_SALTLEN_MAX then
    begin
        sLen := emLen - hLen - 2;
    end
    else
    if (sLen > emLen - hLen - 2) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        goto _err ;
    end;
    if sLen > 0 then
    begin
        salt := OPENSSL_malloc(sLen);
        if salt = nil then
        begin
            ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        if RAND_bytes_ex(rsa.libctx, salt, sLen, 0) <= 0  then
            goto _err ;
    end;
    maskedDBLen := emLen - hLen - 1;
    H := EM + maskedDBLen;
    ctx := EVP_MD_CTX_new();
    if ctx = nil then goto _err ;
    if (0>= EVP_DigestInit_ex(ctx, Hash, nil))  or
       (0>= EVP_DigestUpdate(ctx, @zeroes, sizeof(zeroes)))
         or  (0>= EVP_DigestUpdate(ctx, mHash, hLen))  then
        goto _err ;
    if (sLen > 0)  and  (0>= EVP_DigestUpdate(ctx, salt, sLen)) then
        goto _err ;
    if 0>= EVP_DigestFinal_ex(ctx, H, nil) then
        goto _err ;
    { Generate dbMask in place then perform XOR on it }
    if PKCS1_MGF1(EM, maskedDBLen, H, hLen, mgf1Hash) > 0 then
        goto _err ;
    p := EM;
    {
     * Initial PS XORs with all zeroes which is a NOP so just update pointer.
     * Note from a test above this value is guaranteed to be non-negative.
     }
    p  := p + (emLen - sLen - hLen - 2);
    PostInc(p)^  := PostInc(p)^ xor $1;
    if sLen > 0 then
    begin
        for i := 0 to sLen-1 do
            PostInc(p)^  := PostInc(p)^ xor (salt[i]);
    end;
    if MSBits > 0 then
       EM[0] := EM[0] and ($FF  shr  (8 - MSBits));
    { H is already in place so just set final $bc }
    EM[emLen - 1] := $bc;
    ret := 1;
 _err:
    EVP_MD_CTX_free(ctx);
    OPENSSL_clear_free(Pointer(salt), size_t( sLen)); { salt <> nil implies sLen > 0 }
    Exit(ret);
end;

function ossl_rsa_pss_params_30_copy(&to : PRSA_PSS_PARAMS_30;const from : PRSA_PSS_PARAMS_30):integer;
begin
    memcpy(&to, from, sizeof( &to^));
    Result := 1;
end;

function ossl_rsa_pss_params_30_set_saltlen( rsa_pss_params : PRSA_PSS_PARAMS_30; saltlen : integer):integer;
begin
    if rsa_pss_params = nil then Exit(0);
    rsa_pss_params.salt_len := saltlen;
    Result := 1;
end;

function ossl_rsa_pss_params_30_set_maskgenhashalg( rsa_pss_params : PRSA_PSS_PARAMS_30; maskgenhashalg_nid : integer):integer;
begin
    if rsa_pss_params = nil then Exit(0);
    rsa_pss_params.mask_gen.hash_algorithm_nid := maskgenhashalg_nid;
    Result := 1;
end;



function ossl_rsa_pss_params_30_set_hashalg( rsa_pss_params : PRSA_PSS_PARAMS_30; hashalg_nid : integer):integer;
begin
    if rsa_pss_params = nil then Exit(0);
    rsa_pss_params.hash_algorithm_nid := hashalg_nid;
    Result := 1;
end;




function ossl_rsa_pss_params_30_set_defaults( rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
begin
    if rsa_pss_params = nil then Exit(0);
    rsa_pss_params^ := default_RSASSA_PSS_params;
    Result := 1;
end;



function ossl_rsa_pss_params_30_saltlen(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
begin
    if rsa_pss_params = nil then Exit(default_RSASSA_PSS_params.salt_len);
    Result := rsa_pss_params.salt_len;
end;


function ossl_rsa_pss_params_30_trailerfield(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
begin
    if rsa_pss_params = nil then Exit(default_RSASSA_PSS_params.trailer_field);
    Result := rsa_pss_params.trailer_field;
end;




function ossl_rsa_pss_params_30_maskgenhashalg(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
begin
    if rsa_pss_params = nil then Exit(default_RSASSA_PSS_params.hash_algorithm_nid);
    Result := rsa_pss_params.mask_gen.hash_algorithm_nid;
end;




function ossl_rsa_pss_params_30_maskgenalg(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
begin
    if rsa_pss_params = nil then
       Exit(default_RSASSA_PSS_params.mask_gen.algorithm_nid);
    Result := rsa_pss_params.mask_gen.algorithm_nid;
end;

function ossl_rsa_pss_params_30_hashalg(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
begin
    if rsa_pss_params = nil then
       Exit(default_RSASSA_PSS_params.hash_algorithm_nid);
    Result := rsa_pss_params.hash_algorithm_nid;
end;

function ossl_rsa_pss_params_30_is_unrestricted(const rsa_pss_params : PRSA_PSS_PARAMS_30):integer;
begin
   FillChar(pss_params_cmp, SizeOf(pss_params_cmp) ,0);
   Result := Int ( (rsa_pss_params = nil)
                or (memcmp(rsa_pss_params, @pss_params_cmp,
                  sizeof(rsa_pss_params^)) = 0));
end;


end.
