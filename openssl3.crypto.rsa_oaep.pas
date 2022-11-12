unit openssl3.crypto.rsa_oaep;

interface
uses OpenSSL.Api;

function ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(libctx : POSSL_LIB_CTX; _to : PByte; tlen : integer;const from : PByte; flen : integer;const param : PByte; plen : integer; md, mgf1md : PEVP_MD):integer;

implementation
 uses openssl3.crypto.evp.legacy_sha, openssl3.crypto.evp.evp_lib,
      OpenSSL3.Err, openssl3.crypto.rand.rand_lib, openssl3.crypto.mem;

function ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(libctx : POSSL_LIB_CTX; _to : PByte; tlen : integer;const from : PByte; flen : integer;const param : PByte; plen : integer; md, mgf1md : PEVP_MD):integer;
var
  rv,
  i,
  emlen      : integer;
  db,
  seed,
  dbmask     : PByte;
  seedmask   : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;
  mdlen,
  dbmask_len : integer;
  label _err;
begin
    rv := 0;
    emlen := tlen - 1;
    dbmask := nil;
    dbmask_len := 0;
    if md = nil then
    begin
{$IFNDEF FIPS_MODULE}
        md := EVP_sha1();
{$ELSE}
        ERR_raise(ERR_LIB_RSA, ERR_R_PASSED_nil_PARAMETER);
        Exit(0);
{$ENDIF}
    end;
    if mgf1md = nil then
       mgf1md := md;
    mdlen := EVP_MD_get_size(md);
    if mdlen <= 0 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_LENGTH);
        Exit(0);
    end;
    { step 2b: check KLen > nLen - 2 HLen - 2 }
    if flen > emlen - 2 * mdlen - 1 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
        Exit(0);
    end;
    if emlen < 2 * mdlen + 1 then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_KEY_SIZE_TOO_SMALL);
        Exit(0);
    end;
    { step 3i: EM = 00000000  or  maskedMGF  or  maskedDB }
    _to[0] := 0;
    seed := _to + 1;
    db := _to + mdlen + 1;
    { step 3a: hash the additional input }
    if 0>= EVP_Digest(Pointer( param), plen, db, nil, md, nil)  then
        goto _err ;
    { step 3b: zero bytes array of length nLen - KLen - 2 HLen -2 }
    memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
    { step 3c: DB = HA  or  PS  or  00000001  or  K }
    db[emlen - flen - mdlen - 1] := $01;
    memcpy(db + emlen - flen - mdlen, from, Uint32 (flen));
    { step 3d: generate random byte string }
    if RAND_bytes_ex(libctx, seed, mdlen, 0) <= 0  then
        goto _err ;
    dbmask_len := emlen - mdlen;
    dbmask := OPENSSL_malloc(dbmask_len);
    if dbmask = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    { step 3e: dbMask = MGF(mgfSeed, nLen - HLen - 1) }
    if PKCS1_MGF1(dbmask, dbmask_len, seed, mdlen, mgf1md )< 0 then
        goto _err ;
    { step 3f: maskedDB = DB XOR dbMask }
    for i := 0 to dbmask_len-1 do
        db[i]  := db[i] xor (dbmask[i]);
    { step 3g: mgfSeed = MGF(maskedDB, HLen) }
    if PKCS1_MGF1(@seedmask, mdlen, db, dbmask_len, mgf1md ) < 0 then
        goto _err ;
    { stepo 3h: maskedMGFSeed = mgfSeed XOR mgfSeedMask }
    for i := 0 to mdlen-1 do
        seed[i]  := seed[i] xor (seedmask[i]);
    rv := 1;
 _err:
    OPENSSL_cleanse(@seedmask, sizeof(seedmask));
    OPENSSL_clear_free(dbmask, dbmask_len);
    Result := rv;
end;


end.
