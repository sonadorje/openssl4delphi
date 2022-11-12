unit openssl3.crypto.evp.evp_pbe;

interface
uses OpenSSL.Api, SysUtils;

type
   sk_EVP_PBE_CTL_freefunc = procedure(a: PEVP_PBE_CTL);

function EVP_PBE_CipherInit_ex(pbe_obj : PASN1_OBJECT;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE; ctx : PEVP_CIPHER_CTX; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function EVP_PBE_find_ex( &type, pbe_nid : integer; pcnid, pmnid : PInteger; pkeygen : PEVP_PBE_KEYGEN; pkeygen_ex : PEVP_PBE_KEYGEN_EX):integer;
function sk_EVP_PBE_CTL_find( sk : Pstack_st_EVP_PBE_CTL; ptr : PEVP_PBE_CTL):integer;
 function sk_EVP_PBE_CTL_value(const sk : Pstack_st_EVP_PBE_CTL; idx : integer):PEVP_PBE_CTL;
 function OBJ_bsearch_pbe2(key : PEVP_PBE_CTL;const base : PEVP_PBE_CTL; num : integer):PEVP_PBE_CTL;
 function pbe2_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
function pbe2_cmp(const pbe1, pbe2 : Pointer):integer;
function EVP_PBE_find( _type, pbe_nid : integer; pcnid, pmnid : PInteger; pkeygen : PEVP_PBE_KEYGEN):integer;


var
  pbe_algs: PSTACK_st_EVP_PBE_CTL;
  builtin_pbe: array[0..28] of TEVP_PBE_CTL ;

procedure EVP_PBE_cleanup;
procedure sk_EVP_PBE_CTL_pop_free( sk : Pstack_st_EVP_PBE_CTL; freefunc : sk_EVP_PBE_CTL_freefunc);
procedure free_evp_pbe_ctl( pbe : PEVP_PBE_CTL);

implementation

uses openssl3.crypto.stack, openssl3.crypto.objects.obj_dat,
     OpenSSL3.Err,          openssl3.crypto.o_str,
     openssl3.crypto.evp.evp_enc,     openssl3.crypto.mem,
     openssl3.crypto.asn1.a_object,   openssl3.providers.fips.fipsprov,
     openssl3.crypto.evp.p12_crpt, openssl3.crypto.asn1.p5_scrypt,
     openssl3.crypto.evp.p5_crpt,  openssl3.crypto.evp.p5_crpt2,
     openssl3.crypto.evp, openssl3.crypto.evp.digest;




procedure free_evp_pbe_ctl( pbe : PEVP_PBE_CTL);
begin
    OPENSSL_free(Pointer(pbe));
end;




procedure sk_EVP_PBE_CTL_pop_free( sk : Pstack_st_EVP_PBE_CTL; freefunc : sk_EVP_PBE_CTL_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;

procedure EVP_PBE_cleanup;
begin
    sk_EVP_PBE_CTL_pop_free(pbe_algs, free_evp_pbe_ctl);
    pbe_algs := nil;
end;




function EVP_PBE_find( _type, pbe_nid : integer; pcnid, pmnid : PInteger; pkeygen : PEVP_PBE_KEYGEN):integer;
begin
    Result := EVP_PBE_find_ex(_type, pbe_nid, pcnid, pmnid, pkeygen, nil);
end;



function pbe2_cmp(const pbe1, pbe2 : Pointer):integer;
var
  ret : integer;
begin
    ret := PEVP_PBE_CTL(pbe1).pbe_type - PEVP_PBE_CTL(pbe2).pbe_type;
    if ret > 0  then
       Exit(ret)
    else
        Result := PEVP_PBE_CTL(pbe1).pbe_nid - PEVP_PBE_CTL(pbe2).pbe_nid;
end;


function pbe2_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a,b: PEVP_PBE_CTL;
begin
  a := a_;
  b := b_;
  Result := pbe2_cmp(a,b);
end;




function OBJ_bsearch_pbe2(key : PEVP_PBE_CTL;const base : PEVP_PBE_CTL; num : integer):PEVP_PBE_CTL;
begin
   result := PEVP_PBE_CTL( OBJ_bsearch_(key, base, num, sizeof(TEVP_PBE_CTL), pbe2_cmp_BSEARCH_CMP_FN));
end;





function sk_EVP_PBE_CTL_value(const sk : Pstack_st_EVP_PBE_CTL; idx : integer):PEVP_PBE_CTL;
begin
   Result := PEVP_PBE_CTL( OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;


function sk_EVP_PBE_CTL_find( sk : Pstack_st_EVP_PBE_CTL; ptr : PEVP_PBE_CTL):integer;
begin
 Result := OPENSSL_sk_find(POPENSSL_STACK( sk), Pointer( ptr));
end;




function EVP_PBE_find_ex( &type, pbe_nid : integer; pcnid, pmnid : PInteger; pkeygen : PEVP_PBE_KEYGEN; pkeygen_ex : PEVP_PBE_KEYGEN_EX):integer;
var
  pbetmp , pbelu: PEVP_PBE_CTL;

  i : integer;
begin
    pbetmp := nil;
    if pbe_nid = NID_undef then Exit(0);
    pbelu.pbe_type := &type;
    pbelu.pbe_nid := pbe_nid;
    if pbe_algs <> nil then
    begin
        i := sk_EVP_PBE_CTL_find(pbe_algs, @pbelu);
        pbetmp := sk_EVP_PBE_CTL_value(pbe_algs, i);
    end;
    if pbetmp = nil then
    begin
        pbetmp := OBJ_bsearch_pbe2(@pbelu, @builtin_pbe, Length(builtin_pbe));
    end;
    if pbetmp = nil then Exit(0);
    if pcnid <> nil then pcnid^ := pbetmp.cipher_nid;
    if pmnid <> nil then pmnid^ := pbetmp.md_nid;
    if pkeygen <> nil then pkeygen^ := pbetmp.keygen;
    if pkeygen_ex <> nil then pkeygen_ex^ := pbetmp.keygen_ex;
    Result := 1;
end;

function EVP_PBE_CipherInit_ex(pbe_obj : PASN1_OBJECT;const pass : PUTF8Char; passlen : integer; param : PASN1_TYPE; ctx : PEVP_CIPHER_CTX; en_de : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  cipher,
  cipher_fetch : PEVP_CIPHER;
  md,
  md_fetch     : PEVP_MD;
  ret ,
  cipher_nid, md_nid  : integer;
  keygen_ex    : TEVP_PBE_KEYGEN_EX;
  keygen       : TEVP_PBE_KEYGEN;
  obj_tmp      : array[0..79] of UTF8Char;
  pc: PUTF8Char;
  label _err;
begin
    cipher := nil;
    cipher_fetch := nil;
    md := nil;
    md_fetch := nil;
    ret := 0;
    if 0>= EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, OBJ_obj2nid(pbe_obj) ,
                         @cipher_nid, @md_nid, @keygen, @keygen_ex)  then
    begin
        pc:= @obj_tmp;
        if pbe_obj = nil then
            OPENSSL_strlcpy(pc, 'nil', sizeof(obj_tmp))
        else
            i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), pbe_obj);
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM,
                       Format('TYPE=%s', [obj_tmp]) );
        goto _err ;
    end;
    if pass = nil then
       passlen := 0
    else
    if (passlen = -1) then
        passlen := Length(pass);
    if cipher_nid <> -1 then
    begin
        ERR_set_mark();
        cipher_fetch := EVP_CIPHER_fetch(libctx, OBJ_nid2sn(cipher_nid), propq);
        cipher := cipher_fetch;
        { Fallback to legacy method }
        if cipher = nil then
           cipher := EVP_get_cipherbynid(cipher_nid);
        if cipher = nil then
        begin
            ERR_clear_last_mark();
            ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_CIPHER,
                           OBJ_nid2sn(cipher_nid));
            goto _err ;
        end;
        ERR_pop_to_mark();
    end;
    if md_nid <> -1 then
    begin
        ERR_set_mark();
        md_fetch := EVP_MD_fetch(libctx, OBJ_nid2sn(md_nid), propq);
        md := md_fetch;
        { Fallback to legacy method }
        if md = nil then EVP_get_digestbynid(md_nid);
        if md = nil then
        begin
            ERR_clear_last_mark();
            ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_DIGEST);
            goto _err ;
        end;
        ERR_pop_to_mark();
    end;
    { Try extended keygen with libctx/propq first, fall back to legacy keygen }
    if Assigned(keygen_ex) then
       ret := keygen_ex(ctx, pass, passlen, param, cipher, md, en_de, libctx, propq)
    else
       ret := keygen(ctx, pass, passlen, param, cipher, md, en_de);
_err:
    EVP_CIPHER_free(cipher_fetch);
    EVP_MD_free(md_fetch);
    Result := ret;
end;

initialization
   builtin_pbe[0] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbeWithMD2AndDES_CBC,
     NID_des_cbc, NID_md2, PKCS5_PBE_keyivgen, PKCS5_PBE_keyivgen_ex);
    builtin_pbe[1] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndDES_CBC,
     NID_des_cbc, NID_md5, PKCS5_PBE_keyivgen, PKCS5_PBE_keyivgen_ex);
    builtin_pbe[2] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbeWithSHA1AndRC2_CBC,
     NID_rc2_64_cbc, NID_sha1, PKCS5_PBE_keyivgen, PKCS5_PBE_keyivgen_ex);

    builtin_pbe[3] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_id_pbkdf2, -1, -1, PKCS5_v2_PBKDF2_keyivgen, nil);

    builtin_pbe[4] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And128BitRC4,
     NID_rc4, NID_sha1, PKCS12_PBE_keyivgen, &PKCS12_PBE_keyivgen_ex);
    builtin_pbe[5] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And40BitRC4,
     NID_rc4_40, NID_sha1, PKCS12_PBE_keyivgen, &PKCS12_PBE_keyivgen_ex);
    builtin_pbe[6] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
     NID_des_ede3_cbc, NID_sha1, PKCS12_PBE_keyivgen, &PKCS12_PBE_keyivgen_ex);
    builtin_pbe[7] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
     NID_des_ede_cbc, NID_sha1, PKCS12_PBE_keyivgen, &PKCS12_PBE_keyivgen_ex);
    builtin_pbe[8] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And128BitRC2_CBC,
     NID_rc2_cbc, NID_sha1, PKCS12_PBE_keyivgen, &PKCS12_PBE_keyivgen_ex);
    builtin_pbe[9] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbe_WithSHA1And40BitRC2_CBC,
     NID_rc2_40_cbc, NID_sha1, PKCS12_PBE_keyivgen, &PKCS12_PBE_keyivgen_ex);

    builtin_pbe[10] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbes2, -1, -1, PKCS5_v2_PBE_keyivgen, &PKCS5_v2_PBE_keyivgen_ex);

    builtin_pbe[11] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbeWithMD2AndRC2_CBC,
     NID_rc2_64_cbc, NID_md2, PKCS5_PBE_keyivgen, PKCS5_PBE_keyivgen_ex);
    builtin_pbe[12] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbeWithMD5AndRC2_CBC,
     NID_rc2_64_cbc, NID_md5, PKCS5_PBE_keyivgen, PKCS5_PBE_keyivgen_ex);
    builtin_pbe[13] := get_EVP_PBE_CTL(EVP_PBE_TYPE_OUTER, NID_pbeWithSHA1AndDES_CBC,
     NID_des_cbc, NID_sha1, PKCS5_PBE_keyivgen, PKCS5_PBE_keyivgen_ex);

    builtin_pbe[14] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithSHA1, -1, NID_sha1, nil, nil);
    builtin_pbe[15] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmac_md5, -1, NID_md5, nil, nil);
    builtin_pbe[16] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmac_sha1, -1, NID_sha1, nil, nil);
    builtin_pbe[17] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithMD5, -1, NID_md5, nil, nil);
    builtin_pbe[18] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithSHA224, -1, NID_sha224, nil, nil);
    builtin_pbe[19] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithSHA256, -1, NID_sha256, nil, nil);
    builtin_pbe[20] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithSHA384, -1, NID_sha384, nil, nil);
    builtin_pbe[21] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithSHA512, -1, NID_sha512, nil, nil);
    builtin_pbe[22] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_id_HMACGostR3411_94, -1, NID_id_GostR3411_94, nil, nil);
    builtin_pbe[23] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_id_tc26_hmac_gost_3411_2012_256, -1,
                                    NID_id_GostR3411_2012_256, nil, nil);
    builtin_pbe[24] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_id_tc26_hmac_gost_3411_2012_512, -1,
                                   NID_id_GostR3411_2012_512, nil, nil);
    builtin_pbe[25] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithSHA512_224, -1, NID_sha512_224, nil, nil);
    builtin_pbe[26] := get_EVP_PBE_CTL(EVP_PBE_TYPE_PRF, NID_hmacWithSHA512_256, -1, NID_sha512_256, nil, nil);
    builtin_pbe[27] := get_EVP_PBE_CTL(EVP_PBE_TYPE_KDF, NID_id_pbkdf2, -1, -1, PKCS5_v2_PBKDF2_keyivgen, &PKCS5_v2_PBKDF2_keyivgen_ex);
{$ifndef OPENSSL_NO_SCRYPT}
    builtin_pbe[28] := get_EVP_PBE_CTL(EVP_PBE_TYPE_KDF, NID_id_scrypt, -1, -1, PKCS5_v2_scrypt_keyivgen, &PKCS5_v2_scrypt_keyivgen_ex);
{$endif}
end.
