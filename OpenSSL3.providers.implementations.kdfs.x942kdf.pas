unit OpenSSL3.providers.implementations.kdfs.x942kdf;

interface
uses OpenSSL.Api, OpenSSL3.providers.common.prov.der_wrap_gen;

type
    kek_st = record
      name : PUTF8Char;
      oid : PByte;
      oid_len, keklen : size_t;
    end;

function x942kdf_new( provctx : Pointer):Pointer;
procedure x942kdf_free( vctx : Pointer);
procedure x942kdf_reset( vctx : Pointer);
function x942kdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function x942kdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function x942kdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
function x942kdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
function x942kdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
function x942kdf_size( ctx : PKDF_X942):size_t;
 function x942kdf_set_buffer(var _out : PByte; out_len : Psize_t;const p : POSSL_PARAM):integer;
  function find_alg_id(libctx : POSSL_LIB_CTX;const algname, propq : PUTF8Char; id : Psize_t):integer;
function x942_encode_otherinfo(keylen : size_t;const cek_oid : PByte; cek_oid_len : size_t;const acvp : PByte; acvp_len : size_t;const partyu : PByte; partyu_len : size_t;const partyv : PByte; partyv_len : size_t;const supp_pub : PByte; supp_pub_len : size_t;const supp_priv : PByte; supp_priv_len : size_t; der : PPByte; der_len : Psize_t; out_ctr : PPByte):integer;
function der_encode_sharedinfo(pkt : PWPACKET; buf : PByte; buflen : size_t;const der_oid : PByte; der_oidlen : size_t;const acvp : PByte; acvplen : size_t;const partyu : PByte; partyulen : size_t;const partyv : PByte; partyvlen : size_t;const supp_pub : PByte; supp_publen : size_t;const supp_priv : PByte; supp_privlen : size_t; keylen_bits : uint32; pcounter : PPByte):integer;
function DER_w_keyinfo(pkt : PWPACKET;const der_oid : PByte; der_oidlen : size_t; pcounter : PPByte):integer;
function x942kdf_hash_kdm(const kdf_md : PEVP_MD; z : PByte; z_len : size_t;const other : PByte; other_len : size_t; ctr, derived_key : PByte; derived_key_len : size_t):integer;


const
 X942KDF_MAX_INLEN = (1 shl 30);
 ossl_kdf_x942_kdf_functions: array[0..8] of TOSSL_DISPATCH  = (
    ( function_id: OSSL_FUNC_KDF_NEWCTX; method:(code:@x942kdf_new ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_FREECTX; method:(code:@x942kdf_free ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_RESET; method:(code:@x942kdf_reset ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_DERIVE; method:(code:@x942kdf_derive ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS;
      method:(code:@x942kdf_settable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_SET_CTX_PARAMS; method:(code:@x942kdf_set_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS;
      method:(code:@x942kdf_gettable_ctx_params ;data:nil)),
    ( function_id: OSSL_FUNC_KDF_GET_CTX_PARAMS; method:(code:@x942kdf_get_ctx_params ;data:nil)),
    ( function_id: 0; method:(code:nil ;data:nil) )
);

   kek_algs: array[0..3] of kek_st = (
    ( name :'AES-128-WRAP'; oid :@ossl_der_oid_id_aes128_wrap; oid_len:DER_OID_SZ_id_aes128_wrap;
      keklen :16 ),
    ( name :'AES-192-WRAP'; oid :@ossl_der_oid_id_aes192_wrap; oid_len:DER_OID_SZ_id_aes192_wrap;
      keklen :24 ),
    ( name :'AES-256-WRAP'; oid :@ossl_der_oid_id_aes256_wrap; oid_len:DER_OID_SZ_id_aes256_wrap;
      keklen :32 ),
{$ifndef FIPS_MODULE}
    ( name :'DES3-WRAP'; oid :@ossl_der_oid_id_alg_CMS3DESwrap;
      oid_len:DER_OID_SZ_id_alg_CMS3DESwrap; keklen :24 )
{$endif}
);
var // 1d arrays
  known_settable_ctx_params : array[0..12] of TOSSL_PARAM ;
  known_gettable_ctx_params : array[0..2] of TOSSL_PARAM ;

implementation

uses OpenSSL3.providers.common.capabilities, openssl3.crypto.params,
     OpenSSL3.openssl.params, OpenSSL3.providers.common.provider_ctx,
     OpenSSL3.providers.common.provider_util, openssl3.crypto.mem,
     OpenSSL3.Err ,openssl3.providers.fips.self_test,
     openssl3.crypto.evp, openssl3.crypto.evp.digest,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.mac_lib,
     openssl3.crypto.evp.evp_enc, openssl3.crypto.packet,
     openssl3.crypto.der_write;





function x942kdf_hash_kdm(const kdf_md : PEVP_MD; z : PByte; z_len : size_t;const other : PByte; other_len : size_t; ctr, derived_key : PByte; derived_key_len : size_t):integer;
var
  ret,hlen : integer;

  counter, out_len, len : size_t;

  mac : array[0..(EVP_MAX_MD_SIZE)-1] of Byte;

  &out : PByte;

  ctx,ctx_init : PEVP_MD_CTX;
  label _end;
begin
    ret := 0;
    len := derived_key_len;
    out := derived_key;
    ctx := nil; ctx_init := nil;
    if (z_len > X942KDF_MAX_INLEN)
         or  (other_len > X942KDF_MAX_INLEN )
         or  (derived_key_len > X942KDF_MAX_INLEN)
         or  (derived_key_len = 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        Exit(0);
    end;
    hlen := EVP_MD_get_size(kdf_md);
    if hlen <= 0 then Exit(0);
    out_len := size_t(hlen);
    ctx := EVP_MD_CTX_create();
    ctx_init := EVP_MD_CTX_create();
    if (ctx = nil)  or  (ctx_init = nil) then
       goto _end ;
    if  0>= EVP_DigestInit(ctx_init, kdf_md  )then
        goto _end ;
    counter := 1;
    while True do
    begin
        { updating the ctr modifies 4 bytes in the 'other' buffer }
        ctr[0] := ((counter  shr  24) and $ff);
        ctr[1] := ((counter  shr  16) and $ff);
        ctr[2] := ((counter  shr  8) and $ff);
        ctr[3] := (counter and $ff);
        if (0>= EVP_MD_CTX_copy_ex(ctx, ctx_init)) or
           (0>= EVP_DigestUpdate(ctx, z, z_len))
             or  (0>= EVP_DigestUpdate(ctx, other, other_len))   then
            goto _end ;
        if len >= out_len then
        begin
            if 0>= EVP_DigestFinal_ex(ctx, out, nil) then
                goto _end ;
            &out  := &out + out_len;
            len  := len - out_len;
            if len = 0 then break;
        end
        else
        begin
            if 0>= EVP_DigestFinal_ex(ctx, @mac, nil)   then
                goto _end ;
            memcpy(&out, @mac, len);
            break;
        end;
        Inc(counter);
    end;
    ret := 1;
_end:
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx_init);
    OPENSSL_cleanse(@mac, sizeof(mac));
    Result := ret;
end;


function DER_w_keyinfo(pkt : PWPACKET;const der_oid : PByte; der_oidlen : size_t; pcounter : PPByte):integer;
begin
    pcounter^ := WPACKET_get_curr(pkt) ;
    Result := int( (ossl_DER_w_begin_sequence(pkt, -1)>0)
           { Store the initial value of 1 into the counter }
            and  (ossl_DER_w_octet_string_uint32(pkt, -1, 1)>0)
           { Remember where we stored the counter in the buffer }
            and  ( (pcounter = nil)
                    or  (pcounter^ <> nil) )
            and  (ossl_DER_w_precompiled(pkt, -1, der_oid, der_oidlen)>0)
            and  (ossl_DER_w_end_sequence(pkt, -1)>0));
end;





function der_encode_sharedinfo(pkt : PWPACKET; buf : PByte; buflen : size_t;const der_oid : PByte; der_oidlen : size_t;const acvp : PByte; acvplen : size_t;const partyu : PByte; partyulen : size_t;const partyv : PByte; partyvlen : size_t;const supp_pub : PByte; supp_publen : size_t;const supp_priv : PByte; supp_privlen : size_t; keylen_bits : uint32; pcounter : PPByte):integer;
var
  init_ok: Boolean;
begin
  if (buf <> nil ) then
     init_ok := Boolean(WPACKET_init_der(pkt, buf, buflen))
  else
     init_ok := Boolean(WPACKET_init_null_der(pkt));

    Result := int( (init_ok)
            and  (ossl_DER_w_begin_sequence(pkt, -1)>0)
            and  ( (supp_priv = nil)
                  or  (ossl_DER_w_octet_string(pkt, 3, supp_priv, supp_privlen)>0) )
            and  ( (supp_pub = nil)
                or  (ossl_DER_w_octet_string(pkt, 2, supp_pub, supp_publen)>0) )
            and  ( (keylen_bits = 0)
                or  (ossl_DER_w_octet_string_uint32(pkt, 2, keylen_bits)>0) )
            and  ( (partyv = nil)  or  (ossl_DER_w_octet_string(pkt, 1, partyv, partyvlen)>0) )
            and  ( (partyu = nil)  or  (ossl_DER_w_octet_string(pkt, 0, partyu, partyulen)>0) )
            and  ( (acvp = nil)  or  (ossl_DER_w_precompiled(pkt, -1, acvp, acvplen)>0) )
            and  (DER_w_keyinfo(pkt, der_oid, der_oidlen, pcounter)>0)
            and  (ossl_DER_w_end_sequence(pkt, -1)>0)
            and  (WPACKET_finish(pkt)>0));
end;




function x942_encode_otherinfo(keylen : size_t;const cek_oid : PByte; cek_oid_len : size_t;const acvp : PByte; acvp_len : size_t;const partyu : PByte; partyu_len : size_t;const partyv : PByte; partyv_len : size_t;const supp_pub : PByte; supp_pub_len : size_t;const supp_priv : PByte; supp_priv_len : size_t; der : PPByte; der_len : Psize_t; out_ctr : PPByte):integer;
var
    ret         : integer;

    pcounter,
    der_buf    : PByte;

    der_buflen  : size_t;

    pkt         : TWPACKET;

    keylen_bits : uint32;
    label _err;
begin
    ret := 0;
    pcounter := nil; der_buf := nil;
    der_buflen := 0;
    { keylenbits must fit into 4 bytes }
    if keylen > $FFFFFF then Exit(0);
    keylen_bits := 8 * keylen;
    { Calculate the size of the buffer }
    if  (0>= der_encode_sharedinfo(@pkt, nil, 0, cek_oid, cek_oid_len,
                               acvp, acvp_len,
                               partyu, partyu_len, partyv, partyv_len,
                               supp_pub, supp_pub_len, supp_priv, supp_priv_len,
                               keylen_bits, nil)) or
       (0>= WPACKET_get_total_written(@pkt, @der_buflen)) then
        goto _err ;
    WPACKET_cleanup(@pkt);
    { Alloc the buffer }
    der_buf := OPENSSL_zalloc(der_buflen);
    if der_buf = nil then goto _err ;
    { Encode into the buffer }
    if  0>= der_encode_sharedinfo(@pkt, der_buf, der_buflen, cek_oid, cek_oid_len,
                               acvp, acvp_len,
                               partyu, partyu_len, partyv, partyv_len,
                               supp_pub, supp_pub_len, supp_priv, supp_priv_len,
                               keylen_bits, @pcounter)    then
        goto _err ;
    {
     * Since we allocated the exact size required, the buffer should point to the
     * start of the alllocated buffer at this point.
     }
    if WPACKET_get_curr(@pkt) <> der_buf  then
        goto _err ;
    {
     * The data for the DER encoded octet string of a 32 bit counter = 1
     * should be 04 04 00 00 00 01
     * So just check the header is correct and skip over it.
     * This counter will be incremented in the kdf update loop.
     }
    if (pcounter = nil)
         or  (pcounter[0] <> $04)
         or  (pcounter[1] <> $04) then
         goto _err ;
    out_ctr^ := (pcounter + 2);
    der^ := der_buf;
    der_len^ := der_buflen;
    ret := 1;
_err:
    WPACKET_cleanup(@pkt);
    Result := ret;
end;



function find_alg_id(libctx : POSSL_LIB_CTX;const algname, propq : PUTF8Char; id : Psize_t):integer;
var
  ret : integer;
  i : size_t;
  cipher : PEVP_CIPHER;
  label _end;
begin
    ret := 1;
    cipher := EVP_CIPHER_fetch(libctx, algname, propq);
    if cipher <> nil then
    begin
        for i := 0 to Length(kek_algs)-1 do
        begin
            if EVP_CIPHER_is_a(cipher, kek_algs[i].name) then
            begin
                id^ := i;
                goto _end ;
            end;
        end;
    end;
    ret := 0;
    ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_CEK_ALG);
_end:
    EVP_CIPHER_free(cipher);
    Result := ret;
end;




function x942kdf_set_buffer(var _out : PByte; out_len : Psize_t;const p : POSSL_PARAM):integer;
begin
    if (p.data_size = 0)  or  (p.data = nil) then Exit(1);
    OPENSSL_free(Pointer( _out));
    _out := nil;
    Result := OSSL_PARAM_get_octet_string(p, Pointer(_out), 0, out_len);
end;





function x942kdf_size( ctx : PKDF_X942):size_t;
var
  len : integer;

  md : PEVP_MD;
begin
    md := ossl_prov_digest_md(@ctx.digest);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    len := EVP_MD_get_size(md);
    Result := get_result(len <= 0, 0 , size_t(len));
end;



function x942kdf_get_ctx_params( vctx : Pointer; params : POSSL_PARAM):integer;
var
  ctx : PKDF_X942;

  p : POSSL_PARAM;
begin
    ctx := (PKDF_X942  (vctx));
    p := OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE );
    if p <> nil then
        Exit(OSSL_PARAM_set_size_t(p, x942kdf_size(ctx)));
    Result := -2;
end;





function x942kdf_gettable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_gettable_ctx_params[0] := _OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, nil);
    known_gettable_ctx_params[1] := OSSL_PARAM_END ;

    Result := @known_gettable_ctx_params;
end;



function x942kdf_set_ctx_params(vctx : Pointer;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_X942;
  p, pq: POSSL_PARAM ;
  provctx : POSSL_LIB_CTX;

  propq : PUTF8Char;

  id : size_t;
begin

    ctx := vctx;
    provctx := PROV_LIBCTX_OF(ctx.provctx);
     propq := nil;
    if params = nil then Exit(1);
    if 0>= ossl_prov_digest_load_from_params(@ctx.digest, params, provctx) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET);
    if p = nil then
       p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p <> nil)  and  (0>= x942kdf_set_buffer(ctx.secret, @ctx.secret_len, p)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_X942_ACVPINFO);
    if (p <> nil)
         and  (0>= x942kdf_set_buffer(ctx.acvpinfo, @ctx.acvpinfo_len, p)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_X942_PARTYUINFO);
    if p = nil then
       p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_UKM);
    if (p <> nil)
         and  (0>= x942kdf_set_buffer(ctx.partyuinfo, @ctx.partyuinfo_len, p)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_X942_PARTYVINFO);
    if (p <> nil)
         and  (0>= x942kdf_set_buffer(ctx.partyvinfo, @ctx.partyvinfo_len, p)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_X942_USE_KEYBITS);
    if (p <> nil)  and  (0>= OSSL_PARAM_get_int(p, @ctx.use_keybits)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_X942_SUPP_PUBINFO);
    if p <> nil then
    begin
        if 0>= x942kdf_set_buffer(ctx.supp_pubinfo, @ctx.supp_pubinfo_len, p) then
            Exit(0);
        ctx.use_keybits := 0;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_X942_SUPP_PRIVINFO);
    if (p <> nil)
         and  (0>= x942kdf_set_buffer(ctx.supp_privinfo, @ctx.supp_privinfo_len, p)) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        pq := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
        {
         * We already grab the properties during ossl_prov_digest_load_from_params()
         * so there is no need to check the validity again..
         }
        if pq <> nil then propq := p.data;
        if find_alg_id(provctx, p.data, propq, @id) = 0 then
            Exit(0);
        ctx.cek_oid := kek_algs[id].oid;
        ctx.cek_oid_len := kek_algs[id].oid_len;
        ctx.dkm_len := kek_algs[id].keklen;
    end;
    Result := 1;
end;





function x942kdf_settable_ctx_params( ctx, provctx : Pointer):POSSL_PARAM;
begin
    known_settable_ctx_params[0] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, nil, 0);
    known_settable_ctx_params[1] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, nil, 0);
    known_settable_ctx_params[2] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, nil, 0);
    known_settable_ctx_params[3] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, nil, 0);
    known_settable_ctx_params[4] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_UKM, nil, 0);
    known_settable_ctx_params[5] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_X942_ACVPINFO, nil, 0);
    known_settable_ctx_params[6] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_X942_PARTYUINFO, nil, 0);
    known_settable_ctx_params[7] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_X942_PARTYVINFO, nil, 0);
    known_settable_ctx_params[8] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_X942_SUPP_PUBINFO, nil, 0);
    known_settable_ctx_params[9] := _OSSL_PARAM_octet_string(OSSL_KDF_PARAM_X942_SUPP_PRIVINFO, nil, 0);
    known_settable_ctx_params[10] := _OSSL_PARAM_int(OSSL_KDF_PARAM_X942_USE_KEYBITS, nil);
    known_settable_ctx_params[11] := _OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, nil, 0);
    known_settable_ctx_params[12] := OSSL_PARAM_END;

    Result := @known_settable_ctx_params;
end;



function x942kdf_derive(vctx : Pointer; key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
var
  ctx : PKDF_X942;

  ret : integer;

  ctr, der : PByte;
  md: PEVP_MD;
  der_len : size_t;
begin
    ctx := (PKDF_X942  (vctx));
    ret := 0;
    der := nil;
    der_len := 0;
    if (not ossl_prov_is_running)  or
       (0>= x942kdf_set_ctx_params(ctx, params))  then
        Exit(0);
    {
     * These 2 options encode to the same field so only one of them should be
     * active at once.
     }
    if (ctx.use_keybits>0)  and  (ctx.supp_pubinfo <> nil) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_PUBINFO);
        Exit(0);
    end;
    {
     * If the blob of acvp data is used then the individual info fields that it
     * replaces should0>= also be defined.
     }
    if (ctx.acvpinfo <> nil)
         and  (  (ctx.partyuinfo <> nil)
             or  (ctx.partyvinfo <> nil)
             or  (ctx.supp_pubinfo <> nil)
             or  (ctx.supp_privinfo <> nil) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        Exit(0);
    end;
    if ctx.secret = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        Exit(0);
    end;
    md := ossl_prov_digest_md(@ctx.digest);
    if md = nil then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        Exit(0);
    end;
    if (ctx.cek_oid = nil)  or  (ctx.cek_oid_len = 0) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CEK_ALG);
        Exit(0);
    end;
    if (ctx.partyuinfo <> nil)  and  (ctx.partyuinfo_len >= X942KDF_MAX_INLEN) then begin
        {
         * Note the ukm length MUST be 512 bits if it is used.
         * For backwards compatibility the old check is being done.
         }
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_UKM_LENGTH);
        Exit(0);
    end;
    { generate the otherinfo der }
    if 0>= x942_encode_otherinfo(get_result(ctx.use_keybits >0, ctx.dkm_len , 0),
                               ctx.cek_oid, ctx.cek_oid_len,
                               ctx.acvpinfo, ctx.acvpinfo_len,
                               ctx.partyuinfo, ctx.partyuinfo_len,
                               ctx.partyvinfo, ctx.partyvinfo_len,
                               ctx.supp_pubinfo, ctx.supp_pubinfo_len,
                               ctx.supp_privinfo, ctx.supp_privinfo_len,
                               @der, @der_len, @ctr) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        Exit(0);
    end;
    ret := x942kdf_hash_kdm(md, ctx.secret, ctx.secret_len,
                           der, der_len, ctr, key, keylen);
    OPENSSL_free(Pointer(der));
    Result := ret;
end;





procedure x942kdf_reset( vctx : Pointer);
var
  ctx : PKDF_X942;

  provctx : Pointer;
begin
    ctx := (PKDF_X942  (vctx));
    provctx := ctx.provctx;
    ossl_prov_digest_reset(@ctx.digest);
    OPENSSL_clear_free(Pointer(ctx.secret), ctx.secret_len);
    OPENSSL_clear_free(Pointer(ctx.acvpinfo), ctx.acvpinfo_len);
    OPENSSL_clear_free(Pointer(ctx.partyuinfo), ctx.partyuinfo_len);
    OPENSSL_clear_free(Pointer(ctx.partyvinfo), ctx.partyvinfo_len);
    OPENSSL_clear_free(Pointer(ctx.supp_pubinfo), ctx.supp_pubinfo_len);
    OPENSSL_clear_free(Pointer(ctx.supp_privinfo), ctx.supp_privinfo_len);
    memset(ctx, 0, sizeof( ctx^));
    ctx.provctx := provctx;
    ctx.use_keybits := 1;
end;





procedure x942kdf_free( vctx : Pointer);
var
  ctx : PKDF_X942;
begin
    ctx := (PKDF_X942  (vctx));
    if ctx <> nil then
    begin
        x942kdf_reset(ctx);
        OPENSSL_free(Pointer(ctx));
    end;
end;




function x942kdf_new( provctx : Pointer):Pointer;
var
  ctx : PKDF_X942;
begin
    if not ossl_prov_is_running() then
        Exit(0);
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx =  nil then
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    ctx.provctx := provctx;
    ctx.use_keybits := 1;
    Result := ctx;
end;

end.
