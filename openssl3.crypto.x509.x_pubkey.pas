unit openssl3.crypto.x509.x_pubkey;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
  Td2i_x509_pubkey_func = function (a : PPX509_PUBKEY;const _in : PPByte; len : long):PX509_PUBKEY;

function i2d_X509_PUBKEY(const a : Pointer; _out : PPByte):integer;
function X509_PUBKEY_new:PX509_PUBKEY;
procedure X509_PUBKEY_free( a : PX509_PUBKEY);
function d2i_X509_PUBKEY(a : PPX509_PUBKEY;const _in : PPByte; len : long):PX509_PUBKEY;
function X509_PUBKEY_it: PASN1_ITEM;
 procedure x509_pubkey_ex_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
function x509_pubkey_ex_i2d(const pval : PPASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
function x509_pubkey_ex_print(_out : PBIO;const pval : PPASN1_VALUE; indent : integer;const fname : PUTF8Char;const pctx : PASN1_PCTX):integer;
function x509_pubkey_ex_new_ex(pval : PPASN1_VALUE;const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function x509_pubkey_ex_d2i_ex(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : UTF8Char; ctx : PASN1_TLC; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
 function x509_pubkey_ex_populate(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
function x509_pubkey_set0_libctx(x : PX509_PUBKEY; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function X509_PUBKEY_INTERNAL_it:PASN1_ITEM;
function x509_pubkey_decode(ppkey : PPEVP_PKEY;const key : PX509_PUBKEY):integer;
function ossl_x509_PUBKEY_get0_libctx(plibctx : PPOSSL_LIB_CTX;const ppropq : PPUTF8Char; key : PX509_PUBKEY):integer;
function X509_PUBKEY_get0_param(ppkalg : PPASN1_OBJECT;const pk : PPByte; ppklen : PInteger; pa : PPX509_ALGOR;const pub : PX509_PUBKEY):integer;
function X509_PUBKEY_set( x : PPX509_PUBKEY; pkey : PEVP_PKEY):integer;
 function OSSL_ENCODER_to_data( ctx : POSSL_ENCODER_CTX; pdata : PPByte; pdata_len : Psize_t):integer;
function i2d_PUBKEY(const a : Pointer; pp : PPByte):integer;
function d2i_PUBKEY_ex(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
function d2i_PUBKEY_int(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; force_legacy : uint32; d2i_x509_pubkey : Td2i_x509_pubkey_func):PEVP_PKEY;
function X509_PUBKEY_get(const key : PX509_PUBKEY):PEVP_PKEY;
function X509_PUBKEY_get0(const key : PX509_PUBKEY):PEVP_PKEY;
function X509_PUBKEY_set0_param( pub : PX509_PUBKEY; aobj : PASN1_OBJECT; ptype : integer; pval : Pointer; penc : PByte; penclen : integer):integer;
function ossl_d2i_DH_PUBKEY(a : PPDH;const pp : PPByte; length : long):PDH;
 function ossl_d2i_PUBKEY_legacy(a : PPEVP_PKEY;const pp : PPByte; length : long):PEVP_PKEY;
function ossl_d2i_DHx_PUBKEY(a : PPDH;const pp : PPByte; length : long):PDH;
 function d2i_DSA_PUBKEY(a : PPDSA;const pp : PPByte; length : long):PDSA;
function d2i_EC_PUBKEY(a : PPEC_KEY;const pp : PPByte; length : long):PEC_KEY;
function ossl_d2i_X25519_PUBKEY( a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
function ossl_d2i_X448_PUBKEY(a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
function ossl_d2i_ED25519_PUBKEY(a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
 function ossl_d2i_ED448_PUBKEY(a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
function d2i_RSA_PUBKEY(a : PPRSA;const pp : PPByte; length : long):PRSA;
function ossl_d2i_X509_PUBKEY_INTERNAL(const pp : PPByte; len : long; libctx : POSSL_LIB_CTX):PX509_PUBKEY;
procedure ossl_X509_PUBKEY_INTERNAL_free( xpub : PX509_PUBKEY);




const x509_pubkey_ff: TASN1_EXTERN_FUNCS  = (
    app_data: nil;
    asn1_ex_new: nil;
    asn1_ex_free: x509_pubkey_ex_free;
    asn1_ex_clear: nil;
    asn1_ex_d2i: nil;
    asn1_ex_i2d: x509_pubkey_ex_i2d;
    asn1_ex_print: x509_pubkey_ex_print;
    asn1_ex_new_ex: x509_pubkey_ex_new_ex;
    asn1_ex_d2i_ex: x509_pubkey_ex_d2i_ex;
);

var
  X509_PUBKEY_INTERNAL_seq_tt: array[0..1] of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.mem, openssl3.crypto.o_str,
     openssl3.crypto.encode_decode.encoder_pkey,
     openssl3.crypto.encode_decode.encoder_lib,
     openssl3.crypto.encode_decode.encoder_meth,
     openssl3.crypto.encode_decode.decoder_meth,
     openssl3.crypto.encode_decode.decoder_lib,
     openssl3.crypto.asn1.a_i2d_fp,   openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.tasn_enc,   openssl3.crypto.asn1.x_algor,
     openssl3.crypto.evp.p_lib,       openssl3.providers.fips.fipsprov,
     openssl3.crypto.evp,             openssl3.crypto.dh.dh_lib,
     openssl3.crypto.asn1.tasn_prn,   OpenSSL3.include.openssl.asn1,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.engine.tb_pkmeth,
     openssl3.crypto.asn1.tasn_new,   openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.dsa.dsa_lib,     openssl3.crypto.evp.p_legacy,
     openssl3.crypto.bio.bio_lib,     openssl3.crypto.bio.bss_mem,
     openssl3.crypto.ec.ec_key,       openssl3.crypto.ec.ecx_key,
     openssl3.crypto.rsa.rsa_lib,
     openssl3.crypto.engine.eng_init, openssl3.crypto.encode_decode.decoder_pkey,
     openssl3.crypto.asn1.tasn_dec,   OpenSSL3.Err, OpenSSL3.common;



procedure ossl_X509_PUBKEY_INTERNAL_free( xpub : PX509_PUBKEY);
begin
    ASN1_item_free(PASN1_VALUE(xpub), X509_PUBKEY_INTERNAL_it);
end;


function ossl_d2i_X509_PUBKEY_INTERNAL(const pp : PPByte; len : long; libctx : POSSL_LIB_CTX):PX509_PUBKEY;
var
  xpub : PX509_PUBKEY;
begin
    xpub := OPENSSL_zalloc(sizeof( xpub^));
    if xpub = nil then Exit(nil);
    Result := PX509_PUBKEY (ASN1_item_d2i_ex(PPASN1_VALUE(@xpub), pp, len,
                                           X509_PUBKEY_INTERNAL_it,
                                           libctx, nil));
end;


function d2i_RSA_PUBKEY(a : PPRSA;const pp : PPByte; length : long):PRSA;
var
  pkey : PEVP_PKEY;
  key : PRSA;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    key := EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then begin
        RSA_free(a^);
        a^ := key;
    end;
    Result := key;
end;


function ossl_d2i_ED448_PUBKEY(a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
var
  pkey : PEVP_PKEY;
  key : PECX_KEY;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    if EVP_PKEY_get_id(pkey) = EVP_PKEY_ED448  then
        key := ossl_evp_pkey_get1_ED448(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then begin
        ossl_ecx_key_free( a^);
        a^ := key;
    end;
    Result := key;
end;



function ossl_d2i_ED25519_PUBKEY(a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
var
  pkey : PEVP_PKEY;
  key : PECX_KEY;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    key := ossl_evp_pkey_get1_ED25519(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then begin
        ossl_ecx_key_free( a^);
        a^ := key;
    end;
    Result := key;
end;




function ossl_d2i_X448_PUBKEY(a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
var
  pkey : PEVP_PKEY;
  key : PECX_KEY;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    if EVP_PKEY_get_id(pkey) = EVP_PKEY_X448  then
        key := ossl_evp_pkey_get1_X448(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then begin
        ossl_ecx_key_free( a^);
        a^ := key;
    end;
    Result := key;
end;


function ossl_d2i_X25519_PUBKEY(a : PPECX_KEY;const pp : PPByte; length : long):PECX_KEY;
var
  pkey : PEVP_PKEY;
  key : PECX_KEY;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    if EVP_PKEY_get_id(pkey) = EVP_PKEY_X25519  then
        key := ossl_evp_pkey_get1_X25519(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then
    begin
        ossl_ecx_key_free(a^);
        a^ := key;
    end;
    Result := key;
end;

function d2i_EC_PUBKEY(a : PPEC_KEY;const pp : PPByte; length : long):PEC_KEY;
var
  pkey : PEVP_PKEY;
  key : PEC_KEY;
  q : PByte;
  _type : integer;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    _type := EVP_PKEY_get_id(pkey);
    if (_type = EVP_PKEY_EC)  or  (_type = EVP_PKEY_SM2) then
       key := EVP_PKEY_get1_EC_KEY(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then begin
        EC_KEY_free( a^);
        a^ := key;
    end;
    Result := key;
end;


function d2i_DSA_PUBKEY(a : PPDSA;const pp : PPByte; length : long):PDSA;
var
  pkey : PEVP_PKEY;
  key : PDSA;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    key := EVP_PKEY_get1_DSA(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then
    begin
        DSA_free(a^);
        a^ := key;
    end;
    Result := key;
end;




function ossl_d2i_DHx_PUBKEY(a : PPDH;const pp : PPByte; length : long):PDH;
var
  pkey : PEVP_PKEY;
  key : PDH;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    if EVP_PKEY_get_id(pkey) = EVP_PKEY_DHX  then
        key := EVP_PKEY_get1_DH(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then begin
        DH_free( a^);
        a^ := key;
    end;
    Result := key;
end;

function ossl_d2i_PUBKEY_legacy(a : PPEVP_PKEY;const pp : PPByte; length : long):PEVP_PKEY;
begin
    Result := d2i_PUBKEY_int(a, pp, length, nil, nil, 1, d2i_X509_PUBKEY);
end;

function ossl_d2i_DH_PUBKEY(a : PPDH;const pp : PPByte; length : long):PDH;
var
  pkey : PEVP_PKEY;
  key : PDH;
  q : PByte;
begin
    key := nil;
    q := pp^;
    pkey := ossl_d2i_PUBKEY_legacy(nil, @q, length);
    if pkey = nil then Exit(nil);
    if EVP_PKEY_get_id(pkey) = EVP_PKEY_DH  then
        key := EVP_PKEY_get1_DH(pkey);
    EVP_PKEY_free(pkey);
    if key = nil then Exit(nil);
    pp^ := q;
    if a <> nil then begin
        DH_free( a^);
        a^ := key;
    end;
    Result := key;
end;

function X509_PUBKEY_set0_param( pub : PX509_PUBKEY; aobj : PASN1_OBJECT; ptype : integer; pval : Pointer; penc : PByte; penclen : integer):integer;
begin
    if 0>=X509_ALGOR_set0(pub.algor, aobj, ptype, pval) then
        Exit(0);
    if penc <> nil then
    begin
        OPENSSL_free(pub.public_key.data);
        pub.public_key.data := penc;
        pub.public_key.length := penclen;
        { Set number of unused bits to zero }
        pub.public_key.flags := pub.public_key.flags and not (ASN1_STRING_FLAG_BITS_LEFT or $07);
        pub.public_key.flags := pub.public_key.flags  or ASN1_STRING_FLAG_BITS_LEFT;
    end;
    Result := 1;
end;




function X509_PUBKEY_get0(const key : PX509_PUBKEY):PEVP_PKEY;
begin
    if key = nil then begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if key.pkey = nil then begin
        { We failed to decode the key when we loaded it, or it was never set }
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        Exit(nil);
    end;
    Result := key.pkey;
end;




function X509_PUBKEY_get(const key : PX509_PUBKEY):PEVP_PKEY;
var
  ret : PEVP_PKEY;
begin
    ret := X509_PUBKEY_get0(key);
    if (ret <> nil)  and  (0>= EVP_PKEY_up_ref(ret)) then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR);
        ret := nil;
    end;
    Result := ret;
end;

function d2i_PUBKEY_int(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char; force_legacy : uint32; d2i_x509_pubkey : Td2i_x509_pubkey_func):PEVP_PKEY;
var
  xpk, xpk2 : PX509_PUBKEY;
  pxpk: PPX509_PUBKEY;
  pktmp : PEVP_PKEY;
  q : PByte;
  label _end;
begin
    xpk2 := nil; pxpk := nil;
    pktmp := nil;
    q := pp^;
    {
     * If libctx or propq are non-nil, we take advantage of the reuse
     * feature.  It's not generally recommended, but is safe enough for
     * newly created structures.
     }
    if (libctx <> nil)  or  (propq <> nil)  or  (force_legacy>0) then
    begin
        xpk2 := OPENSSL_zalloc(sizeof( xpk2^));
        if xpk2 = nil then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
        if 0>= x509_pubkey_set0_libctx(xpk2, libctx, propq) then
            goto _end ;
        xpk2.flag_force_legacy := not  not force_legacy;
        pxpk := @xpk2;
    end;
    xpk := d2i_x509_pubkey(pxpk, @q, length);
    if xpk = nil then
       goto _end ;
    pktmp := X509_PUBKEY_get(xpk);
    X509_PUBKEY_free(xpk);
    xpk2 := nil;                 { We know that xpk = xpk2 }
    if pktmp = nil then
       goto _end ;
    pp^ := q;
    if a <> nil then
    begin
        EVP_PKEY_free(a^);
        a^ := pktmp;
    end;
 _end:
    X509_PUBKEY_free(xpk2);
    Result := pktmp;
end;



function d2i_PUBKEY_ex(a : PPEVP_PKEY;const pp : PPByte; length : long; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PEVP_PKEY;
begin
    Result := d2i_PUBKEY_int(a, pp, length, libctx, propq, 0, d2i_X509_PUBKEY);
end;

function i2d_PUBKEY(const a :Pointer; pp : PPByte):integer;
var
  ret : integer;
  xpk : PX509_PUBKEY;
  ctx : POSSL_ENCODER_CTX;
  _out : PBIO;
  buf : PBUF_MEM;
begin
    ret := -1;
    if a = nil then Exit(0);
    if PEVP_PKEY(a).ameth <> nil then
    begin
        xpk := nil;
        xpk := X509_PUBKEY_new();
        if xpk = nil then
            Exit(-1);
        { pub_encode() only encode parameters, not the key itself }
        if (Assigned(PEVP_PKEY(a).ameth.pub_encode))  and  (PEVP_PKEY(a).ameth.pub_encode(xpk, a)>0) then
        begin
            xpk.pkey := PEVP_PKEY(a);
            ret := i2d_X509_PUBKEY(xpk, pp);
            xpk.pkey := nil;
        end;
        X509_PUBKEY_free(xpk);
    end
    else
    if (PEVP_PKEY(a).keymgmt <> nil) then
    begin
        ctx := OSSL_ENCODER_CTX_new_for_pkey(a, EVP_PKEY_PUBLIC_KEY,
                                          'DER' , 'SubjectPublicKeyInfo' ,nil);
        _out := BIO_new(BIO_s_mem());
        buf := nil;
        if (OSSL_ENCODER_CTX_get_num_encoders(ctx) <> 0)
             and  (_out <> nil)
             and  (OSSL_ENCODER_to_bio(ctx, _out) > 0)
             and  (BIO_get_mem_ptr(_out, @buf) > 0) then
        begin
            ret := buf.length;
            if pp <> nil then
            begin
                if pp^ = nil then
                begin
                    pp^ := PByte( buf.data);
                    buf.length := 0;
                    buf.data := nil;
                end
                else
                begin
                    memcpy( pp^, buf.data, ret);
                    pp^  := pp^ + ret;
                end;
            end;
        end;
        BIO_free(_out);
        OSSL_ENCODER_CTX_free(ctx);
    end;
    Result := ret;
end;



function OSSL_ENCODER_to_data( ctx : POSSL_ENCODER_CTX; pdata : PPByte; pdata_len : Psize_t):integer;
var
  _out : PBIO;

  buf : PBUF_MEM;

  ret : integer;
begin
    buf := nil;
    ret := 0;
    if pdata_len = nil then begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    _out := BIO_new(BIO_s_mem());
    if (_out <> nil)
         and  (OSSL_ENCODER_to_bio(ctx, _out)>0)  and  (BIO_get_mem_ptr(_out, @buf) > 0) then
    begin
        ret := 1; { Hope for the best. A too small buffer will clear this }
        if (pdata <> nil)  and  (pdata^ <> nil) then
        begin
            if pdata_len^ < buf.length then
                {
                 * It's tempting to do |*pdata_len = size_t( buf.length|
                 * However, it's believed to be confusing more than helpful,
                 * so we don't.
                 }
                ret := 0
            else
                pdata_len^  := pdata_len^ - buf.length;
        end
        else
        begin
            { The buffer with the right size is already allocated for us }
            pdata_len^ := size_t( buf.length);
        end;
        if ret > 0 then
        begin
            if pdata <> nil then
            begin
                if pdata^ <> nil then
                begin
                    memcpy( pdata^, buf.data, buf.length);
                    pdata^  := pdata^ + buf.length;
                end
                else
                begin
                    { In this case, we steal the data from BIO_s_mem() }
                    pdata^ := PByte( buf.data);
                    buf.data := nil;
                end;
            end;
        end;
    end;
    BIO_free(_out);
    Result := ret;
end;

function X509_PUBKEY_set( x : PPX509_PUBKEY; pkey : PEVP_PKEY):integer;
var
  pk : PX509_PUBKEY;
  der : PByte;
  derlen : size_t;
  ectx : POSSL_ENCODER_CTX;
  pder : PByte;
  label _error;
begin
    pk := nil;
    if (x = nil)  or  (pkey = nil) then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if pkey.ameth <> nil then
    begin
        pk := X509_PUBKEY_new();
        if pk = nil then
        begin
            ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
            goto _error ;
        end;
        if Assigned(pkey.ameth.pub_encode) then
        begin
            if 0>= pkey.ameth.pub_encode(pk, pkey) then
            begin
                ERR_raise(ERR_LIB_X509, X509_R_PUBLIC_KEY_ENCODE_ERROR);
                goto _error ;
            end;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509, X509_R_METHOD_NOT_SUPPORTED);
            goto _error ;
        end;
    end
    else
    if (evp_pkey_is_provided(pkey)) then
    begin
        der := nil;
        derlen := 0;
        ectx := OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY,
                                          ' DER' , ' SubjectPublicKeyInfo' ,
                                          nil);
        if OSSL_ENCODER_to_data(ectx, @der, @derlen) > 0 then
        begin
            pder := der;
            pk := d2i_X509_PUBKEY(nil, @pder, long(derlen));
        end;
        OSSL_ENCODER_CTX_free(ectx);
        OPENSSL_free(der);
    end;
    if pk = nil then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM);
        goto _error ;
    end;
    X509_PUBKEY_free( x^);
    if 0>= EVP_PKEY_up_ref(pkey) then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR);
        goto _error ;
    end;
    x^ := pk;
    {
     * pk.pkey is nil when using the legacy routine, but is non-nil when
     * going through the encoder, and for all intents and purposes, it's
     * a perfect copy of the public key portions of |pkey|, just not the same
     * instance.  If that's all there was to pkey then we could simply return
     * early, right here. However, some application might very well depend on
     * the passed |pkey| being used and none other, so we spend a few more
     * cycles throwing away the newly created |pk.pkey| and replace it with
     * |pkey|.
     }
    if pk.pkey <> nil then EVP_PKEY_free(pk.pkey);
    pk.pkey := pkey;
    Exit(1);
 _error:
    X509_PUBKEY_free(pk);
    Result := 0;
end;



function X509_PUBKEY_get0_param(ppkalg : PPASN1_OBJECT;const pk : PPByte; ppklen : PInteger; pa : PPX509_ALGOR;const pub : PX509_PUBKEY):integer;
begin
    if ppkalg <> nil then
       ppkalg^ := pub.algor.algorithm;
    if pk <> nil then
    begin
        pk^ := pub.public_key.data;
        ppklen^ := pub.public_key.length;
    end;
    if pa <> nil then
       pa^ := pub.algor;
    Result := 1;
end;




function ossl_x509_PUBKEY_get0_libctx(plibctx : PPOSSL_LIB_CTX;const ppropq : PPUTF8Char; key : PX509_PUBKEY):integer;
begin
    if plibctx <> nil then
      plibctx^ := key.libctx;
    if ppropq <> nil then
       ppropq^ := key.propq;
    Result := 1;
end;




function x509_pubkey_decode(ppkey : PPEVP_PKEY;const key : PX509_PUBKEY):integer;
var
  pkey : PEVP_PKEY;
  nid : integer;
  e : PENGINE;
  label _error;
begin
    nid := OBJ_obj2nid(key.algor.algorithm);
    if 0>= key.flag_force_legacy then
    begin
{$IFNDEF OPENSSL_NO_ENGINE}
        e := nil;
        e := ENGINE_get_pkey_meth_engine(nid);
        if e = nil then Exit(0);
        ENGINE_finish(e);
{$ELSE Exit(0);}
{$ENDIF}
    end;
    pkey := EVP_PKEY_new();
    if pkey = nil then
    begin
        ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    if 0>= EVP_PKEY_set_type(pkey, nid) then
    begin
        ERR_raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM);
        goto _error ;
    end;
    if Assigned(pkey.ameth.pub_decode) then
    begin
        {
         * Treat any failure of pub_decode as a decode error. In
         * future we could have different return codes for decode
         * errors and fatal errors such as malloc failure.
         }
        if 0>= pkey.ameth.pub_decode(pkey, key) then
            goto _error ;
    end
    else
    begin
        ERR_raise(ERR_LIB_X509, X509_R_METHOD_NOT_SUPPORTED);
        goto _error ;
    end;
    ppkey^ := pkey;
    Exit(1);
 _error:
    EVP_PKEY_free(pkey);
    Result := 0;
end;

var
  local_it :TASN1_ITEM;

function X509_PUBKEY_INTERNAL_it:PASN1_ITEM;
begin
 local_it := get_ASN1_ITEM($1, 16, @X509_PUBKEY_INTERNAL_seq_tt,
             sizeof(X509_PUBKEY_INTERNAL_seq_tt) div sizeof(TASN1_TEMPLATE),
             Pointer(0) , sizeof(TX509_PUBKEY), 'X509_PUBKEY');

 result := @local_it;
end;


function x509_pubkey_set0_libctx(x : PX509_PUBKEY; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    if x <> nil then
    begin
        x.libctx := libctx;
        OPENSSL_free(x.propq);
        x.propq := nil;
        if propq <> nil then
        begin
            OPENSSL_strdup(x.propq ,propq);
            if x.propq = nil then
               Exit(0);
        end;
    end;
    Result := 1;
end;


function x509_pubkey_ex_populate(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
var
  pubkey : PX509_PUBKEY;
begin
    pubkey := PX509_PUBKEY(pval^);
    if pubkey.public_key = nil then
       pubkey.public_key := ASN1_BIT_STRING_new();
    if pubkey.algor = nil then
       pubkey.algor := X509_ALGOR_new();
    Result := int( (pubkey.algor <> nil) and
                   (pubkey.public_key <> nil) );

end;

function x509_pubkey_ex_new_ex(pval : PPASN1_VALUE;const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  ret : PX509_PUBKEY;
begin
    ret := OPENSSL_zalloc(sizeof(ret^));
    if (ret = nil)
         or  (0>= x509_pubkey_ex_populate(PPASN1_VALUE(@ret), nil))
         or  (0>= x509_pubkey_set0_libctx(ret, libctx, propq))  then
    begin
        x509_pubkey_ex_free(PPASN1_VALUE(@ret), nil);
        ret := nil;
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
    end
    else
    begin
        pval^ := PASN1_VALUE( ret);
    end;
    Result := Int(ret <> nil);
end;


function x509_pubkey_ex_d2i_ex(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : UTF8Char; ctx : PASN1_TLC; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
    in_saved, p   : PByte;
    publen     : size_t;
    pubkey     : PX509_PUBKEY;
    ret        : integer;
    dctx       : POSSL_DECODER_CTX;
    tmpbuf     : PByte;
    txtoidname : array[0..(OSSL_MAX_NAME_SIZE)-1] of UTF8Char;
    slen       : size_t;
    item         : PASN1_ITEM;
    label _end;
begin
    in_saved := _in^;
    dctx := nil;
    tmpbuf := nil;
    if (pval^ = nil)  and  (0>= x509_pubkey_ex_new_ex(pval, it, libctx, propq)) then
        Exit(0);
    if 0>= x509_pubkey_ex_populate(pval, nil) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    { This ensures that |*in| advances properly no matter what }
    item := X509_PUBKEY_INTERNAL_it;
    ret := ASN1_item_ex_d2i(pval, _in, len, item, tag, aclass, Ord(opt), ctx);
    if (ret <= 0) then
        Exit(ret);
    publen := _in^ - in_saved;
    if not ossl_assert(publen > 0) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    pubkey := PX509_PUBKEY(pval^);
    EVP_PKEY_free(pubkey.pkey);
    pubkey.pkey := nil;
    {
     * Opportunistically decode the key but remove any non fatal errors
     * from the queue. Subsequent explicit attempts to decode/use the key
     * will return an appropriate error.
     }
    ERR_set_mark();
    {
     * Try to decode with legacy method first.  This ensures that engines
     * aren't overridden by providers.
     }
    ret := x509_pubkey_decode(@pubkey.pkey, pubkey);
    if ret = -1 then
    begin
        { -1 indicates a fatal error, like malloc failure }
        ERR_clear_last_mark();
        goto _end ;
    end;
    { Try to decode it into an EVP_PKEY with OSSL_DECODER }
    if (ret <= 0)  and  (0>= pubkey.flag_force_legacy) then
    begin
        slen := publen;
        {
        * The decoders don't know how to handle anything other than Universal
        * class so we modify the data accordingly.
        }
        if aclass <> V_ASN1_UNIVERSAL then
        begin
            tmpbuf := OPENSSL_memdup(in_saved, publen);
            if tmpbuf = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
            in_saved := tmpbuf;
            tmpbuf^ := V_ASN1_CONSTRUCTED or V_ASN1_SEQUENCE;
        end;
        p := in_saved;
        if OBJ_obj2txt(txtoidname, sizeof(txtoidname) ,
                        pubkey.algor.algorithm, 0) <= 0  then
        begin
            ERR_clear_last_mark();
            goto _end ;
        end;
        dctx := OSSL_DECODER_CTX_new_for_pkey(@pubkey.pkey,
                                           'DER', 'SubjectPublicKeyInfo',
                                           txtoidname, EVP_PKEY_PUBLIC_KEY,
                                           pubkey.libctx,
                                           pubkey.propq);
        if (dctx <> nil) then
            {
             * As said higher up, we're being opportunistic.  In other words,
             * we don't care if we fail.
             }
            if OSSL_DECODER_from_data(dctx, @p, @slen) > 0 then
            begin
                if slen <> 0 then
                begin
                    {
                     * If we successfully decoded then we *must* consume all the
                     * bytes.
                     }
                    ERR_clear_last_mark();
                    ERR_raise(ERR_LIB_ASN1, EVP_R_DECODE_ERROR);
                    goto _end ;
                end;
            end;
    end;
    ERR_pop_to_mark();
    ret := 1;
 _end:
    OSSL_DECODER_CTX_free(dctx);
    OPENSSL_free(tmpbuf);
    Result := ret;
end;


function x509_pubkey_ex_print(_out : PBIO;const pval : PPASN1_VALUE; indent : integer;const fname : PUTF8Char;const pctx : PASN1_PCTX):integer;
begin
    Result := ASN1_item_print(_out, pval^, indent, X509_PUBKEY_INTERNAL_it, pctx);
end;




function x509_pubkey_ex_i2d(const pval : PPASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
begin
    Result := ASN1_item_ex_i2d(pval, _out, X509_PUBKEY_INTERNAL_it, tag, aclass);
end;

procedure x509_pubkey_ex_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
var
  pubkey : PX509_PUBKEY;
begin
    pubkey := PX509_PUBKEY(pval^);
    if (pval <> nil)  and  (pubkey <> nil) then
    begin
        X509_ALGOR_free(pubkey.algor);
        ASN1_BIT_STRING_free(pubkey.public_key);
        EVP_PKEY_free(pubkey.pkey);
        OPENSSL_free(pubkey.propq);
        OPENSSL_free(pubkey);
        pval^ := nil;
    end;
end;

function X509_PUBKEY_it: PASN1_ITEM;
const local_it: TASN1_ITEM = (
        itype     : $4;
        utype     : 16;
        templates : nil;
        tcount    : 0;
        funcs     : Addr(x509_pubkey_ff);
        size      : 0;
        sname     : 'X509_PUBKEY');
begin
   result  := @local_it;
end;

//typedef void *d2i_of_void(void **, const unsigned char **, long);

function d2i_X509_PUBKEY(a : PPX509_PUBKEY;const _in : PPByte; len : long):PX509_PUBKEY;
var
  it: PASN1_ITEM;
begin
   it := X509_PUBKEY_it;
   Result := ASN1_item_d2i(PPASN1_VALUE(a), _in, len, it);
end;

function X509_PUBKEY_new:PX509_PUBKEY;
begin
   Result := PX509_PUBKEY(ASN1_item_new(X509_PUBKEY_it));
end;


procedure X509_PUBKEY_free( a : PX509_PUBKEY);
begin
   ASN1_item_free(PASN1_VALUE( a), X509_PUBKEY_it);
end;

function i2d_X509_PUBKEY(const a : Pointer; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, X509_PUBKEY_it);
end;


initialization
  X509_PUBKEY_INTERNAL_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_PUBKEY(0).algor), 'algor', X509_ALGOR_it );
  X509_PUBKEY_INTERNAL_seq_tt[1] := get_ASN1_TEMPLATE( 0, 0, size_t(@PX509_PUBKEY(0).public_key), 'public_key', ASN1_BIT_STRING_it );




end.
