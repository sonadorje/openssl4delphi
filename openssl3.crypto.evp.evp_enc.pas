unit openssl3.crypto.evp.evp_enc;

interface
uses openssl.api, SysUtils;

{$ifdef PTRDIFF_T}
{$undef PTRDIFF_T}
{$endif}
{$if defined(OPENSSL_SYS_VMS) and (__INITIAL_POINTER_SIZE=64)}
(*
 * Then we have VMS that distinguishes itself by adhering to
 * sizeof(size_t)==4 even in 64-bit builds, which means that
 * difference between two pointers might be truncated to 32 bits.
 * In the context one can even wonder how comparison for
 * equality is implemented. To be on the safe side we adhere to
 * PTRDIFF_T even for comparison for equality.
 *)
 PTRDIFF_T = uint64_t;
{$else}
  type PTRDIFF_T = size_t;
{$endif}

function EVP_CIPHER_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_CIPHER;
function evp_cipher_from_algorithm({const} name_id : integer; const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function evp_cipher_new:PEVP_CIPHER;
procedure set_legacy_nid(const name : PUTF8Char; vlegacy_nid : Pointer);
procedure EVP_CIPHER_free( cipher : Pointer);
procedure evp_cipher_free_int( cipher : PEVP_CIPHER);
function EVP_CIPHER_gettable_ctx_params(const cipher : PEVP_CIPHER):POSSL_PARAM;
//function evp_cipher_up_ref( cipher : Pointer):integer;
function EVP_CIPHER_CTX_get_params( ctx : PEVP_CIPHER_CTX; params : POSSL_PARAM):integer;
function EVP_CIPHER_CTX_new:PEVP_CIPHER_CTX;
 function EVP_EncryptInit_ex(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte):integer;
function EVP_CipherInit_ex(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte; enc : integer):integer;
function evp_cipher_init_internal(ctx : PEVP_CIPHER_CTX;{const} cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte; enc : integer;const params : POSSL_PARAM):integer;
function EVP_EncryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer;
function EVP_EncryptFinal_ex( ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger):integer;  overload;
procedure EVP_CIPHER_CTX_free( ctx : PEVP_CIPHER_CTX);

function EVP_DecryptInit_ex(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte):integer;
function EVP_DecryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer;
function EVP_DecryptFinal_ex( ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger):integer;
function ossl_is_partially_overlapping(const ptr1, ptr2 : Pointer; len : integer):integer;
function evp_EncryptDecryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;{const} _in : PByte; inl : integer):integer;
function EVP_CIPHER_CTX_reset( ctx : PEVP_CIPHER_CTX):integer;
function EVP_CIPHER_CTX_set_padding( ctx : PEVP_CIPHER_CTX; pad : integer):integer;
function EVP_CIPHER_CTX_ctrl( ctx : PEVP_CIPHER_CTX; _type, arg : integer; ptr : Pointer):integer;
function EVP_CIPHER_CTX_set_params(ctx : PEVP_CIPHER_CTX;const params : POSSL_PARAM):integer;
function EVP_CIPHER_CTX_set_key_length( c : PEVP_CIPHER_CTX; keylen : integer):integer;
function EVP_CIPHER_settable_ctx_params(const cipher : PEVP_CIPHER):POSSL_PARAM;
function EVP_CipherUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer;

function EVP_CIPHER_CTX_copy(_out : PEVP_CIPHER_CTX;const _in : PEVP_CIPHER_CTX):integer;
function EVP_CipherFinal_ex( ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger):integer;
function EVP_CIPHER_up_ref( cipher : PEVP_CIPHER):integer;
function EVP_EncryptInit(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER;const key, iv : PByte):integer;
function EVP_CipherInit(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER;const key, iv : PByte; enc : integer):integer;
function EVP_CIPHER_CTX_rand_key( ctx : PEVP_CIPHER_CTX; key : PByte):integer;

const
  EVP_OpenUpdate: function (ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer = EVP_DecryptUpdate;
  EVP_SealUpdate: function (ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer = EVP_EncryptUpdate;
  EVP_CIPHER_CTX_init: function( ctx : PEVP_CIPHER_CTX):integer =  EVP_CIPHER_CTX_reset;

implementation

uses  openssl3.crypto.evp.evp_fetch,           openssl3.crypto.mem,
      openssl3.crypto.evp.evp_lib,             openssl3.include.internal.refcount,
      OpenSSL3.threads_none,                   openssl3.crypto.objects.o_names,
      openssl3.crypto.engine.eng_init,         openssl3.crypto.objects.obj_dat,
      openssl3.crypto.provider_core,           openssl3.crypto.core_algorithm,
      openssl3.crypto.params,                  openssl3.crypto.evp.evp_utils,
      OpenSSL3.common, OpenSSL3.Err,           openssl3.crypto.evp,
      OpenSSL3.openssl.core_dispatch,          openssl3.crypto.engine.tb_cipher,
      openssl3.crypto.rand.rand_lib;

{$ifndef FIPS_MODULE}
function EVP_CIPHER_CTX_get_libctx( ctx : PEVP_CIPHER_CTX):POSSL_LIB_CTX;
var
  cipher : PEVP_CIPHER;
  prov   : POSSL_PROVIDER;
begin
    cipher := ctx.cipher;
    if cipher = nil then
       Exit(nil);
    prov := EVP_CIPHER_get0_provider(cipher);
    Result := ossl_provider_libctx(prov);
end;
{$ENDIF}

function EVP_CIPHER_CTX_rand_key( ctx : PEVP_CIPHER_CTX; key : PByte):integer;
var
  kl : integer;
  libctx : POSSL_LIB_CTX;
begin
    if ctx.cipher.flags and EVP_CIPH_RAND_KEY > 0 then
       Exit(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0, key));
{$IFDEF FIPS_MODULE}
    Exit(0);
{$ELSE}
   begin
        libctx := EVP_CIPHER_CTX_get_libctx(ctx);
        kl := EVP_CIPHER_CTX_get_key_length(ctx);
        if (kl <= 0)  or  (RAND_priv_bytes_ex(libctx, key, kl, 0) <= 0)  then
            Exit(0);
        Exit(1);
    end;
{$endif} { FIPS_MODULE }
end;

function EVP_CipherInit(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER;const key, iv : PByte; enc : integer):integer;
begin
    if cipher <> nil then
       EVP_CIPHER_CTX_reset(ctx);
    Result := evp_cipher_init_internal(ctx, cipher, nil, key, iv, enc, nil);
end;

function EVP_EncryptInit(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER;const key, iv : PByte):integer;
begin
    Result := EVP_CipherInit(ctx, cipher, key, iv, 1);
end;

function _evp_cipher_up_ref( cipher : Pointer):integer;
begin
    Result := EVP_CIPHER_up_ref(cipher);
end;

function EVP_CIPHER_up_ref( cipher : PEVP_CIPHER):integer;
var
  ref : integer;
begin
    ref := 0;
    if cipher.origin = EVP_ORIG_DYNAMIC then
       CRYPTO_UP_REF(cipher.refcnt, ref, cipher.lock);
    Result := 1;
end;

function EVP_CipherFinal_ex( ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger):integer;
begin
    if ctx.encrypt > 0 then
       Exit(EVP_EncryptFinal_ex(ctx, _out, outl))
    else
        Result := EVP_DecryptFinal_ex(ctx, _out, outl);
end;

function EVP_CIPHER_CTX_copy(_out : PEVP_CIPHER_CTX;const _in : PEVP_CIPHER_CTX):integer;
label _legacy;
begin
    if (_in = nil)  or  (_in.cipher = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INPUT_NOT_INITIALIZED);
        Exit(0);
    end;
    if _in.cipher.prov = nil then goto _legacy;
    if not Assigned(_in.cipher.dupctx) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX);
        Exit(0);
    end;
    EVP_CIPHER_CTX_reset(_out);
    _out^ := _in^;
    _out.algctx := nil;
    if (_in.fetched_cipher <> nil)  and  (0>=EVP_CIPHER_up_ref(_in.fetched_cipher)) then
    begin
        _out.fetched_cipher := nil;
        Exit(0);
    end;
    _out.algctx := _in.cipher.dupctx(_in.algctx);
    if _out.algctx = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX);
        Exit(0);
    end;
    Exit(1);
    { Code below to be removed when legacy support is dropped. }
 _legacy:
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    { Make sure it's safe to copy a cipher context using an PENGINE  }
    if (_in.engine <> nil)  and  (0>=ENGINE_init(_in.engine) ) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_ENGINE_LIB);
        Exit(0);
    end;
{$ENDIF}
    EVP_CIPHER_CTX_reset(_out);
    memcpy(_out, _in, sizeof( _out^));
    if (_in.cipher_data <> nil)  and  (_in.cipher.ctx_size > 0) then
    begin
        _out.cipher_data := OPENSSL_malloc(_in.cipher.ctx_size);
        if _out.cipher_data = nil then begin
            _out.cipher := nil;
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(_out.cipher_data, _in.cipher_data, _in.cipher.ctx_size);
    end;
    if _in.cipher.flags and EVP_CIPH_CUSTOM_COPY > 0 then
        if (0>= _in.cipher.ctrl(PEVP_CIPHER_CTX(_in), EVP_CTRL_COPY, 0, _out)) then
        begin
            _out.cipher := nil;
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
    Result := 1;
end;

function EVP_CipherUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer;
begin
    if ctx.encrypt > 0 then
       Exit(EVP_EncryptUpdate(ctx, _out, outl, _in, inl))
    else
        Result := EVP_DecryptUpdate(ctx, _out, outl, _in, inl);
end;

function EVP_CIPHER_settable_ctx_params(const cipher : PEVP_CIPHER):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (cipher <> nil)  and  (Assigned(cipher.settable_ctx_params)) then
    begin
        provctx := ossl_provider_ctx(EVP_CIPHER_get0_provider(cipher));
        Exit(cipher.settable_ctx_params(nil, provctx));
    end;
    Result := nil;
end;

function EVP_CIPHER_CTX_set_key_length( c : PEVP_CIPHER_CTX; keylen : integer):integer;
var
  ok : integer;
  params : array of TOSSL_PARAM;
  len : size_t;
begin
    if c.cipher.prov <> nil then
    begin
        params := [OSSL_PARAM_END, OSSL_PARAM_END];
        len := keylen;
        if EVP_CIPHER_CTX_get_key_length(c) = keylen  then
            Exit(1);
        { Check the cipher actually understands this parameter }
        if OSSL_PARAM_locate_const(EVP_CIPHER_settable_ctx_params(c.cipher) ,
                                    OSSL_CIPHER_PARAM_KEYLEN) = nil  then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH);
            Exit(0);
        end;
        params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, @len);
        ok := evp_do_ciph_ctx_setparams(c.cipher, c.algctx, @params);
        Exit(get_result(ok > 0 , 1 , 0));
    end;
    { Code below to be removed when legacy support is dropped. }
    {
     * Note there have never been any built-in ciphers that define this flag
     * since it was first introduced.
     }
    if c.cipher.flags and EVP_CIPH_CUSTOM_KEY_LENGTH > 0 then
       Exit(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_KEY_LENGTH, keylen, nil));
    if EVP_CIPHER_CTX_get_key_length(c) = keylen  then
        Exit(1);
    if (keylen > 0)  and  (c.cipher.flags and EVP_CIPH_VARIABLE_LENGTH > 0) then
    begin
        c.key_len := keylen;
        Exit(1);
    end;
    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH);
    Result := 0;
end;

function EVP_CIPHER_CTX_set_params(ctx : PEVP_CIPHER_CTX;const params : POSSL_PARAM):integer;
begin
    if (ctx.cipher <> nil)  and  (Assigned(ctx.cipher.set_ctx_params)) then
       Exit(ctx.cipher.set_ctx_params(ctx.algctx, params));
    Result := 0;
end;

function EVP_CIPHER_CTX_ctrl( ctx : PEVP_CIPHER_CTX; _type, arg : integer; ptr : Pointer):integer;
var
  ret,
  set_params : integer;
  sz         : size_t;
  i          : uint32;
  params     : array[0..3] of TOSSL_PARAM;
  p          : PEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;
  label _legacy, _NEXT1, _NEXT2, _end;
begin
    ret := EVP_CTRL_RET_UNSUPPORTED;
    set_params := 1;
    sz := arg;
    params[0] := OSSL_PARAM_END;
    params[1] := OSSL_PARAM_END;
    params[2] := OSSL_PARAM_END;
    params[3] := OSSL_PARAM_END;

    if (ctx = nil)  or  (ctx.cipher = nil) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        Exit(0);
    end;
    if ctx.cipher.prov = nil then goto _legacy;
    case _type of
        EVP_CTRL_SET_KEY_LENGTH:
            params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN, @sz);
            //break;
        EVP_CTRL_RAND_KEY:       { Used by DES }
        begin
            set_params := 0;
            params[0] := OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_RANDOM_KEY,
                                                  ptr, sz);
        end;
        EVP_CTRL_INIT:
            {
             * EVP_CTRL_INIT is purely legacy, no provider counterpart.
             * As a matter of fact, this should be dead code, but some caller
             * might still do a direct control call with this command, so...
             * Legacy methods return 1 except for exceptional circumstances, so
             * we do the same here to not be disruptive.
             }
            Exit(1);
        EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:  { Used by DASYNC }
        //else
            goto _end;
        EVP_CTRL_AEAD_SET_IVLEN:
        begin
            if arg < 0 then Exit(0);
            params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, @sz);
        end;
        EVP_CTRL_CCM_SET_L:
        begin
            if (arg < 2)  or  (arg > 8) then Exit(0);
            sz := 15 - arg;
            params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, @sz);
        end;
        EVP_CTRL_AEAD_SET_IV_FIXED:
            params[0] := OSSL_PARAM_construct_octet_string(
                            OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, ptr, sz);
            //break;
        EVP_CTRL_GCM_IV_GEN:
        begin
            set_params := 0;
            if arg < 0 then
               sz := 0; { special case that uses the iv length }
            params[0] := OSSL_PARAM_construct_octet_string(
                            OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, ptr, sz);
        end;
        EVP_CTRL_GCM_SET_IV_INV:
        begin
            if arg < 0 then Exit(0);
            params[0] := OSSL_PARAM_construct_octet_string(
                            OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, ptr, sz);
        end;
        EVP_CTRL_GET_RC5_ROUNDS:
        begin
            set_params := 0; { Fall thru }
            goto _NEXT1;
        end;
        EVP_CTRL_SET_RC5_ROUNDS:
        begin
    _NEXT1:
            if arg < 0 then Exit(0);
            i := uint32(arg);
            params[0] := OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_ROUNDS, @i);
        end;
        EVP_CTRL_SET_SPEED:
        begin
            if arg < 0 then Exit(0);
            i := uint32(arg);
            params[0] := OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_SPEED, @i);
        end;
        EVP_CTRL_AEAD_GET_TAG:
        begin
            set_params := 0; { Fall thru }
            goto _NEXT2;
        end;
        EVP_CTRL_AEAD_SET_TAG:
    _NEXT2:
            params[0] := OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                          ptr, sz);
            //break;
        EVP_CTRL_AEAD_TLS1_AAD:
        begin
            { This one does a set and a get - since it returns a size }
            params[0] := OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
                                                  ptr, sz);
            ret := evp_do_ciph_ctx_setparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then goto _end;
            params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, @sz);
            ret := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then goto _end;
            Exit(sz);
        end;
    {$IFNDEF OPENSSL_NO_RC2}
        EVP_CTRL_GET_RC2_KEY_BITS:
            set_params := 0; { Fall thru }
        EVP_CTRL_SET_RC2_KEY_BITS:
            params[0] := OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_RC2_KEYBITS, @sz);
            //break;

    {$endif} { OPENSSL_NO_RC2 }
    {$IF not defined(OPENSSL_NO_MULTIBLOCK)}
        EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE:
        begin
            params[0] := OSSL_PARAM_construct_size_t(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, @sz);
            ret := evp_do_ciph_ctx_setparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then Exit(0);
            params[0] := OSSL_PARAM_construct_size_t(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE, @sz);
            params[1] := OSSL_PARAM_construct_end;
            ret := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then Exit(0);
            Exit(sz);
        end;
        EVP_CTRL_TLS1_1_MULTIBLOCK_AAD:
        begin
            p := PEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM (ptr);
            if arg < int(sizeof(EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM)) then
                Exit(0);
            params[0] := OSSL_PARAM_construct_octet_string(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD, Pointer(p.inp), p.len);
            params[1] := OSSL_PARAM_construct_uint(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, @p.interleave);
            ret := evp_do_ciph_ctx_setparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then Exit(ret);
            { Retrieve the return values changed by the set }
            params[0] := OSSL_PARAM_construct_size_t(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, @sz);
            params[1] := OSSL_PARAM_construct_uint(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, @p.interleave);
            params[2] := OSSL_PARAM_construct_end;
            ret := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then Exit(0);
            Exit(sz);
        end;
        EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT:
        begin
            p := PEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM(ptr);
            params[0] := OSSL_PARAM_construct_octet_string(
                            OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC, p.out, p.len);
            params[1] := OSSL_PARAM_construct_octet_string(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN, Pointer(p.inp),
                    p.len);
            params[2] := OSSL_PARAM_construct_uint(
                    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, @p.interleave);
            ret := evp_do_ciph_ctx_setparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then Exit(ret);
            params[0] := OSSL_PARAM_construct_size_t(
                            OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, @sz);
            params[1] := OSSL_PARAM_construct_end;
            ret := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
            if ret <= 0 then Exit(0);
            Exit(sz);
        end;
    {$endif} { OPENSSL_NO_MULTIBLOCK }
        EVP_CTRL_AEAD_SET_MAC_KEY:
        begin
            if arg < 0 then Exit(-1);
            params[0] := OSSL_PARAM_construct_octet_string(
                    OSSL_CIPHER_PARAM_AEAD_MAC_KEY, ptr, sz);
        end;
        else
            goto _end;
    end;

    if set_params > 0 then
       ret := evp_do_ciph_ctx_setparams(ctx.cipher, ctx.algctx, @params)
    else
        ret := evp_do_ciph_ctx_getparams(ctx.cipher, ctx.algctx, @params);
    goto _end;
    { Code below to be removed when legacy support is dropped. }
_legacy:
    if not Assigned(ctx.cipher.ctrl) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_CTRL_NOT_IMPLEMENTED);
        Exit(0);
    end;
    ret := ctx.cipher.ctrl(ctx, _type, arg, ptr);
 _end:
    if ret = EVP_CTRL_RET_UNSUPPORTED then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        Exit(0);
    end;
    Result := ret;
end;



function EVP_CIPHER_CTX_set_padding( ctx : PEVP_CIPHER_CTX; pad : integer):integer;
var
  ok : integer;
  params : array[0..1] of TOSSL_PARAM;
  pd : uint32;
begin
    params[0] := OSSL_PARAM_END;
    params[0] := OSSL_PARAM_END;
    pd := pad;
    if pad > 0 then
       ctx.flags := ctx.flags and not EVP_CIPH_NO_PADDING
    else
        ctx.flags  := ctx.flags  or EVP_CIPH_NO_PADDING;
    if (ctx.cipher <> nil)  and  (ctx.cipher.prov = nil) then
       Exit(1);
    params[0] := OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_PADDING, @pd);
    ok := evp_do_ciph_ctx_setparams(ctx.cipher, ctx.algctx, @params);
    Result := Int(ok <> 0);
end;

function EVP_CIPHER_CTX_reset( ctx : PEVP_CIPHER_CTX):integer;
label _legacy;
begin
    if ctx = nil then Exit(1);
    if (ctx.cipher = nil)  or  (ctx.cipher.prov = nil) then
       goto _legacy;
    if ctx.algctx <> nil then
    begin
        if Assigned(ctx.cipher.freectx) then
            ctx.cipher.freectx(ctx.algctx);
        ctx.algctx := nil;
    end;
    if ctx.fetched_cipher <> nil then
       EVP_CIPHER_free(ctx.fetched_cipher);
    //memset(ctx, 0, sizeof( ctx^));
    ctx^ := default(TEVP_CIPHER_CTX);
    Exit(1);
    { Remove legacy code below when legacy support is removed. }
 _legacy:
    if ctx.cipher <> nil then
    begin
        if (Assigned(ctx.cipher.cleanup)) and  (0>=ctx.cipher.cleanup(ctx)) then
            Exit(0);
        { Cleanse cipher context data }
        if (ctx.cipher_data <> nil) and  (ctx.cipher.ctx_size > 0) then
           OPENSSL_cleanse(ctx.cipher_data, ctx.cipher.ctx_size);
    end;
    OPENSSL_free(ctx.cipher_data);
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    ENGINE_finish(ctx.engine);
{$ENDIF}
    memset(ctx, 0, sizeof( ctx^));
    Result := 1;
end;




function evp_EncryptDecryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;{const} _in : PByte; inl : integer):integer;
var
  i, j, bl, cmpl : integer;
begin
    cmpl := inl;
    if EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) > 0 then
        cmpl := (cmpl + 7) div 8;
    bl := ctx.cipher.block_size;
    if ctx.cipher.flags and EVP_CIPH_FLAG_CUSTOM_CIPHER > 0 then
    begin
        { If block size > 1 then the cipher will have to do this check }
        if (bl = 1)  and  (ossl_is_partially_overlapping(_out, _in, cmpl) > 0) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING);
            Exit(0);
        end;
        i := ctx.cipher.do_cipher(ctx, _out, _in, inl);
        if i < 0 then
           Exit(0)
        else
           outl^ := i;
        Exit(1);
    end;
    if inl <= 0 then begin
        outl^ := 0;
        Exit(Int(inl = 0));
    end;
    if ossl_is_partially_overlapping(_out + ctx.buf_len, _in, cmpl) > 0 then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING);
        Exit(0);
    end;
    if (ctx.buf_len = 0)  and  (inl and ctx.block_mask  = 0)  then
    begin
        if ctx.cipher.do_cipher(ctx, _out, _in, inl) > 0 then
        begin
            outl^ := inl;
            Exit(1);
        end
        else begin
            outl^ := 0;
            Exit(0);
        end;
    end;
    i := ctx.buf_len;
    assert(bl <= int(sizeof(ctx.buf)));
    if i <> 0 then begin
        if bl - i > inl then  begin
            memcpy(@(ctx.buf[i]), _in, inl);
            ctx.buf_len  := ctx.buf_len + inl;
            outl^ := 0;
            Exit(1);
        end
        else
        begin
            j := bl - i;
            {
             * Once we've processed the first j bytes from in, the amount of
             * data left that is a multiple of the block length is:
             * (inl - j) and ~(bl - 1)
             * We must ensure that this amount of data, plus the one block that
             * we process from ctx.buf does not exceed INT_MAX
             }
            if (inl - j)and (not (bl - 1)) > INT_MAX - bl then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_OUTPUT_WOULD_OVERFLOW);
                Exit(0);
            end;
            memcpy(@(ctx.buf[i]), _in, j);
            inl  := inl - j;
            _in  := _in + j;
            if 0>=ctx.cipher.do_cipher(ctx, _out, @ctx.buf, bl) then
                Exit(0);
            _out  := _out + bl;
            outl^ := bl;
        end;
    end
    else
        outl^ := 0;
    i := inl and (bl - 1);
    inl  := inl - i;
    if inl > 0 then begin
        if 0>=ctx.cipher.do_cipher(ctx, _out, _in, inl) then
            Exit(0);
        outl^  := outl^ + inl;
    end;
    if i <> 0 then
       memcpy(@ctx.buf, @(_in[inl]), i);
    ctx.buf_len := i;
    Result := 1;
end;

function ossl_is_partially_overlapping(const ptr1, ptr2 : Pointer; len : integer):integer;
var
    diff       : PTRDIFF_T;

    overlapped : integer;
begin
    diff := PTRDIFF_T(ptr1)- PTRDIFF_T(ptr2);
    {
     * Check for partially overlapping buffers. [Binary logical
     * operations are used instead of boolean to minimize number
     * of conditional branches.]
     }
    overlapped := int(len > 0) and int(diff <> 0) and
               ( Int(diff < PTRDIFF_T(len)) or
                 Int(diff > 0 - PTRDIFF_T(len)) );
    Result := overlapped;
end;


function EVP_DecryptFinal_ex( ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger):integer;
var
  i,
  n         : integer;
  b         : uint32;
  soutl     : size_t;
  ret,
  blocksize : integer;
  label _legacy;
begin
    if outl <> nil then
    begin
       outl^ := 0;
    end
    else
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { Prevent accidental use of encryption context when decrypting }
    if ctx.encrypt > 0 then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
        Exit(0);
    end;
    if ctx.cipher = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        Exit(0);
    end;
    if ctx.cipher.prov = nil then goto _legacy ;
    blocksize := EVP_CIPHER_CTX_get_block_size(ctx);
    if (blocksize < 1)  or  (not Assigned(ctx.cipher.cfinal)) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
        Exit(0);
    end;
    ret := ctx.cipher.cfinal(ctx.algctx, _out, @soutl,
                             get_result(blocksize = 1 , 0 , blocksize));
    if ret > 0 then begin
        if soutl > INT_MAX then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
            Exit(0);
        end;
        outl^ := soutl;
    end;
    Exit(ret);
    { Code below to be removed when legacy support is dropped. }
 _legacy:
    outl^ := 0;
    if ctx.cipher.flags and EVP_CIPH_FLAG_CUSTOM_CIPHER > 0 then
    begin
        i := ctx.cipher.do_cipher(ctx, _out, nil, 0);
        if i < 0 then
           Exit(0)
        else
           outl^ := i;
        Exit(1);
    end;
    b := ctx.cipher.block_size;
    if ctx.flags and EVP_CIPH_NO_PADDING > 0 then begin
        if ctx.buf_len > 0 then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            Exit(0);
        end;
        outl^ := 0;
        Exit(1);
    end;
    if b > 1 then
    begin
        if (ctx.buf_len > 0) or  (0>= ctx.final_used) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_WRONG_FINAL_BLOCK_LENGTH);
            Exit(0);
        end;
        assert(b <= sizeof(ctx.final));
        {
         * The following assumes that the ciphertext has been authenticated.
         * Otherwise it provides a padding oracle.
         }
        n := ctx.final[b - 1];
        if (n = 0)  or  (n > int (b)) then begin
            ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
            Exit(0);
        end;
        for i := 0 to n-1 do
        begin
            Dec(b);
            if ctx.final[b] <> n  then  begin
                ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
                Exit(0);
            end;
        end;
        n := ctx.cipher.block_size - n;
        for i := 0 to n-1 do
            _out[i] := ctx.final[i];
        outl^ := n;
    end
    else
        outl^ := 0;
    Result := 1;
end;

function EVP_DecryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer;
var
  fix_len,
  cmpl, ret      : integer;
  b         : uint32;
  soutl     : size_t;
  blocksize : integer;
  label _legacy;
begin
    cmpl := inl;
    if outl <> nil then
    begin
        outl^ := 0;
    end
    else
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { Prevent accidental use of encryption context when decrypting }
    if ctx.encrypt > 0 then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
        Exit(0);
    end;
    if ctx.cipher = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        Exit(0);
    end;
    if ctx.cipher.prov = nil then goto _legacy ;
    blocksize := EVP_CIPHER_CTX_get_block_size(ctx);
    if (not Assigned(ctx.cipher.cupdate))  or  (blocksize < 1) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR);
        Exit(0);
    end;
    ret := ctx.cipher.cupdate(ctx.algctx, _out, @soutl,
                               inl + get_result(blocksize = 1 , 0 , blocksize), _in,
                               size_t( inl));
    if ret > 0 then begin
        if soutl > INT_MAX then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR);
            Exit(0);
        end;
        outl^ := soutl;
    end;
    Exit(ret);
    { Code below to be removed when legacy support is dropped. }
 _legacy:
    b := ctx.cipher.block_size;
    if EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) > 0 then
        cmpl := (cmpl + 7) div 8;
    if ctx.cipher.flags and EVP_CIPH_FLAG_CUSTOM_CIPHER > 0 then
    begin
        if (b = 1)  and  (ossl_is_partially_overlapping(_out, _in, cmpl) > 0) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING);
            Exit(0);
        end;
        fix_len := ctx.cipher.do_cipher(ctx, _out, _in, inl);
        if fix_len < 0 then begin
            outl^ := 0;
            Exit(0);
        end
        else
            outl^ := fix_len;
        Exit(1);
    end;
    if inl <= 0 then begin
        outl^ := 0;
        Exit(int(inl = 0));
    end;
    if ctx.flags and EVP_CIPH_NO_PADDING > 0 then
       Exit(evp_EncryptDecryptUpdate(ctx, _out, outl, _in, inl));
    assert(b <= sizeof(ctx.final));
    if ctx.final_used > 0 then begin
        { see comment about PTRDIFF_T comparison above }
        if (PTRDIFF_T(_out) = PTRDIFF_T(_in))
             or  (ossl_is_partially_overlapping(_out, _in, b) > 0)  then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_PARTIALLY_OVERLAPPING);
            Exit(0);
        end;
        {
         * final_used is only ever set if buf_len is 0. Therefore the maximum
         * length output we will ever see from evp_EncryptDecryptUpdate is
         * the maximum multiple of the block length that is <= inl, or just:
         * inl and ~(b - 1)
         * Since final_used has been set then the final output length is:
         * (inl and ~(b - 1)) + b
         * This must never exceed INT_MAX
         }
        if inl and (not(b - 1)) > INT_MAX - b then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_OUTPUT_WOULD_OVERFLOW);
            Exit(0);
        end;
        memcpy(_out, @ctx.final, b);
        _out  := _out + b;
        fix_len := 1;
    end
    else
        fix_len := 0;
    if 0>= evp_EncryptDecryptUpdate(ctx, _out, outl, _in, inl) then
        Exit(0);
    {
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     }
    if (b > 1)  and  (0>= ctx.buf_len) then begin
        outl^  := outl^ - b;
        ctx.final_used := 1;
        memcpy(@ctx.final, @_out[outl^], b);
    end
    else
        ctx.final_used := 0;
    if fix_len > 0 then
       outl^  := outl^ + b;
    Result := 1;
end;

function EVP_DecryptInit_ex(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte):integer;
begin
    Result := EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 0);
end;

procedure EVP_CIPHER_CTX_free( ctx : PEVP_CIPHER_CTX);
begin
    if ctx = nil then
       exit;
    EVP_CIPHER_CTX_reset(ctx);
    ctx := nil;
    FreeMem(ctx);
end;

function EVP_EncryptFinal_ex( ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger):integer;
var
  n, ret    : integer;
  i, b, bl  : uint32;
  soutl     : size_t;
  blocksize : integer;
  label _legacy;
begin
    if outl <> nil then
    begin
        outl^ := 0;
    end
    else
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { Prevent accidental use of decryption context when encrypting }
    if 0>= ctx.encrypt then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
        Exit(0);
    end;
    if ctx.cipher = nil then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        Exit(0);
    end;
    if ctx.cipher.prov = nil then goto _legacy ;
    blocksize := EVP_CIPHER_CTX_get_block_size(ctx);
    if (blocksize < 1)  or  (not Assigned(ctx.cipher.cfinal)) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
        Exit(0);
    end;
    ret := ctx.cipher.cfinal(ctx.algctx, _out, @soutl,
                             get_result(blocksize = 1 , 0 , blocksize));
    if ret > 0 then begin
        if soutl > INT_MAX then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
            Exit(0);
        end;
        outl^ := soutl;
    end;
    Exit(ret);
    { Code below to be removed when legacy support is dropped. }
 _legacy:
    if ctx.cipher.flags and EVP_CIPH_FLAG_CUSTOM_CIPHER > 0 then begin
        ret := ctx.cipher.do_cipher(ctx, _out, nil, 0);
        if ret < 0 then
           Exit(0)
        else
           outl^ := ret;
        Exit(1);
    end;
    b := ctx.cipher.block_size;
    assert(b <= sizeof(ctx.buf));
    if b = 1 then begin
        outl^ := 0;
        Exit(1);
    end;
    bl := ctx.buf_len;
    if ctx.flags and EVP_CIPH_NO_PADDING > 0 then begin
        if bl > 0 then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            Exit(0);
        end;
        outl^ := 0;
        Exit(1);
    end;
    n := b - bl;
    for i := bl to b-1 do
        ctx.buf[i] := n;
    ret := ctx.cipher.do_cipher(ctx, _out, @ctx.buf, b);
    if ret > 0 then
       outl^ := b;
    Result := ret;
end;

function EVP_EncryptUpdate(ctx : PEVP_CIPHER_CTX; _out : PByte; outl : PInteger;const _in : PByte; inl : integer):integer;
var
    ret       : integer;
    soutl     : size_t;
    blocksize : integer;
    label _legacy;
begin
    if outl <> nil then
    begin
        outl^ := 0;
    end
    else
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    { Prevent accidental use of decryption context when encrypting }
    if 0>= ctx.encrypt then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION);
        Exit(0);
    end;
    if ctx.cipher = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        Exit(0);
    end;
    if ctx.cipher.prov = nil then
       goto _legacy ;
    blocksize := ctx.cipher.block_size;
    if (not Assigned(ctx.cipher.cupdate))   or  (blocksize < 1) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR);
        Exit(0);
    end;
    ret := ctx.cipher.cupdate(ctx.algctx, _out, @soutl,
                               inl + get_result(blocksize = 1 , 0 , blocksize), _in,
                               size_t( inl));
    if ret > 0 then
    begin
        if soutl > INT_MAX then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR);
            Exit(0);
        end;
        outl^ := soutl;
    end;
    Exit(ret);
    { Code below to be removed when legacy support is dropped. }
 _legacy:
    Result := evp_EncryptDecryptUpdate(ctx, _out, outl, _in, inl);
end;


function evp_cipher_init_internal(ctx : PEVP_CIPHER_CTX;{const} cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte; enc : integer;const params : POSSL_PARAM):integer;
var
    n        : integer;
    tmpimpl  : PENGINE;
    flags    : Cardinal;
    provciph : PEVP_CIPHER;
    c        : PEVP_CIPHER;
    p        : Pointer;
    sn       : PUTF8Char;
    label _legacy, _skip_to_init, _NEXT;
begin
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    tmpimpl := nil;
{$ENDIF}
    {
     * enc = 1 means we are encrypting.
     * enc = 0 means we are decrypting.
     * enc = -1 means, use the previously initialised value for encrypt/decrypt
     }
    if enc = -1 then
    begin
        enc := ctx.encrypt;
    end
    else
    begin
        if enc > 0 then enc := 1;
        ctx.encrypt := enc;
    end;
    if (cipher = nil)  and  (ctx.cipher = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET);
        Exit(0);
    end;
    { Code below to be removed when legacy support is dropped. }
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
    {
     * Whether it's nice or not, 'Inits" can be used on "Final''d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unnecessary.
     }
    if (ctx.engine <> nil)  and  (ctx.cipher <> nil)
         and ( (cipher = nil)  or  (cipher.nid = ctx.cipher.nid) ) then
        goto _skip_to_init ;
    if (cipher <> nil)  and  (impl = nil) then
    begin
         { Ask if an ENGINE is reserved for this job }
        tmpimpl := ENGINE_get_cipher_engine(cipher.nid);
    end;
{$ENDIF}
    {
     * If there are engines involved then we should use legacy handling for now.
     }
    if (ctx.engine <> nil)
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
             or  (tmpimpl <> nil)
{$ENDIF}
             or  (impl <> nil) then
    begin
        if ctx.cipher = ctx.fetched_cipher then
            ctx.cipher := nil;
        EVP_CIPHER_free(ctx.fetched_cipher);
        ctx.fetched_cipher := nil;
        goto _legacy ;
    end;
    {
     * Ensure a context left lying around from last time is cleared
     * (legacy code)
     }
    if (cipher <> nil)  and  (ctx.cipher <> nil) then begin
        OPENSSL_clear_free(ctx.cipher_data, ctx.cipher.ctx_size);
        ctx.cipher_data := nil;
    end;
    { Start of non-legacy code below }
    { Ensure a context left lying around from last time is cleared }
    if (cipher <> nil)  and  (ctx.cipher <> nil) then
    begin
        flags := ctx.flags;
        EVP_CIPHER_CTX_reset(ctx);
        { Restore encrypt and flags }
        ctx.encrypt := enc;
        ctx.flags := flags;
    end;
    if cipher = nil then cipher := ctx.cipher;
    if cipher.prov = nil then
    begin
{$IFDEF FIPS_MODULE}
        { We only do explicit fetches inside the FIPS module }
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
{$ELSE}
        sn := OBJ_nid2sn(cipher.nid);
        sn := get_result(cipher.nid = NID_undef , 'NULL' , sn);
        provciph := EVP_CIPHER_fetch(nil, sn, '');
        if provciph = nil then Exit(0);
        cipher := provciph;
        EVP_CIPHER_free(ctx.fetched_cipher);
        ctx.fetched_cipher := provciph;
{$ENDIF}
    end;
    if cipher.prov <> nil then
    begin
        if 0>= EVP_CIPHER_up_ref(cipher) then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
        EVP_CIPHER_free(ctx.fetched_cipher);
        ctx.fetched_cipher := PEVP_CIPHER  (cipher);
    end;
    ctx.cipher := cipher;
    if ctx.algctx = nil then
    begin
        p := ossl_provider_ctx(cipher.prov);
        ctx.algctx := ctx.cipher.newctx(p);
        if ctx.algctx = nil then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
    end;
    if ctx.flags and EVP_CIPH_NO_PADDING  <> 0 then  begin
        {
         * If this ctx was already set up for no padding then we need to tell
         * the new cipher about it.
         }
        if 0>= EVP_CIPHER_CTX_set_padding(ctx, 0) then
            Exit(0);
    end;
    if enc > 0 then
    begin
        if not Assigned(ctx.cipher.einit) then  begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
        Exit(ctx.cipher.einit(ctx.algctx,  key,
                get_result(key = nil , 0, EVP_CIPHER_CTX_get_key_length(ctx)), iv,
                get_result(iv = nil , 0, EVP_CIPHER_CTX_get_iv_length(ctx)), params));
    end;
    if not Assigned(ctx.cipher.dinit) then begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
        Exit(0);
    end;
    Exit(ctx.cipher.dinit(ctx.algctx, key,
          get_result(key = nil , 0, EVP_CIPHER_CTX_get_key_length(ctx)), iv,
          get_result(iv = nil , 0, EVP_CIPHER_CTX_get_iv_length(ctx)), params));
    { Code below to be removed when legacy support is dropped. }
 _legacy:
    if cipher <> nil then begin
        {
         * Ensure a context left lying around from last time is cleared (we
         * previously attempted to avoid this if the same ENGINE and
         * EVP_CIPHER could be used).
         }
        if ctx.cipher <> nil then
        begin
            flags := ctx.flags;
            EVP_CIPHER_CTX_reset(ctx);
            { Restore encrypt and flags }
            ctx.encrypt := enc;
            ctx.flags := flags;
        end;
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
        if impl <> nil then
        begin
            if 0>= ENGINE_init(impl) then  begin
                ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
                Exit(0);
            end;
        end
        else
        begin
            impl := tmpimpl;
        end;
        if impl <> nil then
        begin
            { There's an ENGINE for this job ... (apparently) }
            c := ENGINE_get_cipher(impl, cipher.nid);
            if c = nil then begin
                {
                 * One positive side-effect of US's export control history,
                 * is that we should at least be able to avoid using US
                 * misspellings of 'initialisation'?
                 }
                ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
                Exit(0);
            end;
            { We'll use the ENGINE's private cipher definition }
            cipher := c;
            {
             * Store the ENGINE functional reference so we know 'cipher' came
             * from an ENGINE and we need to release it when done.
             }
            ctx.engine := impl;
        end
        else
        begin
            ctx.engine := nil;
        end;
{$ENDIF}
        ctx.cipher := cipher;
        if ctx.cipher.ctx_size > 0 then begin
            ctx.cipher_data := OPENSSL_zalloc(ctx.cipher.ctx_size);
            if ctx.cipher_data = nil then begin
                ctx.cipher := nil;
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
        end
        else begin
            ctx.cipher_data := nil;
        end;
        ctx.key_len := cipher.key_len;
        { Preserve wrap enable flag, zero everything else }
        ctx.flags := ctx.flags and  EVP_CIPHER_CTX_FLAG_WRAP_ALLOW;
        if ctx.cipher.flags and EVP_CIPH_CTRL_INIT > 0 then begin
            if 0>= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, nil) then  begin
                ctx.cipher := nil;
                ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
                Exit(0);
            end;
        end;
    end;
{$IF not defined(OPENSSL_NO_ENGINE)  and  not defined(FIPS_MODULE)}
 _skip_to_init:
{$ENDIF}
    if ctx.cipher = nil then Exit(0);
    { we assume block size is a power of 2 in *cryptUpdate }
    assert( (ctx.cipher.block_size = 1)
                    or  (ctx.cipher.block_size = 8)
                    or  (ctx.cipher.block_size = 16) );
    if (0>= (ctx.flags and EVP_CIPHER_CTX_FLAG_WRAP_ALLOW))  and
       (EVP_CIPHER_CTX_get_mode(ctx) = EVP_CIPH_WRAP_MODE)  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_WRAP_MODE_NOT_ALLOWED);
        Exit(0);
    end;
    if EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(ctx)) and EVP_CIPH_CUSTOM_IV = 0 then
    begin
        case (EVP_CIPHER_CTX_get_mode(ctx)) of
            EVP_CIPH_STREAM_CIPHER,
            EVP_CIPH_ECB_MODE:
            begin
               //break;
            end;
            EVP_CIPH_CFB_MODE,
            EVP_CIPH_OFB_MODE:
            begin
                ctx.num := 0;
                { fall-through }
                goto _NEXT;
            end;
            EVP_CIPH_CBC_MODE:
            begin
_NEXT:
                n := EVP_CIPHER_CTX_get_iv_length(ctx);
                if not ossl_assert( (n >= 0)  and  (n <= int(sizeof(ctx.iv))) ) then
                        Exit(0);
                if iv <> nil then
                   memcpy(@ctx.oiv, iv, n);
                memcpy(@ctx.iv, @ctx.oiv, n);
            end;
            EVP_CIPH_CTR_MODE:
            begin
                ctx.num := 0;
                { Don't reuse IV for CTR mode }
                if iv <> nil then
                begin
                    n := EVP_CIPHER_CTX_get_iv_length(ctx);
                    if n <= 0 then
                        Exit(0);
                    memcpy(@ctx.iv, iv, n);
                end;
            end;
            else
                Exit(0);
        end;
    end;
    if (key <> nil)  or  (ctx.cipher.flags and EVP_CIPH_ALWAYS_CALL_INIT > 0 ) then
    begin
        if 0>= ctx.cipher.init(ctx, key, iv, enc) then
            Exit(0);
    end;
    ctx.buf_len := 0;
    ctx.final_used := 0;
    ctx.block_mask := ctx.cipher.block_size - 1;
    Result := 1;
end;



function EVP_CipherInit_ex(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte; enc : integer):integer;
begin
    Result := evp_cipher_init_internal(ctx, cipher, impl, key, iv, enc, nil);
end;



function EVP_EncryptInit_ex(ctx : PEVP_CIPHER_CTX;const cipher : PEVP_CIPHER; impl : PENGINE;const key, iv : PByte):integer;
begin
    Result := EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 1);
end;

function EVP_CIPHER_CTX_new:PEVP_CIPHER_CTX;
begin
    Result := OPENSSL_zalloc(sizeof(TEVP_CIPHER_CTX));
end;




function EVP_CIPHER_CTX_get_params( ctx : PEVP_CIPHER_CTX; params : POSSL_PARAM):integer;
begin
    if (ctx.cipher <> nil)  and  Assigned(ctx.cipher.get_ctx_params) then
       Exit(ctx.cipher.get_ctx_params(ctx.algctx, params));
    Result := 0;
end;


function EVP_CIPHER_gettable_ctx_params(const cipher : PEVP_CIPHER):POSSL_PARAM;
var
  provctx : Pointer;
begin
    if (cipher <> nil)  and  (Assigned(cipher.gettable_ctx_params)) then
    begin
        provctx := ossl_provider_ctx(EVP_CIPHER_get0_provider(cipher));
        Result := cipher.gettable_ctx_params(nil, provctx);
        Exit(Result);
    end;
    Result := nil;
end;


procedure evp_cipher_free_int( cipher : PEVP_CIPHER);
begin
    OPENSSL_free(cipher.type_name);
    ossl_provider_free(cipher.prov);
    CRYPTO_THREAD_lock_free(cipher.lock);
    OPENSSL_free(cipher);
end;



procedure EVP_CIPHER_free( cipher : Pointer);
var
  i : integer;
begin
    if (cipher = nil)  or  (PEVP_CIPHER(cipher).origin <> EVP_ORIG_DYNAMIC) then exit;
    CRYPTO_DOWN_REF(PEVP_CIPHER(cipher).refcnt, i, PEVP_CIPHER(cipher).lock);
    if i > 0 then exit;
    evp_cipher_free_int(PEVP_CIPHER(cipher));
end;





procedure set_legacy_nid(const name : PUTF8Char; vlegacy_nid : Pointer);
var
    nid           : integer;

    legacy_nid    : PInteger;

    legacy_method : Pointer;
begin
    legacy_nid := vlegacy_nid;
    {
     * We use lowest level function to get the associated method, because
     * higher level functions such as EVP_get_cipherbyname() have changed
     * to look at providers too.
     }
    legacy_method := OBJ_NAME_get((name), OBJ_NAME_TYPE_CIPHER_METH);
    if (legacy_nid^ = -1 )then { We found a clash already }
        exit;
    if legacy_method = nil then exit;
    nid := EVP_CIPHER_get_nid(legacy_method);
    if (legacy_nid^ <> NID_undef)  and  (legacy_nid^ <> nid) then
    begin
        legacy_nid^ := -1;
        exit;
    end;
    legacy_nid^ := nid;
end;



function evp_cipher_new:PEVP_CIPHER;
var
  cipher : PEVP_CIPHER;
begin
    cipher := OPENSSL_zalloc(sizeof(TEVP_CIPHER));
    if cipher <> nil then
    begin
        cipher.lock := CRYPTO_THREAD_lock_new();
        if cipher.lock = nil then
        begin
            OPENSSL_free(cipher);
            Exit(nil);
        end;
        cipher.refcnt := 1;
    end;
    Result := cipher;
end;

function evp_cipher_from_algorithm({const} name_id : integer; const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
    fns       : POSSL_DISPATCH;
    cipher    : PEVP_CIPHER;
    fnciphcnt,fnctxcnt : integer;
begin
    fns := algodef._implementation;
    if fns.function_id = 0 then
       Exit(nil);
    cipher := nil;
    fnciphcnt := 0; fnctxcnt := 0;
    cipher := evp_cipher_new( );
    if cipher =  nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
{$IFNDEF FIPS_MODULE}
    cipher.nid := NID_undef;
    if  (0>= evp_names_do_all(prov, name_id, set_legacy_nid, @cipher.nid ))  or
        (cipher.nid = -1) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        EVP_CIPHER_free(cipher);
        Exit(nil);
    end;
{$ENDIF}
    cipher.name_id := name_id;
    cipher.type_name := ossl_algorithm_get1_first_name(algodef );
    if cipher.type_name  = nil then
    begin
        EVP_CIPHER_free(cipher);
        Exit(nil);
    end;
    cipher.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
        case fns.function_id of
        OSSL_FUNC_CIPHER_NEWCTX:
        begin
            if Assigned(cipher.newctx) then break;
            cipher.newctx := _OSSL_FUNC_cipher_newctx(fns);
            Inc(fnctxcnt);
        end;
        OSSL_FUNC_CIPHER_ENCRYPT_INIT:
        begin
            if Assigned(cipher.einit) then break;
            cipher.einit := _OSSL_FUNC_cipher_encrypt_init(fns);
            Inc(fnciphcnt);
        end;
        OSSL_FUNC_CIPHER_DECRYPT_INIT:
        begin
            if Assigned(cipher.dinit ) then break;
            cipher.dinit := _OSSL_FUNC_cipher_decrypt_init(fns);
            Inc(fnciphcnt);
        end;
        OSSL_FUNC_CIPHER_UPDATE:
        begin
            if Assigned(cipher.cupdate ) then break;
            cipher.cupdate := _OSSL_FUNC_cipher_update(fns);
            Inc(fnciphcnt);
        end;
        OSSL_FUNC_CIPHER_FINAL:
        begin
            if Assigned(cipher.cfinal ) then break;
            cipher.cfinal := _OSSL_FUNC_cipher_final(fns);
            PostInc(fnciphcnt);
        end;
        OSSL_FUNC_CIPHER_CIPHER:
        begin
            if Assigned(cipher.ccipher ) then break;
            cipher.ccipher := _OSSL_FUNC_cipher_cipher(fns);
        end;
        OSSL_FUNC_CIPHER_FREECTX:
        begin
            if Assigned(cipher.freectx ) then break;
            cipher.freectx := _OSSL_FUNC_cipher_freectx(fns);
            Inc(fnctxcnt);
        end;
        OSSL_FUNC_CIPHER_DUPCTX:
        begin
            if Assigned(cipher.dupctx ) then break;
            cipher.dupctx := _OSSL_FUNC_cipher_dupctx(fns);
        end;
        OSSL_FUNC_CIPHER_GET_PARAMS:
        begin
            if Assigned(cipher.get_params ) then break;
            cipher.get_params := _OSSL_FUNC_cipher_get_params(fns);
        end;
        OSSL_FUNC_CIPHER_GET_CTX_PARAMS:
        begin
            if Assigned(cipher.get_ctx_params ) then break;
            cipher.get_ctx_params := _OSSL_FUNC_cipher_get_ctx_params(fns);
        end;
        OSSL_FUNC_CIPHER_SET_CTX_PARAMS:
        begin
            if Assigned(cipher.set_ctx_params ) then break;
            cipher.set_ctx_params := _OSSL_FUNC_cipher_set_ctx_params(fns);
        end;
        OSSL_FUNC_CIPHER_GETTABLE_PARAMS:
        begin
            if Assigned(cipher.gettable_params ) then break;
            cipher.gettable_params := _OSSL_FUNC_cipher_gettable_params(fns);
        end;
        OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS:
        begin
            if Assigned(cipher.gettable_ctx_params ) then break;
            cipher.gettable_ctx_params := _OSSL_FUNC_cipher_gettable_ctx_params(fns);
        end;
        OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS:
        begin
            if Assigned(cipher.settable_ctx_params ) then break;
            cipher.settable_ctx_params := _OSSL_FUNC_cipher_settable_ctx_params(fns);
        end;
        end;
         Inc(fns);
    end;
    if (not fnciphcnt  in [0,3,5])  or
       ( (fnciphcnt = 0)  and  (not Assigned(cipher.ccipher)) )
             or  (fnctxcnt <> 2)  then
    begin
        {
         * In order to be a consistent set of functions we must have at least
         * a complete set of 'encrypt" functions, or a complete set of "decrypt'
         * functions, or a single 'cipher' function. In all cases we need both
         * the 'newctx" and "freectx' functions.
         }
        EVP_CIPHER_free(cipher);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    cipher.prov := prov;
    if prov <> nil then ossl_provider_up_ref(prov);
    if  0>= evp_cipher_cache_constants(cipher)   then
    begin
        EVP_CIPHER_free(cipher);
        ERR_raise(ERR_LIB_EVP, EVP_R_CACHE_CONSTANTS_FAILED);
        cipher := nil;
    end;
    Result := cipher;
end;

function EVP_CIPHER_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_CIPHER;
begin
   Result := evp_generic_fetch(ctx, OSSL_OP_CIPHER, algorithm, properties,
                                evp_cipher_from_algorithm, _evp_cipher_up_ref,
                                evp_cipher_free);

end;

end.
