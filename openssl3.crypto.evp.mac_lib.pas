unit openssl3.crypto.evp.mac_lib;

interface
uses OpenSSL.Api;

function EVP_Q_mac(libctx : POSSL_LIB_CTX;const name, propq, subalg : PUTF8Char; params : POSSL_PARAM; key : Pointer; keylen : size_t;const data : PByte; datalen : size_t; &out : PByte; outsize : size_t; outlen : Psize_t):PByte;


function EVP_MAC_CTX_new( mac : PEVP_MAC):PEVP_MAC_CTX;
function EVP_MAC_CTX_set_params(ctx : PEVP_MAC_CTX;const params : POSSL_PARAM):integer;
function EVP_MAC_init(ctx : PEVP_MAC_CTX;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
function EVP_MAC_update(ctx : PEVP_MAC_CTX;const data : PByte; datalen : size_t):integer;
function EVP_MAC_final( ctx : PEVP_MAC_CTX; &out : PByte; outl : Psize_t; outsize : size_t):integer;
function _evp_mac_final( ctx : PEVP_MAC_CTX; xof : integer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
function EVP_MAC_CTX_get_mac_size( ctx : PEVP_MAC_CTX):size_t;
function get_size_t_ctx_param(ctx : PEVP_MAC_CTX;const name : PUTF8Char):size_t;
procedure EVP_MAC_CTX_free( ctx : PEVP_MAC_CTX);
function EVP_MAC_CTX_get0_mac( ctx : PEVP_MAC_CTX):PEVP_MAC;
function EVP_MAC_is_a(const mac : PEVP_MAC; name : PUTF8Char):Boolean;
function EVP_MAC_CTX_dup(const src : PEVP_MAC_CTX):PEVP_MAC_CTX;
function EVP_MAC_get0_name(const mac : PEVP_MAC):PUTF8Char;

implementation
uses openssl3.crypto.evp.evp_fetch, OpenSSL3.Err, openssl3.crypto.mem,
     openssl3.include.internal.refcount, openssl3.crypto.provider_core,
     openssl3.crypto.core_algorithm, OpenSSL3.openssl.core_dispatch,
     openssl3.crypto.evp.keymgmt_meth, OpenSSL3.openssl.params,
     OpenSSL3.threads_none,
     openssl3.crypto.evp.mac_meth, openssl3.crypto.params;






function EVP_MAC_get0_name(const mac : PEVP_MAC):PUTF8Char;
begin
    Result := mac.type_name;
end;

function EVP_MAC_CTX_dup(const src : PEVP_MAC_CTX):PEVP_MAC_CTX;
var
  dst : PEVP_MAC_CTX;
begin
    if src.algctx = nil then Exit(nil);
    dst := OPENSSL_malloc(sizeof( dst^));
    if dst = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    dst^ := src^;
    if  0>= EVP_MAC_up_ref(dst.meth ) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(dst);
        Exit(nil);
    end;
    dst.algctx := src.meth.dupctx(src.algctx);
    if dst.algctx = nil then
    begin
        EVP_MAC_CTX_free(dst);
        Exit(nil);
    end;
    Result := dst;
end;


function EVP_MAC_is_a(const mac : PEVP_MAC; name : PUTF8Char):Boolean;
begin
    Result := evp_is_a(mac.prov, mac.name_id, nil, name);
end;





function EVP_MAC_CTX_get0_mac( ctx : PEVP_MAC_CTX):PEVP_MAC;
begin
    Result := ctx.meth;
end;

procedure EVP_MAC_CTX_free( ctx : PEVP_MAC_CTX);
begin
    if ctx = nil then exit;
    ctx.meth.freectx(ctx.algctx);
    ctx.algctx := nil;
    { PostDec(refcnt) }
    EVP_MAC_free(ctx.meth);
    OPENSSL_free(ctx);
end;



function get_size_t_ctx_param(ctx : PEVP_MAC_CTX;const name : PUTF8Char):size_t;
var
  sz : size_t;

  params : array[0..1] of TOSSL_PARAM;
begin
    sz := 0;
    if ctx.algctx <> nil then
    begin
        params[0] := OSSL_PARAM_END;
        params[1] := OSSL_PARAM_END;
        params[0] := OSSL_PARAM_construct_size_t(name, @sz);
        if Assigned(ctx.meth.get_ctx_params ) then
        begin
            if ctx.meth.get_ctx_params(ctx.algctx, @params)>0 then
                Exit(sz);
        end
        else
        if Assigned(ctx.meth.get_params) then
        begin
            if ctx.meth.get_params(@params)>0 then
                Exit(sz);
        end;
    end;
    {
     * If the MAC hasn't been initialized yet, or there is no size to get,
     * we return zero
     }
    Result := 0;
end;

function EVP_MAC_CTX_get_mac_size( ctx : PEVP_MAC_CTX):size_t;
begin
    Result := get_size_t_ctx_param(ctx, OSSL_MAC_PARAM_SIZE);
end;

function _evp_mac_final( ctx : PEVP_MAC_CTX; xof : integer; &out : PByte; outl : Psize_t; outsize : size_t):integer;
var
  l : size_t;

  res : integer;

  params : array[0..1] of TOSSL_PARAM;

  macsize : size_t;
begin
    if (ctx = nil)  or  (ctx.meth = nil) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_NULL_ALGORITHM);
        Exit(0);
    end;
    if not Assigned(ctx.meth.final) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR);
        Exit(0);
    end;
    macsize := EVP_MAC_CTX_get_mac_size(ctx);
    if &out = nil then
    begin
        if outl = nil then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER);
            Exit(0);
        end;
        outl^ := macsize;
        Exit(1);
    end;
    if outsize < macsize then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_BUFFER_TOO_SMALL);
        Exit(0);
    end;
    if xof>0 then
    begin
        params[0] := OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, @xof);
        params[1] := OSSL_PARAM_construct_end();
        if EVP_MAC_CTX_set_params(ctx, @params) <= 0 then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_SETTING_XOF_FAILED);
            Exit(0);
        end;
    end;
    res := ctx.meth.final(ctx.algctx, &out, @l, outsize);
    if outl <> nil then outl^ := l;
    Result := res;
end;


function EVP_MAC_final( ctx : PEVP_MAC_CTX; &out : PByte; outl : Psize_t; outsize : size_t):integer;
begin
    Result := _evp_mac_final(ctx, 0, &out, outl, outsize);
end;

function EVP_MAC_update(ctx : PEVP_MAC_CTX;const data : PByte; datalen : size_t):integer;
begin
    Result := ctx.meth.update(ctx.algctx, data, datalen);
end;

function EVP_MAC_init(ctx : PEVP_MAC_CTX;const key : PByte; keylen : size_t;const params : POSSL_PARAM):integer;
begin
    Result := ctx.meth.init(ctx.algctx, key, keylen, params);
end;





function EVP_MAC_CTX_set_params(ctx : PEVP_MAC_CTX;const params : POSSL_PARAM):integer;
begin
    if Assigned(ctx.meth.set_ctx_params ) then
       Exit(ctx.meth.set_ctx_params(ctx.algctx, params));
    Result := 1;
end;

function EVP_MAC_CTX_new( mac : PEVP_MAC):PEVP_MAC_CTX;
var
  ctx : PEVP_MAC_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof(TEVP_MAC_CTX));
    ctx.algctx := mac.newctx(ossl_provider_ctx(mac.prov) );
    if (ctx = nil)
         or  ( (ctx.algctx =  nil )  or
               (0>= EVP_MAC_up_ref(mac) )) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        if ctx <> nil then
           mac.freectx(ctx.algctx);
        OPENSSL_free(ctx);
        ctx := nil;
    end
    else
    begin
        ctx.meth := mac;
    end;
    Result := ctx;
end;

function EVP_Q_mac(libctx : POSSL_LIB_CTX;const name, propq, subalg : PUTF8Char; params : POSSL_PARAM; key : Pointer; keylen : size_t;const data : PByte; datalen : size_t; &out : PByte; outsize : size_t; outlen : Psize_t):PByte;
var
    mac            : PEVP_MAC;
    subalg_param   : array[0..1] of TOSSL_PARAM;
    ctx            : PEVP_MAC_CTX;
    len            : size_t;
    res            : PByte;
    defined_params : POSSL_PARAM;
    param_name     : PUTF8Char;
    label err ;
begin
    mac := EVP_MAC_fetch(libctx, name, propq);
    subalg_param[0] := OSSL_PARAM_END;
    subalg_param[1] := OSSL_PARAM_END;

    ctx := nil;
    len := 0;
    res := nil;
    if outlen <> nil then outlen^ := 0;
    if mac = nil then Exit(nil);
    if subalg <> nil then
    begin
        defined_params := EVP_MAC_settable_ctx_params(mac);
       param_name := OSSL_MAC_PARAM_DIGEST;
        {
         * The underlying algorithm may be a cipher or a digest.
         * We don't know which it is, but we can ask the MAC what it
         * should be and bet on that.
         }
        if OSSL_PARAM_locate_const(defined_params, param_name )= nil then
        begin
            param_name := OSSL_MAC_PARAM_CIPHER;
            if OSSL_PARAM_locate_const(defined_params, param_name ) = nil then
            begin
                ERR_raise(ERR_LIB_EVP, ERR_R_PASSED_INVALID_ARGUMENT);
                goto err;
            end;
        end;
        subalg_param[0] := OSSL_PARAM_construct_utf8_string(param_name, PUTF8Char(subalg), 0);
    end;
    { Single-shot - on nil key input, set dummy key value for EVP_MAC_Init. }
    if (key = nil)  and  (keylen = 0) then
       key := data;
    ctx := EVP_MAC_CTX_new(mac );
    if (ctx <> nil)
             and  (EVP_MAC_CTX_set_params(ctx, @subalg_param)>0)
             and  (EVP_MAC_CTX_set_params(ctx, params)>0)
             and  (EVP_MAC_init(ctx, key, keylen, params)>0)
             and  (EVP_MAC_update(ctx, data, datalen)>0)
             and  (EVP_MAC_final(ctx, &out, @len, outsize)>0) then
    begin
        if &out = nil then
        begin
            &out := OPENSSL_malloc(len);
            if (&out <> nil)  and
                (0>= EVP_MAC_final(ctx, &out, nil, len) )then
                begin
                OPENSSL_free(out);
                &out := nil;
            end;
        end;
        res := &out;
        if (res <> nil)  and  (outlen <> nil) then
           outlen^ := len;
    end;
 err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    Result := res;
end;

end.
