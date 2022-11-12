unit OpenSSL3.crypto.ct.ct_log;

interface
uses OpenSSL.Api;


function ctlog_store_load_ctx_new:PCTLOG_STORE_LOAD_CTX;
  procedure ctlog_store_load_ctx_free( ctx : PCTLOG_STORE_LOAD_CTX);
  function ct_v1_log_id_from_pkey( log : PCTLOG; pkey : PEVP_PKEY):integer;
  function CTLOG_STORE_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PCTLOG_STORE;
  function CTLOG_STORE_new:PCTLOG_STORE;
  procedure CTLOG_STORE_free( store : PCTLOG_STORE);
  function ctlog_new_from_conf(store : PCTLOG_STORE; ct_log : PPCTLOG;const conf : PCONF; section : PUTF8Char):integer;
  function CTLOG_STORE_load_default_file( store : PCTLOG_STORE):integer;
  function ctlog_store_load_log(const log_name : PUTF8Char; log_name_len : integer; arg : Pointer):integer;
  function CTLOG_STORE_load_file(store : PCTLOG_STORE;const _file : PUTF8Char):integer;
  function CTLOG_new_ex(public_key : PEVP_PKEY;const name : PUTF8Char; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PCTLOG;
  function CTLOG_new(public_key : PEVP_PKEY;const name : PUTF8Char):PCTLOG;
  procedure CTLOG_free( log : PCTLOG);
  function CTLOG_get0_name(const log : PCTLOG):PUTF8Char;
  procedure CTLOG_get0_log_id(const log : PCTLOG; log_id : PPByte; log_id_len : Psize_t);
  function CTLOG_get0_public_key(const log : PCTLOG):PEVP_PKEY;
  function CTLOG_STORE_get0_log_by_id(const store : PCTLOG_STORE; log_id : PByte; log_id_len : size_t):PCTLOG;



implementation
uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.x509.x_pubkey,
     openssl3.crypto.evp.digest, openssl3.crypto.o_str,
     OpenSSL3.crypto.ct.ct_b64,  openssl3.crypto.getenv,
     openssl3.crypto.conf.conf_mod,  openssl3.crypto.evp.p_lib,
     openssl3.include.openssl.ct, openssl3.crypto.conf.conf_lib;

function ctlog_store_load_ctx_new:PCTLOG_STORE_LOAD_CTX;
var
  ctx : PCTLOG_STORE_LOAD_CTX;
begin
    ctx := OPENSSL_zalloc(sizeof( ctx^));
    if ctx = nil then
       ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
    Result := ctx;
end;


procedure ctlog_store_load_ctx_free( ctx : PCTLOG_STORE_LOAD_CTX);
begin
    OPENSSL_free(ctx);
end;


function ct_v1_log_id_from_pkey( log : PCTLOG; pkey : PEVP_PKEY):integer;
var
    ret          : integer;
    pkey_der     : PByte;
    pkey_der_len : integer;
    len          : uint32;
    sha256       : PEVP_MD;
    label _err;
begin
    ret := 0;
    pkey_der := nil;
    pkey_der_len := i2d_PUBKEY(pkey, @pkey_der);
    sha256 := nil;
    if pkey_der_len <= 0 then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_KEY_INVALID);
        goto _err ;
    end;
    sha256 := EVP_MD_fetch(log.libctx, ' SHA2-256' , log.propq);
    if sha256 = nil then
    begin
        ERR_raise(ERR_LIB_CT, ERR_R_EVP_LIB);
        goto _err ;
    end;
    ret := EVP_Digest(pkey_der, pkey_der_len, @log.log_id, @len, sha256,
                     nil);
_err:
    EVP_MD_free(sha256);
    OPENSSL_free(pkey_der);
    Result := ret;
end;


function CTLOG_STORE_new_ex(libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PCTLOG_STORE;
var
  ret : PCTLOG_STORE;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.libctx := libctx;
    if propq <> nil then
    begin
        OPENSSL_strdup(ret.propq ,propq);
        if ret.propq = nil then
        begin
            ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    ret.logs := sk_CTLOG_new_null();
    if ret.logs = nil then
    begin
        ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    Exit(ret);
_err:
    CTLOG_STORE_free(ret);
    Result := nil;
end;


function CTLOG_STORE_new:PCTLOG_STORE;
begin
    Result := CTLOG_STORE_new_ex(nil, nil);
end;


procedure CTLOG_STORE_free( store : PCTLOG_STORE);
begin
    if store <> nil then
    begin
        OPENSSL_free(store.propq);
        sk_CTLOG_pop_free(store.logs, CTLOG_free);
        OPENSSL_free(store);
    end;
end;


function ctlog_new_from_conf(store : PCTLOG_STORE; ct_log : PPCTLOG;const conf : PCONF; section : PUTF8Char):integer;
var
  description,
  pkey_base64 : PUTF8Char;
begin
    description := NCONF_get_string(conf, section, ' description' );
    if description = nil then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_CONF_MISSING_DESCRIPTION);
        Exit(0);
    end;
    pkey_base64 := NCONF_get_string(conf, section, ' key' );
    if pkey_base64 = nil then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_CONF_MISSING_KEY);
        Exit(0);
    end;
    Result := CTLOG_new_from_base64_ex(ct_log, pkey_base64, description,
                                    store.libctx, store.propq);
end;


function CTLOG_STORE_load_default_file( store : PCTLOG_STORE):integer;
var
  fpath : PUTF8Char;
begin
    fpath := ossl_safe_getenv(CTLOG_FILE_EVP);
    if fpath = nil then
       fpath := CTLOG_FILE;
    Result := CTLOG_STORE_load_file(store, fpath);
end;


function ctlog_store_load_log(const log_name : PUTF8Char; log_name_len : integer; arg : Pointer):integer;
var
    load_ctx : PCTLOG_STORE_LOAD_CTX;
    ct_log   : PCTLOG;
    tmp      : PUTF8Char;
    ret      : integer;
    label _memerr;
begin
    load_ctx := arg;
    ct_log := nil;
    { log_name may not be null-terminated, so fix that before using it }
    ret := 0;
    { log_name will be nil for empty list entries }
    if log_name = nil then Exit(1);
    OPENSSL_strndup(tmp, log_name, log_name_len);
    if tmp = nil then
       goto _memerr ;
    ret := ctlog_new_from_conf(load_ctx.log_store, @ct_log, load_ctx.conf, tmp);
    OPENSSL_free(tmp);
    if ret < 0 then
    begin
        { Propagate any internal error }
        Exit(ret);
    end;
    if ret = 0 then
    begin
        { If we can't load this log, record that fact and skip it }
        PreInc(load_ctx.invalid_log_entries);
        Exit(1);
    end;
    if 0>= sk_CTLOG_push(load_ctx.log_store.logs, ct_log) then
    begin
        goto _memerr ;
    end;
    Exit(1);
_memerr:
    CTLOG_free(ct_log);
    ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
    Result := -1;
end;


function CTLOG_STORE_load_file(store : PCTLOG_STORE;const _file : PUTF8Char):integer;
var
    ret          : integer;
    enabled_logs : PUTF8Char;
    load_ctx     : PCTLOG_STORE_LOAD_CTX;
    label _end;
begin
    ret := 0;
    load_ctx := ctlog_store_load_ctx_new();
    if load_ctx = nil then Exit(0);
    load_ctx.log_store := store;
    load_ctx.conf := NCONF_new(nil);
    if load_ctx.conf = nil then
       goto _end ;
    if NCONF_load(load_ctx.conf, _file, nil) <= 0  then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_CONF_INVALID);
        goto _end ;
    end;
    enabled_logs := NCONF_get_string(load_ctx.conf, nil, ' enabled_logs' );
    if enabled_logs = nil then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_CONF_INVALID);
        goto _end ;
    end;
    if (0>= CONF_parse_list(enabled_logs, Ord(','), 1, ctlog_store_load_log, load_ctx))  or
       (load_ctx.invalid_log_entries > 0)  then
    begin
        ERR_raise(ERR_LIB_CT, CT_R_LOG_CONF_INVALID);
        goto _end ;
    end;
    ret := 1;
_end:
    NCONF_free(load_ctx.conf);
    ctlog_store_load_ctx_free(load_ctx);
    Result := ret;
end;


function CTLOG_new_ex(public_key : PEVP_PKEY;const name : PUTF8Char; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PCTLOG;
var
  ret : PCTLOG;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.libctx := libctx;
    if propq <> nil then
    begin
         OPENSSL_strdup(ret.name ,propq);
        if ret.propq = nil then
        begin
            ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    OPENSSL_strdup(ret.name ,name);
    if ret.name = nil then
    begin
        ERR_raise(ERR_LIB_CT, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if ct_v1_log_id_from_pkey(ret, public_key)<> 1  then
        goto _err ;
    ret.public_key := public_key;
    Exit(ret);
_err:
    CTLOG_free(ret);
    Result := nil;
end;


function CTLOG_new(public_key : PEVP_PKEY;const name : PUTF8Char):PCTLOG;
begin
    Result := CTLOG_new_ex(public_key, name, nil, nil);
end;


procedure CTLOG_free( log : PCTLOG);
begin
    if log <> nil then
    begin
        OPENSSL_free(log.name);
        EVP_PKEY_free(log.public_key);
        OPENSSL_free(log.propq);
        OPENSSL_free(log);
    end;
end;


function CTLOG_get0_name(const log : PCTLOG):PUTF8Char;
begin
    Result := log.name;
end;


procedure CTLOG_get0_log_id(const log : PCTLOG; log_id : PPByte; log_id_len : Psize_t);
begin
    log_id^ := @log.log_id;
    log_id_len^ := CT_V1_HASHLEN;
end;


function CTLOG_get0_public_key(const log : PCTLOG):PEVP_PKEY;
begin
    Result := log.public_key;
end;


function CTLOG_STORE_get0_log_by_id(const store : PCTLOG_STORE; log_id : PByte; log_id_len : size_t):PCTLOG;
var
  i : integer;
  log : PCTLOG;
begin
    log := sk_CTLOG_value(store.logs, i);
    for i := 0 to sk_CTLOG_num(store.logs)-1 do
    begin
        if memcmp(@log.log_id, log_id, log_id_len) = 0  then
            Exit(log);
    end;
    Result := nil;
end;

end.
