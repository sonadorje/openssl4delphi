unit OpenSSL3.providers.common.provider_util;

interface
uses OpenSSL.Api;

function ossl_prov_digest_md(const pd : PPROV_DIGEST):PEVP_MD;
function ossl_prov_digest_load_from_params(pd : PPROV_DIGEST; params : POSSL_PARAM; ctx : POSSL_LIB_CTX):integer;
function load_common(const params : POSSL_PARAM;var propquery : PUTF8Char;var engine : PENGINE):integer;
function ossl_prov_digest_fetch(pd : PPROV_DIGEST; libctx : POSSL_LIB_CTX;const mdname, propquery : PUTF8Char):PEVP_MD;
procedure ossl_prov_digest_reset(pd : PPROV_DIGEST);
function ossl_prov_macctx_load_from_params(macctx : PPEVP_MAC_CTX;const params : POSSL_PARAM; macname, ciphername, mdname : PUTF8Char; libctx : POSSL_LIB_CTX):integer;
function ossl_prov_set_macctx(macctx : PEVP_MAC_CTX;const params : POSSL_PARAM; ciphername, mdname, engine, properties : PUTF8Char; key : PByte; keylen : size_t):integer;
function ossl_prov_cipher_cipher(pc : PPROV_CIPHER):PEVP_CIPHER;
function ossl_prov_cipher_load_from_params(pc : PPROV_CIPHER;const params : POSSL_PARAM; ctx : POSSL_LIB_CTX):integer;
function ossl_prov_cipher_engine(const pc : PPROV_CIPHER):PENGINE;
procedure ossl_prov_cipher_reset( pc : PPROV_CIPHER);
function ossl_prov_cipher_copy(dst : PPROV_CIPHER;const src : PPROV_CIPHER):integer;
function ossl_prov_digest_copy(dst : PPROV_DIGEST;const src : PPROV_DIGEST):integer;
 function ossl_prov_digest_engine(const pd : PPROV_DIGEST):PENGINE;

implementation

uses
   openssl3.crypto.params, openssl3.crypto.evp.digest,
   openssl3.crypto.evp.mac_meth,    openssl3.crypto.evp.evp_enc,
   openssl3.crypto.evp.names,       openssl3.providers.fips.fipsprov,
   openssl3.crypto.engine.eng_list, openssl3.crypto.evp.mac_lib,
   openssl3.crypto.engine.eng_init, openssl3.crypto.engine.eng_lib;


function ossl_prov_digest_engine(const pd : PPROV_DIGEST):PENGINE;
begin
    Result := pd.engine;
end;

function ossl_prov_digest_copy(dst : PPROV_DIGEST;const src : PPROV_DIGEST):integer;
begin
    if (src.alloc_md <> nil)  and  (0>= EVP_MD_up_ref(src.alloc_md) )then
        Exit(0);
{$IF not defined(FIPS_MODULE)  and  not defined(OPENSSL_NO_ENGINE)}
    if (src.engine <> nil)  and  (0>= ENGINE_init(src.engine)) then
    begin
        EVP_MD_free(src.alloc_md);
        Exit(0);
    end;
{$ENDIF}
    dst.engine := src.engine;
    dst.md := src.md;
    dst.alloc_md := src.alloc_md;
    Result := 1;
end;


function ossl_prov_cipher_copy(dst : PPROV_CIPHER;const src : PPROV_CIPHER):integer;
begin
    if (src.alloc_cipher <> nil)  and  (0>= EVP_CIPHER_up_ref(src.alloc_cipher)) then
        Exit(0);
{$IF not defined(FIPS_MODULE)  and  not defined(OPENSSL_NO_ENGINE)}
    if (src.engine <> nil)  and  (0>= ENGINE_init(src.engine) ) then
    begin
        EVP_CIPHER_free(src.alloc_cipher);
        Exit(0);
    end;
{$ENDIF}
    dst.engine := src.engine;
    dst.cipher := src.cipher;
    dst.alloc_cipher := src.alloc_cipher;
    Result := 1;
end;

procedure ossl_prov_cipher_reset( pc : PPROV_CIPHER);
begin
    EVP_CIPHER_free(pc.alloc_cipher);
    pc.alloc_cipher := nil;
    pc.cipher := nil;
{$IF not defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ENGINE)}
    ENGINE_finish(pc.engine);
{$ENDIF}
    pc.engine := nil;
end;


function ossl_prov_cipher_engine(const pc : PPROV_CIPHER):PENGINE;
begin
    Result := pc.engine;
end;

function ossl_prov_cipher_load_from_params(pc : PPROV_CIPHER;const params : POSSL_PARAM; ctx : POSSL_LIB_CTX):integer;
var
    p         : POSSL_PARAM;
    cipher    : PEVP_CIPHER;
    propquery : PUTF8Char;
begin
    if params = nil then Exit(1);
    if  0>= load_common(params, propquery, pc.engine ) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if p = nil then Exit(1);
    if p.data_type <> OSSL_PARAM_UTF8_STRING then Exit(0);
    EVP_CIPHER_free(pc.alloc_cipher);
    ERR_set_mark();
    pc.alloc_cipher := EVP_CIPHER_fetch(ctx, p.data, propquery);
    pc.cipher := pc.alloc_cipher;
{$ifndef FIPS_MODULE} { Inside the FIPS module, we don't support legacy ciphers }
    if pc.cipher = nil then
    begin
        cipher := EVP_get_cipherbyname(p.data);
        { Do not use global EVP_CIPHERs }
        if (cipher <> nil)  and  (cipher.origin <> EVP_ORIG_GLOBAL) then
           pc.cipher := cipher;
    end;
{$ENDIF}
    if pc.cipher <> nil then
       ERR_pop_to_mark()
    else
        ERR_clear_last_mark();
    Result := Int(pc.cipher <> nil);
end;

function ossl_prov_cipher_cipher(pc : PPROV_CIPHER):PEVP_CIPHER;
begin
    Result := pc.cipher;
end;

function ossl_prov_set_macctx(macctx : PEVP_MAC_CTX;const params : POSSL_PARAM; ciphername, mdname, engine, properties : PUTF8Char; key : PByte; keylen : size_t):integer;
var
    p,mp          : POSSL_PARAM;
    mac_params : array[0..5] of TOSSL_PARAM;
begin
    mp := @mac_params;
    if params <> nil then
    begin
        if mdname = nil then
        begin
            p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
            if (p <> nil) then
            begin
                if p.data_type <> OSSL_PARAM_UTF8_STRING then
                    Exit(0);
                mdname := p.data;
            end;
        end;
        if ciphername = nil then
        begin
            p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
            if p <> nil then
            begin
                if p.data_type <> OSSL_PARAM_UTF8_STRING then
                    Exit(0);
                ciphername := p.data;
            end;
        end;
        if engine = nil then
        begin
             p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE) ;
            if (p <> nil)then
            begin
                if p.data_type <> OSSL_PARAM_UTF8_STRING then
                    Exit(0);
                engine := p.data;
            end;
        end;
    end;
    if mdname <> nil then
    begin
       mp^ := OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, mdname, 0);
       Inc(mp);
    end;
    if ciphername <> nil then
    begin
       mp^ := OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, ciphername, 0);
       Inc(mp);
    end;
    if properties <> nil then
    begin
      mp^ := OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES, properties, 0);
      Inc(mp);
    end;
{$IF not defined(OPENSSL_NO_ENGINE)  and   not defined(FIPS_MODULE)}
    if engine <> nil then
    begin
       mp^ := OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_ENGINE, engine, 0);
       Inc(mp);
    end;
{$ENDIF}
    if key <> nil then
    begin
       mp^ := OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, keylen);
       Inc(mp);
    end;
    mp^ := OSSL_PARAM_construct_end();
    Exit(EVP_MAC_CTX_set_params(macctx, @mac_params));
end;

function ossl_prov_macctx_load_from_params(macctx : PPEVP_MAC_CTX;const params : POSSL_PARAM; macname, ciphername, mdname : PUTF8Char; libctx : POSSL_LIB_CTX):integer;
var
    p          : POSSL_PARAM;
    properties : PUTF8Char;
    mac        : PEVP_MAC;
begin
     properties := nil;
     p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_MAC);
    if (macname = nil) and  (p <> nil) then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        macname := p.data;
    end;
    p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES  ) ;
    if (p <> nil)then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        properties := p.data;
    end;
    // If we got a new mac name, we make a new EVP_MAC_CTX
    if macname <> nil then
    begin
        mac := EVP_MAC_fetch(libctx, macname, properties);
        EVP_MAC_CTX_free( macctx^);
        if mac = nil  then
           macctx^ :=  nil
        else
           macctx^ := EVP_MAC_CTX_new(mac);
        { The context holds on to the MAC }
        EVP_MAC_free(mac);
        if macctx^ = nil then Exit(0);
    end;
    {
     * If there is no MAC yet (and therefore, no MAC context), we ignore
     * all other parameters.
     }
    if macctx^ = nil then Exit(1);
    if ossl_prov_set_macctx( macctx^, params, ciphername, mdname, nil,
                             properties, nil, 0 ) > 0 then
        Exit(1);
    EVP_MAC_CTX_free( macctx^);
    macctx^ := nil;
    Result := 0;
end;

procedure ossl_prov_digest_reset(pd : PPROV_DIGEST);
begin
    EVP_MD_free(pd.alloc_md);
    pd.alloc_md := nil;
    pd.md := nil;
{$IF not defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ENGINE)}
    ENGINE_finish(pd.engine);
{$ENDIF}
    pd.engine := nil;
end;

function ossl_prov_digest_fetch(pd : PPROV_DIGEST; libctx : POSSL_LIB_CTX;const mdname, propquery : PUTF8Char):PEVP_MD;
begin
    EVP_MD_free(pd.alloc_md);
    pd.alloc_md := EVP_MD_fetch(libctx, mdname, propquery);
    pd.md := pd.alloc_md;
    Result := pd.md;
end;

function load_common(const params : POSSL_PARAM;var propquery : PUTF8Char;var engine : PENGINE):integer;
var
  p : POSSL_PARAM;
begin
    propquery := nil;
    p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        propquery := p.data;
    end;
{$IF not defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ENGINE)}
    ENGINE_finish( engine);
{$ENDIF}
    engine := nil;
    { Inside the FIPS module, we don't support legacy ciphers }
{$IF not defined(FIPS_MODULE)  and   not defined(OPENSSL_NO_ENGINE)}
    p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);
    if p <> nil then
    begin
        if p.data_type <> OSSL_PARAM_UTF8_STRING then
            Exit(0);
        { Get a structural reference }
        engine := ENGINE_by_id(p.data);
        if engine = nil then Exit(0);
        { Get a functional reference }
        if  0>= ENGINE_init( engine ) then
        begin
            ENGINE_free( engine);
            engine := nil;
            Exit(0);
        end;
        { Free the structural reference }
        ENGINE_free(engine);
    end;
{$ENDIF}
    Result := 1;
end;


function ossl_prov_digest_load_from_params(pd : PPROV_DIGEST; params : POSSL_PARAM; ctx : POSSL_LIB_CTX):integer;
var
    p         : POSSL_PARAM;
    prop_query : PUTF8Char;
    md        : PEVP_MD;
begin
    if params = nil then Exit(1);
    if  0>= load_common(params, prop_query, pd.engine) then
        Exit(0);
    p := OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
    if p = nil then
       Exit(1);
    if p.data_type <> OSSL_PARAM_UTF8_STRING then
       Exit(0);
    ERR_set_mark();
    ossl_prov_digest_fetch(pd, ctx, p.data, prop_query);
{$ifndef FIPS_MODULE} { Inside the FIPS module, we don't support legacy digests }
    if pd.md = nil then
    begin
        md := EVP_get_digestbyname(p.data);
        { Do not use global EVP_MDs }
        if (md <> nil)  and  (md.origin <> EVP_ORIG_GLOBAL) then
           pd.md := md;
    end;
{$ENDIF}
    if pd.md <> nil then
       ERR_pop_to_mark()
    else
       ERR_clear_last_mark();
    Result := Int(pd.md <> nil);
end;

function ossl_prov_digest_md(const pd : PPROV_DIGEST):PEVP_MD;
begin
    Result := pd.md;
end;

end.
