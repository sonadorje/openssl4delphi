unit openssl3.crypto.provider_conf;

interface
uses OpenSSL.Api, SysUtils;

type
  TPROVIDER_CONF_GLOBAL = record
      lock                : PCRYPTO_RWLOCK;
      activated_providers : Pstack_st_OSSL_PROVIDER;
  end;
  PPROVIDER_CONF_GLOBAL = ^TPROVIDER_CONF_GLOBAL;

  function prov_conf_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
  procedure prov_conf_ossl_ctx_free( vpcgbl : Pointer);
  function skip_dot(const name : PUTF8Char):PUTF8Char;
  function provider_conf_params(prov : POSSL_PROVIDER; provinfo : POSSL_PROVIDER_INFO;const name, value : PUTF8Char; cnf : PCONF):integer;
  //function prov_already_activated(const name : PUTF8Char):integer;
  function provider_conf_activate(libctx : POSSL_LIB_CTX;const name, value, path : PUTF8Char; soft : integer;const cnf : PCONF):integer;
  function provider_conf_load(libctx : POSSL_LIB_CTX;{const} name, value : PUTF8Char; cnf : PCONF):integer;
  function provider_conf_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
  procedure ossl_provider_add_conf_module;

  function prov_already_activated(const name : PUTF8Char; activated : Pstack_st_OSSL_PROVIDER):integer;

  const provider_conf_ossl_ctx_method: TOSSL_LIB_CTX_METHOD  = (
    (* Must be freed before the provider store is freed *)
    priority : OSSL_LIB_CTX_METHOD_PRIORITY_2;
    new_func : prov_conf_ossl_ctx_new;
    free_func: prov_conf_ossl_ctx_free;
  );

implementation

uses openssl3.crypto.mem, OpenSSL3.Err,   OpenSSL3.threads_none,
     OpenSSL3.openssl.conf,               openssl3.crypto.provider,
     openssl3.crypto.context,             openssl3.crypto.o_str,
     openssl3.crypto.conf.conf_mod,
     openssl3.crypto.provider_core,       openssl3.crypto.conf.conf_lib;

function prov_conf_ossl_ctx_new( libctx : POSSL_LIB_CTX):Pointer;
var
  pcgbl : PPROVIDER_CONF_GLOBAL;
begin
    pcgbl := OPENSSL_zalloc(sizeof( pcgbl^));
    if pcgbl = nil then Exit(nil);
    pcgbl.lock := CRYPTO_THREAD_lock_new;
    if pcgbl.lock = nil then
    begin
        OPENSSL_free(pcgbl);
        Exit(nil);
    end;
    Result := pcgbl;
end;


procedure prov_conf_ossl_ctx_free( vpcgbl : Pointer);
var
  pcgbl : PPROVIDER_CONF_GLOBAL;
begin
    pcgbl := vpcgbl;
    sk_OSSL_PROVIDER_pop_free(pcgbl.activated_providers,
                              ossl_provider_free);
    //OSSL_TRACE(CONF, 'Cleaned up providers\n');
    CRYPTO_THREAD_lock_free(pcgbl.lock);
    OPENSSL_free(pcgbl);
end;


function skip_dot(const name : PUTF8Char):PUTF8Char;
var
  p : PUTF8Char;
begin
    p := strchr(name, '.');
    if p <> nil then Exit(p + 1);
    Result := name;
end;


function provider_conf_params(prov : POSSL_PROVIDER; provinfo : POSSL_PROVIDER_INFO;const name, value : PUTF8Char; cnf : PCONF):integer;
var
    sect       : Pstack_st_CONF_VALUE;
    ok,
    i          : integer;
    buffer     : array[0..511] of UTF8Char;
    buffer_len : size_t;
    sectconf   : PCONF_VALUE;
    pc: PUTF8CHar;
begin
    ok := 1;
    sect := NCONF_get_section(cnf, value);
    if sect <> nil then
    begin
        buffer_len := 0;
        pc:= @buffer;
        //OSSL_TRACE1(CONF, 'Provider params: start section %s\n', value);
        if name <> nil then
        begin

            OPENSSL_strlcpy(pc, name, sizeof(buffer));
            OPENSSL_strlcat(pc, '.', sizeof(buffer));
            buffer_len := Length(buffer);
        end;
        for i := 0 to sk_CONF_VALUE_num(sect)-1 do
        begin
            sectconf := sk_CONF_VALUE_value(sect, i);
            if buffer_len + Length(sectconf.name) >= sizeof(buffer)  then
                Exit(0);
            buffer[buffer_len] := #0;
            pc := buffer;
            OPENSSL_strlcat(pc, sectconf.name, sizeof(buffer));
            if 0>=provider_conf_params(prov, provinfo, buffer, sectconf.value,
                                      cnf) then
                Exit(0);
        end;
        //OSSL_TRACE1(CONF, 'Provider params: finish section %s\n', value);
    end
    else
    begin
        //OSSL_TRACE2(CONF, 'Provider params: %s = %s\n', name, value);
        if prov <> nil then
           ok := ossl_provider_add_parameter(prov, name, value)
        else
            ok := ossl_provider_info_add_parameter(provinfo, name, value);
    end;
    Result := ok;
end;




function prov_already_activated(const name : PUTF8Char; activated : Pstack_st_OSSL_PROVIDER):integer;
var
  i, max : integer;
  tstprov : POSSL_PROVIDER;
begin
    if activated = nil then Exit(0);
    max := sk_OSSL_PROVIDER_num(activated);
    for i := 0 to max-1 do begin
        tstprov := sk_OSSL_PROVIDER_value(activated, i);
        if strcmp(OSSL_PROVIDER_get0_name(tstprov) , name) = 0  then
        begin
            Exit(1);
        end;
    end;
    Result := 0;
end;


function provider_conf_activate(libctx : POSSL_LIB_CTX;const name, value, path : PUTF8Char; soft : integer;const cnf : PCONF):integer;
var
  pcgbl : PPROVIDER_CONF_GLOBAL;
  prov, actual : POSSL_PROVIDER;
  ok : integer;
begin
    pcgbl := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_PROVIDER_CONF_INDEX,
                                @provider_conf_ossl_ctx_method);
    prov := nil; actual := nil;
    ok := 0;
    if (pcgbl = nil)  or  (0>=CRYPTO_THREAD_write_lock(pcgbl.lock)) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    if 0>=prov_already_activated(name, pcgbl.activated_providers) then
    begin
        {
        * There is an attempt to activate a provider, so we should disable
        * loading of fallbacks. Otherwise a misconfiguration could mean the
        * intended provider does not get loaded. Subsequent fetches could
        * then fallback to the default provider - which may be the wrong
        * thing.
        }
        if 0>=ossl_provider_disable_fallback_loading(libctx) then
        begin
            CRYPTO_THREAD_unlock(pcgbl.lock);
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
        prov := ossl_provider_find(libctx, name, 1);
        if (prov = nil) then
           prov := ossl_provider_new(libctx, name, nil, 1);
        if prov = nil then
        begin
            CRYPTO_THREAD_unlock(pcgbl.lock);
            if soft > 0 then ERR_clear_error;
            Exit(0);
        end;
        if path <> nil then
           ossl_provider_set_module_path(prov, path);
        ok := provider_conf_params(prov, nil, nil, value, cnf);
        if ok>0 then
        begin
            if 0>=ossl_provider_activate(prov, 1, 0) then
            begin
                ok := 0;
            end
            else
            if (0>=ossl_provider_add_to_store(prov, @actual, 0)) then
            begin
                ossl_provider_deactivate(prov, 1);
                ok := 0;
            end
            else
            if (actual <> prov)
                        and  (0>=ossl_provider_activate(actual, 1, 0)) then
            begin
                ossl_provider_free(actual);
                ok := 0;
            end
            else
            begin
                if pcgbl.activated_providers = nil then
                   pcgbl.activated_providers := sk_OSSL_PROVIDER_new_null;
                if (pcgbl.activated_providers = nil)
                     or  (0>=sk_OSSL_PROVIDER_push(pcgbl.activated_providers,
                                              actual)) then
                begin
                    ossl_provider_deactivate(actual, 1);
                    ossl_provider_free(actual);
                    ok := 0;
                end
                else
                begin
                    ok := 1;
                end;
            end;
        end;
        if 0>=ok then
           ossl_provider_free(prov);
    end;
    CRYPTO_THREAD_unlock(pcgbl.lock);
    Result := ok;
end;


function provider_conf_load(libctx : POSSL_LIB_CTX;{const} name, value : PUTF8Char; cnf : PCONF):integer;
var
    i         : integer;
    ecmds     : Pstack_st_CONF_VALUE;
    soft      : integer;
    path      : PUTF8Char;
    activate  : long;
    ok        : integer;
    ecmd      : PCONF_VALUE;
    confname,
    confvalue : PUTF8Char;
    entry     : TOSSL_PROVIDER_INFO;
begin
    soft := 0;
    path := nil;
    activate := 0;
    ok := 0;
    name := skip_dot(name);
    //OSSL_TRACE1(CONF, 'Configuring provider %s\n', name);
    { Value is a section containing PROVIDER commands }
    ecmds := NCONF_get_section(cnf, value);
    if nil =ecmds then
    begin
        ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_PROVIDER_SECTION_ERROR,
                      Format('section=%s not found', [value]));
        Exit(0);
    end;
    { Find the needed data first }
    for i := 0 to sk_CONF_VALUE_num(ecmds)-1 do
    begin
        ecmd := sk_CONF_VALUE_value(ecmds, i);
        confname := skip_dot(ecmd.name);
        confvalue := ecmd.value;
        //OSSL_TRACE2(CONF, 'Provider command: %s = %s\n',
          //          confname, confvalue);
        { First handle some special pseudo confs }
        { Override provider name to use }
        if strcmp(confname, 'identity') = 0  then
            name := confvalue
        else
        if (strcmp(confname, 'soft_load') = 0) then
            soft := 1
        { Load a dynamic PROVIDER }
        else if (strcmp(confname, 'module') = 0) then
            path := confvalue
        else if (strcmp(confname, 'activate') = 0) then
            activate := 1;
    end;
    if activate > 0 then
    begin
        ok := provider_conf_activate(libctx, name, value, path, soft, cnf);
    end
    else
    begin
        memset(@entry, 0, sizeof(entry));
        ok := 1;
        if name <> nil then begin
            OPENSSL_strdup(entry.name ,name);
            if entry.name = nil then begin
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
                ok := 0;
            end;
        end;
        if (ok > 0)  and  (path <> nil) then
        begin
            OPENSSL_strdup(entry.path ,path);
            if entry.path = nil then
            begin
                ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
                ok := 0;
            end;
        end;
        if ok > 0 then
           ok := provider_conf_params(nil, @entry, nil, value, cnf);
        if (ok > 0)  and ( (entry.path <> nil)  or  (entry.parameters <> nil) ) then
            ok := ossl_provider_info_add_to_store(libctx, @entry);
        if (0>=ok)  or ( (entry.path = nil)  and  (entry.parameters = nil) ) then
        begin
            ossl_provider_info_clear(@entry);
        end;
    end;
    {
     * Even if ok is 0, we still return success. Failure to load a provider is
     * not fatal. We want to continue to load the rest of the config file.
     }
    Result := 1;
end;


function provider_conf_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
var
  elist : Pstack_st_CONF_VALUE;
  cval : PCONF_VALUE;
  i : integer;
begin
    //OSSL_TRACE1(CONF, 'Loading providers module: section %s\n',
      //          CONF_imodule_get_value(md));
    { Value is a section containing PROVIDERs to configure }
    elist := NCONF_get_section(cnf, CONF_imodule_get_value(md));
    if nil =elist then
    begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PROVIDER_SECTION_ERROR);
        Exit(0);
    end;
    for i := 0 to sk_CONF_VALUE_num(elist)-1 do begin
        cval := sk_CONF_VALUE_value(elist, i);
        if 0>=provider_conf_load(NCONF_get0_libctx(PCONF(cnf)),
                    cval.name, cval.value, cnf) then
            Exit(0);
    end;
    Result := 1;
end;


procedure ossl_provider_add_conf_module;
begin
    //OSSL_TRACE(CONF, 'Adding config module 'providers'\n');
    CONF_module_add('providers', provider_conf_init, nil);
end;


end.
