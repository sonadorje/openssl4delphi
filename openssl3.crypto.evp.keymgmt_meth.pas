unit openssl3.crypto.evp.keymgmt_meth;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   {$IFDEF  MSWINDOWS}
      {$IFNDEF FPC} Winapi.Windows, {$ELSE}Windows,{$ENDIF}
   {$ENDIF}
   OpenSSL.Api;

type
  Tfn = procedure(kem: PEVP_KEYMGMT; arg: Pointer);
  Tkeymgmt_meth_fn2 = procedure(const p1: PUTF8Char; arg: Pointer);

function EVP_KEYMGMT_is_a(const keymgmt : PEVP_KEYMGMT; name : PUTF8Char):Boolean;
function evp_keymgmt_get_params(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; params : POSSL_PARAM):integer;
function EVP_KEYMGMT_get0_provider(const keymgmt : PEVP_KEYMGMT):POSSL_PROVIDER;
function EVP_KEYMGMT_get0_name(const keymgmt : PEVP_KEYMGMT):PUTF8Char;
function EVP_KEYMGMT_up_ref( keymgmt : Pointer):integer;
function EVP_KEYMGMT_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KEYMGMT;
function keymgmt_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
function keymgmt_new:Pointer;
function evp_keymgmt_newdata(const keymgmt : PEVP_KEYMGMT):Pointer;

function evp_keymgmt_import(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
 procedure evp_keymgmt_freedata(const keymgmt : PEVP_KEYMGMT; keydata : Pointer);
function evp_keymgmt_export(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
function evp_keymgmt_has(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection : integer):integer;
 function evp_keymgmt_match(const keymgmt : PEVP_KEYMGMT; keydata1, keydata2 : Pointer; selection : integer):integer;
function evp_keymgmt_dup(const keymgmt : PEVP_KEYMGMT; keydata_from : Pointer; selection : integer):Pointer;
 function evp_keymgmt_gen(const keymgmt : PEVP_KEYMGMT; genctx : Pointer; cb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
 function EVP_KEYMGMT_names_do_all(const keymgmt : PEVP_KEYMGMT; fn : Tkeymgmt_meth_fn2; data : Pointer):integer;

procedure EVP_KEYMGMT_free( keymgmt : Pointer);
function evp_keymgmt_gen_set_params(const keymgmt : PEVP_KEYMGMT; genctx : Pointer;const params : POSSL_PARAM):integer;
 function evp_keymgmt_fetch_from_prov(prov : POSSL_PROVIDER;const name, properties : PUTF8Char):PEVP_KEYMGMT;
procedure evp_keymgmt_gen_cleanup(const keymgmt : PEVP_KEYMGMT; genctx : Pointer);
function evp_keymgmt_has_load(const keymgmt : PEVP_KEYMGMT):integer;
function evp_keymgmt_load(const keymgmt : PEVP_KEYMGMT; objref : Pointer; objref_sz : size_t):Pointer;
function evp_keymgmt_util_try_import(const params : POSSL_PARAM; arg : Pointer):integer;
function evp_keymgmt_util_make_pkey( keymgmt : PEVP_KEYMGMT; keydata : Pointer):PEVP_PKEY;
function evp_keymgmt_gen_init(const keymgmt : PEVP_KEYMGMT; selection : integer;const params : POSSL_PARAM):Pointer;
function evp_keymgmt_gen_set_template(const keymgmt : PEVP_KEYMGMT; genctx, template : Pointer):integer;
function evp_keymgmt_validate(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection, checktype : integer):integer;

implementation
uses  openssl3.crypto.evp.evp_fetch, openssl3.include.internal.refcount,
      openssl3.crypto.mem, openssl3.crypto.provider_core,
      openssl3.crypto.evp.p_lib,  openssl3.crypto.evp.keymgmt_lib,
      OpenSSL3.threads_none, OpenSSL3.Err, openssl3.crypto.core_algorithm;




function evp_keymgmt_validate(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection, checktype : integer):integer;
begin
    { We assume valid if the implementation doesn't have a function }
    if not Assigned(keymgmt.validate) then
       Exit(1);
    Result := keymgmt.validate(keydata, selection, checktype);
end;



function evp_keymgmt_gen_set_template(const keymgmt : PEVP_KEYMGMT; genctx, template : Pointer):integer;
begin
    {
     * It's arguable if we actually should return success in this case, as
     * it allows the caller to set a template key, which is then ignored.
     * However, this is how the legacy methods (EVP_PKEY_METHOD) operate,
     * so we do this in the interest of backward compatibility.
     }
    if not Assigned(keymgmt.gen_set_template) then Exit(1);
    Result := keymgmt.gen_set_template(genctx, template);
end;





function evp_keymgmt_gen_init(const keymgmt : PEVP_KEYMGMT; selection : integer;const params : POSSL_PARAM):Pointer;
var
  provctx : Pointer;
begin
    provctx := ossl_provider_ctx(EVP_KEYMGMT_get0_provider(keymgmt));
    if not Assigned(keymgmt.gen_init) then
       Exit(nil);
    Result := keymgmt.gen_init(provctx, selection, params);
end;

function evp_keymgmt_util_make_pkey( keymgmt : PEVP_KEYMGMT; keydata : Pointer):PEVP_PKEY;
var
  pkey : PEVP_PKEY;
begin
    pkey := nil;
    pkey := EVP_PKEY_new();
    if (keymgmt = nil)
         or  (keydata = nil)
         or  (PKey = nil)
         or  (0>= evp_keymgmt_util_assign_pkey(pkey, keymgmt, keydata)) then
    begin
        EVP_PKEY_free(pkey);
        Exit(nil);
    end;
    Result := pkey;
end;




function evp_keymgmt_util_try_import(const params : POSSL_PARAM; arg : Pointer):integer;
var
    data            : Pevp_keymgmt_util_try_import_data_st;
    delete_on_error : integer;
begin
{$POINTERMATH ON}
    data := arg;
    delete_on_error := 0;
    { Just in time creation of keydata }
    if data.keydata = nil then
    begin
        data.keydata := evp_keymgmt_newdata(data.keymgmt);
        if data.keydata = nil then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        delete_on_error := 1;
    end;
    {
     * It's fine if there was no data to transfer, we just end up with an
     * empty destination key.
     }
    if params[0].key = nil then
       Exit(1);
    if evp_keymgmt_import(data.keymgmt, data.keydata, data.selection,
                           params) > 0 then
        Exit(1);
    if delete_on_error > 0 then
    begin
        evp_keymgmt_freedata(data.keymgmt, data.keydata);
        data.keydata := nil;
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

function evp_keymgmt_load(const keymgmt : PEVP_KEYMGMT; objref : Pointer; objref_sz : size_t):Pointer;
begin
    if evp_keymgmt_has_load(keymgmt)>0 then
        Exit(keymgmt.load(objref, objref_sz));
    Result := nil;
end;




function evp_keymgmt_has_load(const keymgmt : PEVP_KEYMGMT):integer;
begin
    Result := Int( (keymgmt <> nil)  and  (Assigned(keymgmt.load)) );
end;




procedure evp_keymgmt_gen_cleanup(const keymgmt : PEVP_KEYMGMT; genctx : Pointer);
begin
    if Assigned(keymgmt.gen) then
       keymgmt.gen_cleanup(genctx);
end;



//https://stackoverflow.com/questions/2309925/anonymous-methods-cast-as-pointers
function evp_keymgmt_fetch_from_prov(prov : POSSL_PROVIDER;const name, properties : PUTF8Char):PEVP_KEYMGMT;
begin

    Result := evp_generic_fetch_from_prov(prov, OSSL_OP_KEYMGMT,  name, properties,
                                       keymgmt_from_algorithm, @EVP_KEYMGMT_up_ref,
                                       @EVP_KEYMGMT_free);
end;




function evp_keymgmt_gen(const keymgmt : PEVP_KEYMGMT; genctx : Pointer; cb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
begin
    if not Assigned(keymgmt.gen) then
       Exit(nil);
    Result := keymgmt.gen(genctx, cb, cbarg);
end;


function evp_keymgmt_dup(const keymgmt : PEVP_KEYMGMT; keydata_from : Pointer; selection : integer):Pointer;
begin
    { We assume no dup if the implementation doesn't have a function }
    if not Assigned(keymgmt.dup) then Exit(nil);
    Result := keymgmt.dup(keydata_from, selection);
end;



function evp_keymgmt_match(const keymgmt : PEVP_KEYMGMT; keydata1, keydata2 : Pointer; selection : integer):integer;
begin
    { We assume no match if the implementation doesn't have a function }
    if not Assigned(keymgmt.match ) then Exit(0);
    Result := keymgmt.match(keydata1, keydata2, selection);
end;




function evp_keymgmt_has(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection : integer):integer;
begin
    { This is mandatory, no need to check for its presence }
    Result := keymgmt.has(keydata, selection);
end;



function evp_keymgmt_export(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection : integer; param_cb : POSSL_CALLBACK; cbarg : Pointer):integer;
begin
    if not Assigned(keymgmt.export) then Exit(0);
    Result := keymgmt.export(keydata, selection, param_cb, cbarg);
end;





procedure evp_keymgmt_freedata(const keymgmt : PEVP_KEYMGMT; keydata : Pointer);
begin
    { This is mandatory, no need to check for its presence }
    keymgmt.free(keydata);
end;


function evp_keymgmt_import(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; selection : integer;const params : POSSL_PARAM):integer;
begin
    if not Assigned(keymgmt.import) then Exit(0);
    Result := keymgmt.import(keydata, selection, params);
end;



function evp_keymgmt_newdata(const keymgmt : PEVP_KEYMGMT):Pointer;
var
  provctx : Pointer;
begin
    provctx := ossl_provider_ctx(EVP_KEYMGMT_get0_provider(keymgmt));
    {
     * 'new' is currently mandatory on its own, but when new
     * constructors appear, it won't be quite as mandatory,
     * so we have a check for future cases.
     }
    if not Assigned(keymgmt.new) then
       Exit(nil);
    Result := keymgmt.new(provctx);
end;


function evp_keymgmt_gen_set_params(const keymgmt : PEVP_KEYMGMT; genctx : Pointer;const params : POSSL_PARAM):integer;
begin
    if not Assigned(keymgmt.gen_set_params) then
       Exit(0);
    Result := keymgmt.gen_set_params(genctx, params);
end;

function keymgmt_new:Pointer;
var
  keymgmt : PEVP_KEYMGMT;
begin
    keymgmt := nil;
    keymgmt := OPENSSL_zalloc(sizeof(keymgmt^));
    keymgmt.lock := CRYPTO_THREAD_lock_new();
    if (keymgmt = nil) or  (keymgmt.lock = nil) then
    begin
        EVP_KEYMGMT_free(keymgmt);
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    keymgmt.refcnt := 1;
    Result := keymgmt;
end;

procedure EVP_KEYMGMT_free( keymgmt : Pointer);
var
  ref : integer;
begin
    ref := 0;
    if keymgmt = nil then
       Exit;
    CRYPTO_DOWN_REF(PEVP_KEYMGMT(keymgmt).refcnt, ref, PEVP_KEYMGMT(keymgmt).lock);
    if ref > 0 then
       exit;
    OPENSSL_free(PEVP_KEYMGMT(keymgmt).type_name);
    ossl_provider_free(PEVP_KEYMGMT(keymgmt).prov);
    CRYPTO_THREAD_lock_free(PEVP_KEYMGMT(keymgmt).lock);
    OPENSSL_free(keymgmt);
end;

function EVP_KEYMGMT_names_do_all(const keymgmt : PEVP_KEYMGMT; fn : Tkeymgmt_meth_fn2; data : Pointer):integer;
begin
    if keymgmt.prov <> nil then
       Exit(evp_names_do_all(keymgmt.prov, keymgmt.name_id, fn, data));
    Result := 1;
end;

function keymgmt_from_algorithm(name_id : integer;const algodef : POSSL_ALGORITHM; prov : POSSL_PROVIDER):Pointer;
var
  fns              : POSSL_DISPATCH;
  keymgmt          : PEVP_KEYMGMT;
  setparamfncnt,
  getparamfncnt,
  setgenparamfncnt,
  importfncnt,
  exportfncnt      : integer;
begin
    fns := algodef._implementation;
    keymgmt := nil;
    setparamfncnt := 0; getparamfncnt := 0;
    setgenparamfncnt := 0;
    importfncnt := 0; exportfncnt := 0;
    keymgmt := keymgmt_new();
    if keymgmt = nil then
        Exit(nil);
    keymgmt.name_id := name_id;
    keymgmt.type_name := ossl_algorithm_get1_first_name(algodef);
    if keymgmt.type_name =  nil then
    begin
        EVP_KEYMGMT_free(keymgmt);
        Exit(nil);
    end;
    keymgmt.description := algodef.algorithm_description;
    while fns.function_id <> 0 do
    begin
      case fns.function_id of
        OSSL_FUNC_KEYMGMT_NEW:
        begin
            if not Assigned(keymgmt.new) then
               keymgmt.new := _OSSL_FUNC_keymgmt_new(fns);
        end;
        OSSL_FUNC_KEYMGMT_GEN_INIT:
        begin
            if not Assigned(keymgmt.gen_init ) then
               keymgmt.gen_init := _OSSL_FUNC_keymgmt_gen_init(fns);
        end;
        OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE:
        begin
            if not Assigned(keymgmt.gen_set_template ) then
               keymgmt.gen_set_template := _OSSL_FUNC_keymgmt_gen_set_template(fns);
        end;
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS:
        begin
            if not Assigned(keymgmt.gen_set_params ) then
            begin
                PostInc(setgenparamfncnt);
                keymgmt.gen_set_params := _OSSL_FUNC_keymgmt_gen_set_params(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS:
        begin
            if not Assigned(keymgmt.gen_settable_params ) then
            begin
                PostInc(setgenparamfncnt);
                keymgmt.gen_settable_params := _OSSL_FUNC_keymgmt_gen_settable_params(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_GEN:
        begin
            if not Assigned(keymgmt.gen ) then
               keymgmt.gen := _OSSL_FUNC_keymgmt_gen(fns);
        end;
        OSSL_FUNC_KEYMGMT_GEN_CLEANUP:
        begin
            if not Assigned(keymgmt.gen_cleanup ) then
               keymgmt.gen_cleanup := _OSSL_FUNC_keymgmt_gen_cleanup(fns);
        end;
        OSSL_FUNC_KEYMGMT_FREE:
        begin
            if not Assigned(keymgmt.free ) then
               keymgmt.free := _OSSL_FUNC_keymgmt_free(fns);
        end;
        OSSL_FUNC_KEYMGMT_LOAD:
        begin
            if not Assigned(keymgmt.load ) then
               keymgmt.load := _OSSL_FUNC_keymgmt_load(fns);
        end;
        OSSL_FUNC_KEYMGMT_GET_PARAMS:
        begin
            if not Assigned(keymgmt.get_params ) then
            begin
                PostInc(getparamfncnt);
                keymgmt.get_params := _OSSL_FUNC_keymgmt_get_params(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS:
        begin
            if not Assigned(keymgmt.gettable_params ) then
            begin
                PostInc(getparamfncnt);
                keymgmt.gettable_params := _OSSL_FUNC_keymgmt_gettable_params(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_SET_PARAMS:
        begin
            if not Assigned(keymgmt.set_params ) then
            begin
                PostInc(setparamfncnt);
                keymgmt.set_params := _OSSL_FUNC_keymgmt_set_params(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS:
        begin
            if not Assigned(keymgmt.settable_params ) then
            begin
                PostInc(setparamfncnt);
                keymgmt.settable_params := _OSSL_FUNC_keymgmt_settable_params(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME:
        begin
            if not Assigned(keymgmt.query_operation_name ) then
               keymgmt.query_operation_name := _OSSL_FUNC_keymgmt_query_operation_name(fns);
        end;
        OSSL_FUNC_KEYMGMT_HAS:
        begin
            if not Assigned(keymgmt.has ) then
               keymgmt.has := _OSSL_FUNC_keymgmt_has(fns);
        end;
        OSSL_FUNC_KEYMGMT_DUP:
        begin
            if not Assigned(keymgmt.dup ) then
               keymgmt.dup := _OSSL_FUNC_keymgmt_dup(fns);
        end;
        OSSL_FUNC_KEYMGMT_VALIDATE:
        begin
            if not Assigned(keymgmt.validate ) then
               keymgmt.validate := _OSSL_FUNC_keymgmt_validate(fns);
        end;
        OSSL_FUNC_KEYMGMT_MATCH:
        begin
            if not Assigned(keymgmt.match ) then
               keymgmt.match := _OSSL_FUNC_keymgmt_match(fns);
        end;
        OSSL_FUNC_KEYMGMT_IMPORT:
        begin
            if not Assigned(keymgmt.import ) then
            begin
                Inc(importfncnt);
                keymgmt.import := _OSSL_FUNC_keymgmt_import(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_IMPORT_TYPES:
        begin
            if not Assigned(keymgmt.import_types ) then
            begin
                Inc(importfncnt);
                keymgmt.import_types := _OSSL_FUNC_keymgmt_import_types(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_EXPORT:
        begin
            if not Assigned(keymgmt.export ) then begin
                PostInc(exportfncnt);
                keymgmt.export := _OSSL_FUNC_keymgmt_export(fns);
            end;
        end;
        OSSL_FUNC_KEYMGMT_EXPORT_TYPES:
        begin
            if not Assigned(keymgmt.export_types ) then
            begin
                PostInc(exportfncnt);
                keymgmt.export_types := _OSSL_FUNC_keymgmt_export_types(fns);
            end;
        end;
      end;
      Inc(fns);
    end;
    {
     * Try to check that the method is sensible.
     * At least one constructor and the destructor are MANDATORY
     * The functions 'has' is MANDATORY
     * It makes no sense being able to free stuff if you can't create it.
     * It makes no sense providing OSSL_PARAM descriptors for import and
     * export if you can't import or export.
     }
    if ( not Assigned(keymgmt.free) )
         or  (    (not Assigned(keymgmt.New))
             and  (not Assigned(keymgmt.gen))
             and  (not Assigned(keymgmt.load)) )
         or  (Assigned(keymgmt.Has) = False)
         or  ( not getparamfncnt in [0,2] )
         or  ( not setparamfncnt in [0,2] )
         or  ( not setgenparamfncnt in [0,2] )
         or  ( not importfncnt in [0,2] )
         or  ( not exportfncnt in [0,2] )
         or  ( (Assigned(keymgmt.gen) = False) and
               ( (Assigned(keymgmt.gen_init) = False) or  (Assigned(keymgmt.gen_cleanup) = False) )
             ) then
    begin
        EVP_KEYMGMT_free(keymgmt);
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS);
        Exit(nil);
    end;
    keymgmt.prov := prov;
    if prov <> nil then ossl_provider_up_ref(prov);
    Result := keymgmt;
end;

function EVP_KEYMGMT_fetch(ctx : POSSL_LIB_CTX;const algorithm, properties : PUTF8Char):PEVP_KEYMGMT;
begin
    Result := evp_generic_fetch(ctx, OSSL_OP_KEYMGMT, algorithm, properties,
                             keymgmt_from_algorithm,
                             EVP_KEYMGMT_up_ref,
                             EVP_KEYMGMT_free); //不确定是否可行，2022-05-11
end;


function EVP_KEYMGMT_up_ref( keymgmt : Pointer):integer;
var
  ref : integer;
begin
    ref := 0;
    CRYPTO_UP_REF(PEVP_KEYMGMT(keymgmt).refcnt, ref, PEVP_KEYMGMT(keymgmt).lock);
    Result := 1;
end;


function EVP_KEYMGMT_get0_name(const keymgmt : PEVP_KEYMGMT):PUTF8Char;
begin
    Result := keymgmt.type_name;
end;

function EVP_KEYMGMT_get0_provider(const keymgmt : PEVP_KEYMGMT):POSSL_PROVIDER;
begin
    Result := keymgmt.prov;
end;


function evp_keymgmt_get_params(const keymgmt : PEVP_KEYMGMT; keydata : Pointer; params : POSSL_PARAM):integer;
begin
    if not Assigned(keymgmt.get_params) then Exit(1);
    Result := keymgmt.get_params(keydata, params);
end;

function EVP_KEYMGMT_is_a(const keymgmt : PEVP_KEYMGMT; name : PUTF8Char):Boolean;
begin
    Result := evp_is_a(keymgmt.prov, keymgmt.name_id, nil, name);
end;

end.
