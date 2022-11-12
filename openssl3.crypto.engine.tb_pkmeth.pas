unit openssl3.crypto.engine.tb_pkmeth;

interface
uses OpenSSL.Api;

function ENGINE_get_pkey_meth( e : PENGINE; nid : integer):PEVP_PKEY_METHOD;
procedure engine_pkey_meths_free( e : PENGINE);
function ENGINE_get_pkey_meths(const e : PENGINE):ENGINE_PKEY_METHS_PTR;
function ENGINE_get_pkey_meth_engine( nid : integer):PENGINE;

var
  pkey_meth_table: PENGINE_TABLE  = nil;

function ENGINE_set_default_pkey_meths( e : PENGINE):integer;
procedure engine_unregister_all_pkey_meths;
function ENGINE_register_pkey_meths( e : PENGINE):integer;

implementation
uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.evp.pmeth_lib, openssl3.crypto.engine.eng_table;




function ENGINE_register_pkey_meths( e : PENGINE):integer;
var
  num_nids : integer;
  nids: PInteger;
begin
    if Assigned(e.pkey_meths) then
    begin
        num_nids := e.pkey_meths(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@pkey_meth_table,
                                         engine_unregister_all_pkey_meths, e,
                                         nids, num_nids, 0));
    end;
    Result := 1;
end;


procedure engine_unregister_all_pkey_meths;
begin
    engine_table_cleanup(@pkey_meth_table);
end;


function ENGINE_set_default_pkey_meths( e : PENGINE):integer;
var
  num_nids : integer;
  nids: PInteger ;
begin
    if Assigned(e.pkey_meths) then
    begin
        num_nids := e.pkey_meths(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@pkey_meth_table,
                                         engine_unregister_all_pkey_meths, e,
                                         nids, num_nids, 1));
    end;
    Result := 1;
end;

function ENGINE_get_pkey_meth_engine( nid : integer):PENGINE;
begin
    Result := ossl_engine_table_select(@pkey_meth_table, nid, nil, 0);
end;

function ENGINE_get_pkey_meths(const e : PENGINE):ENGINE_PKEY_METHS_PTR;
begin
    Result := e.pkey_meths;
end;




function ENGINE_get_pkey_meth( e : PENGINE; nid : integer):PEVP_PKEY_METHOD;
var
  ret : PEVP_PKEY_METHOD;

  fn : ENGINE_PKEY_METHS_PTR;
begin
    fn := ENGINE_get_pkey_meths(e);
    if  (not Assigned(fn) )  or   (0>= fn(e, @ret, nil, nid) )then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD);
        Exit(nil);
    end;
    Result := ret;
end;


procedure engine_pkey_meths_free( e : PENGINE);
var
  i : integer;

  pkm : PEVP_PKEY_METHOD;
  pknids: PInteger;
  npknids : integer;
begin
{$POINTERMATH ON}
    if Assigned(e.pkey_meths) then
    begin
        npknids := e.pkey_meths(e, nil, @pknids, 0);
        for i := 0 to npknids-1 do
        begin
            if e.pkey_meths(e, @pkm, nil, pknids[i])>0 then
            begin
                EVP_PKEY_meth_free(pkm);
            end;
        end;
    end;
{$POINTERMATH OFF}
end;

end.
