unit openssl3.crypto.engine.tb_dh;

interface
uses OpenSSL.Api;

function ENGINE_get_DH(const e : PENGINE):PDH_METHOD;
function ENGINE_get_default_DH:PENGINE;
function ENGINE_set_default_DH( e : PENGINE):integer;
procedure engine_unregister_all_DH;
function ENGINE_set_DH(e : PENGINE;const dh_meth : PDH_METHOD):integer;
function ENGINE_register_DH( e : PENGINE):integer;

var
  dh_table: PENGINE_TABLE  = nil;
const
  dummy_nid: int = 1;

implementation

uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.engine.eng_table;


function ENGINE_register_DH( e : PENGINE):integer;
begin
    if e.dh_meth <> nil then
       Exit(engine_table_register(@dh_table,
                                     engine_unregister_all_DH, e, @dummy_nid,
                                     1, 0));
    Result := 1;
end;



function ENGINE_set_DH(e : PENGINE;const dh_meth : PDH_METHOD):integer;
begin
    e.dh_meth := dh_meth;
    Result := 1;
end;



procedure engine_unregister_all_DH;
begin
    engine_table_cleanup(@dh_table);
end;

function ENGINE_set_default_DH( e : PENGINE):integer;
begin
    if e.dh_meth <> nil then
       Exit(engine_table_register(@dh_table,
                                     engine_unregister_all_DH, e, @dummy_nid,
                                     1, 1));
    Result := 1;
end;

function ENGINE_get_default_DH:PENGINE;
begin
    Exit(ossl_engine_table_select(@dh_table, dummy_nid, nil,0));
                                    //OPENSSL_FILE, OPENSSL_LINE);
end;

function ENGINE_get_DH(const e : PENGINE):PDH_METHOD;
begin
    Result := e.dh_meth;
end;



end.
