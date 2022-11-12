unit openssl3.crypto.engine.tb_rsa;

interface
uses OpenSSL.Api;

function ENGINE_get_RSA(const e : PENGINE):PRSA_METHOD;
function ENGINE_get_default_RSA:PENGINE;
function ENGINE_set_default_RSA( e : PENGINE):integer;
procedure engine_unregister_all_RSA;
function ENGINE_set_RSA(e : PENGINE;const rsa_meth : PRSA_METHOD):integer;
function ENGINE_register_RSA( e : PENGINE):integer;

implementation

uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.engine.eng_table;

var
  rsa_table: PENGINE_TABLE  = nil;
  dummy_nid: int            = 1;

function ENGINE_register_RSA( e : PENGINE):integer;
begin
    if Assigned(e.rsa_meth) then
       Exit(engine_table_register(@rsa_table,
                                     engine_unregister_all_RSA, e, @dummy_nid,
                                     1, 0));
    Result := 1;
end;


function ENGINE_set_RSA(e : PENGINE;const rsa_meth : PRSA_METHOD):integer;
begin
    e.rsa_meth := rsa_meth;
    Result := 1;
end;


procedure engine_unregister_all_RSA;
begin
    engine_table_cleanup(@rsa_table);
end;


function ENGINE_set_default_RSA( e : PENGINE):integer;
begin
    if e.rsa_meth <> nil then
       Exit(engine_table_register (@rsa_table,
                                     engine_unregister_all_RSA, e, @dummy_nid,
                                     1, 1));
    Result := 1;
end;


function ENGINE_get_default_RSA:PENGINE;
begin
    Result := ossl_engine_table_select(@rsa_table, dummy_nid, nil, 0); //OPENSSL_FILE, OPENSSL_LINE));
end;

function ENGINE_get_RSA(const e : PENGINE):PRSA_METHOD;
begin
    Result := e.rsa_meth;
end;

end.
