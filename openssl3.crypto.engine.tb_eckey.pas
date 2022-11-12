unit openssl3.crypto.engine.tb_eckey;

interface
uses OpenSSL.Api;

function ENGINE_get_EC(const e : PENGINE):PEC_KEY_METHOD;
function ENGINE_get_default_EC:PENGINE;
function ENGINE_set_default_EC( e : PENGINE):integer;
procedure engine_unregister_all_EC;
function ENGINE_set_EC(e : PENGINE;const ec_meth : PEC_KEY_METHOD):integer;
function ENGINE_register_EC( e : PENGINE):integer;

var
   dh_table: PENGINE_TABLE  = nil;
   dummy_nid:int = 1;



implementation
uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.engine.eng_table;




function ENGINE_register_EC( e : PENGINE):integer;
begin
    if e.ec_meth <> nil then
       Exit(engine_table_register(@dh_table,
                                     engine_unregister_all_EC, e, @dummy_nid,
                                     1, 0));
    Result := 1;
end;




function ENGINE_set_EC(e : PENGINE;const ec_meth : PEC_KEY_METHOD):integer;
begin
    e.ec_meth := ec_meth;
    Result := 1;
end;




procedure engine_unregister_all_EC;
begin
    engine_table_cleanup(@dh_table);
end;



function ENGINE_set_default_EC( e : PENGINE):integer;
begin
    if e.ec_meth <> nil then Exit(engine_table_register(@dh_table,
                                     engine_unregister_all_EC, e, @dummy_nid,
                                     1, 1));
    Result := 1;
end;





function ENGINE_get_default_EC:PENGINE;
begin
    Exit(ossl_engine_table_select(@dh_table, dummy_nid,
                                    nil, 0 ));//OPENSSL_FILE, OPENSSL_LINE));
end;

function ENGINE_get_EC(const e : PENGINE):PEC_KEY_METHOD;
begin
    Result := e.ec_meth;
end;







end.
