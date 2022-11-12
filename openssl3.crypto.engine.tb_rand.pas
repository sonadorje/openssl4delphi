unit openssl3.crypto.engine.tb_rand;

interface
uses OpenSSL.Api;

 function ENGINE_get_default_RAND:PENGINE;

 var
   rand_table: PENGINE_TABLE  = nil;
   dummy_nid: int = 1;

function ENGINE_get_RAND(const e : PENGINE):PRAND_METHOD;
function ENGINE_set_default_RAND( e : PENGINE):integer;
procedure engine_unregister_all_RAND;
function ENGINE_set_RAND(e : PENGINE;const rand_meth : PRAND_METHOD):integer;
function ENGINE_register_RAND( e : PENGINE):integer;


implementation
uses openssl3.crypto.engine.eng_table;




function ENGINE_register_RAND( e : PENGINE):integer;
begin
    if e.rand_meth <> nil then
       Exit(engine_table_register(@rand_table,
                                     engine_unregister_all_RAND, e,
                                     @dummy_nid, 1, 0));
    Result := 1;
end;



function ENGINE_set_RAND(e : PENGINE;const rand_meth : PRAND_METHOD):integer;
begin
    e.rand_meth := rand_meth;
    Result := 1;
end;


procedure engine_unregister_all_RAND;
begin
    engine_table_cleanup(@rand_table);
end;



function ENGINE_set_default_RAND( e : PENGINE):integer;
begin
    if e.rand_meth <> nil then
       Exit(engine_table_register(@rand_table,
                                     engine_unregister_all_RAND, e,
                                     @dummy_nid, 1, 1));
    Result := 1;
end;



function ENGINE_get_RAND(const e : PENGINE):PRAND_METHOD;
begin
    Result := e.rand_meth;
end;


function ENGINE_get_default_RAND:PENGINE;
begin
    Result := ossl_engine_table_select(@rand_table, dummy_nid, 'OPENSSL_FILE', 0{OPENSSL_LINE});
end;


end.
