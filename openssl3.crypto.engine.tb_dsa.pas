unit openssl3.crypto.engine.tb_dsa;

interface
uses OpenSSL.Api;

const dummy_nid: int  = 1;

function ENGINE_set_DSA(e : PENGINE;const dsa_meth : PDSA_METHOD):integer;
 function ENGINE_get_DSA(const e : PENGINE):PDSA_METHOD;
 function ENGINE_get_default_DSA:PENGINE;
 function ENGINE_set_default_DSA( e : PENGINE):integer;
 procedure engine_unregister_all_DSA;
 function ENGINE_register_DSA( e : PENGINE):integer;



var
  dsa_table: PENGINE_TABLE  = nil;


implementation
uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.engine.eng_table;




function ENGINE_register_DSA( e : PENGINE):integer;
begin
    if Assigned(e.dsa_meth) then
       Exit(engine_table_register(@dsa_table,
                                     engine_unregister_all_DSA, e, @dummy_nid,
                                     1, 0));
    Result := 1;
end;








function ENGINE_set_DSA(e : PENGINE;const dsa_meth : PDSA_METHOD):integer;
begin
    e.dsa_meth := dsa_meth;
    Result := 1;
end;

procedure engine_unregister_all_DSA;
begin
    engine_table_cleanup(@dsa_table);
end;



function ENGINE_set_default_DSA( e : PENGINE):integer;
begin
    if e.dsa_meth <> nil then
       Exit(engine_table_register (@dsa_table,
                                   engine_unregister_all_DSA, e, @dummy_nid,
                                     1, 1));
    Result := 1;
end;


function ENGINE_get_default_DSA:PENGINE;
begin
    Exit(ossl_engine_table_select(@dsa_table, dummy_nid, nil, 0));
                                    //OPENSSL_FILE, OPENSSL_LINE));
end;



function ENGINE_get_DSA(const e : PENGINE):PDSA_METHOD;
begin
    Result := e.dsa_meth;
end;

end.
