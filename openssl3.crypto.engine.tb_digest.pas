unit openssl3.crypto.engine.tb_digest;

interface
uses OpenSSL.Api;

function ENGINE_get_digest( e : PENGINE; nid : integer):PEVP_MD;
function ENGINE_get_digest_engine( nid : integer):PENGINE;
function ENGINE_get_digests(const e : PENGINE):TENGINE_DIGESTS_PTR;
function ENGINE_register_digests( e : PENGINE):integer;
 procedure engine_unregister_all_digests;




var
  digest_table: PENGINE_TABLE  = nil;

implementation
uses OpenSSL3.Err, openssl3.crypto.engine.eng_table;





procedure engine_unregister_all_digests;
begin
    engine_table_cleanup(@digest_table);
end;

function ENGINE_register_digests( e : PENGINE):integer;
var
  num_nids : integer;
  nids: PInteger;
begin
    if Assigned(e.digests) then
    begin
        num_nids := e.digests(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@digest_table,
                                         engine_unregister_all_digests, e,
                                         nids, num_nids, 0));
    end;
    Result := 1;
end;



function ENGINE_get_digest_engine( nid : integer):PENGINE;
begin
    Exit(ossl_engine_table_select(@digest_table, nid,
                                    'OPENSSL_FILE', 0{OPENSSL_LINE}));
end;

function ENGINE_get_digests(const e : PENGINE):TENGINE_DIGESTS_PTR;
begin
    Result := e.digests;
end;



function ENGINE_get_digest( e : PENGINE; nid : integer):PEVP_MD;
var
  fn : TENGINE_DIGESTS_PTR;
  ret: PEVP_MD;
begin
    fn := ENGINE_get_digests(e);
    if (not Assigned(fn))  or  (0>= fn(e, @ret, nil, nid) )then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_DIGEST);
        Exit(nil);
    end;
    Result := ret;
end;


end.
