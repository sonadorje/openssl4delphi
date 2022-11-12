unit openssl3.crypto.engine.tb_cipher;

interface
uses OpenSSL.Api;

procedure ENGINE_unregister_ciphers( e : PENGINE);
  procedure engine_unregister_all_ciphers;
  function ENGINE_register_ciphers( e : PENGINE):integer;
  procedure ENGINE_register_all_ciphers;
  function ENGINE_set_default_ciphers( e : PENGINE):integer;
  function ENGINE_get_cipher_engine( nid : integer):PENGINE;
  function ENGINE_get_cipher( e : PENGINE; nid : integer):PEVP_CIPHER;
  function ENGINE_get_ciphers(const e : PENGINE):TENGINE_CIPHERS_PTR;
  function ENGINE_set_ciphers( e : PENGINE; f : TENGINE_CIPHERS_PTR):integer;
  function ENGINE_set_default_digests( e : PENGINE):integer;
  procedure engine_unregister_all_digests;



var
  cipher_table: PENGINE_TABLE  = nil;
  digest_table: PENGINE_TABLE = nil;

implementation

uses openssl3.crypto.engine.eng_table, openssl3.crypto.engine.eng_list,
     OpenSSL3.Err;




procedure engine_unregister_all_digests;
begin
    engine_table_cleanup(@digest_table);
end;




function ENGINE_set_default_digests( e : PENGINE):integer;
var
    nids     : PInteger;
    num_nids : integer;
begin
    if Assigned(e.digests) then
    begin
        num_nids := e.digests(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@digest_table,
                                         engine_unregister_all_digests, e,
                                         nids, num_nids, 1));
    end;
    Result := 1;
end;

procedure ENGINE_unregister_ciphers( e : PENGINE);
begin
    engine_table_unregister(@cipher_table, e);
end;


procedure engine_unregister_all_ciphers;
begin
    engine_table_cleanup(@cipher_table);
end;


function ENGINE_register_ciphers( e : PENGINE):integer;
var
  num_nids : integer;
  nids: PInteger;
begin
    if Assigned(e.ciphers) then
    begin
        num_nids := e.ciphers(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@cipher_table,
                                         engine_unregister_all_ciphers, e,
                                         nids, num_nids, 0));
    end;
    Result := 1;
end;


procedure ENGINE_register_all_ciphers;
var
  e : PENGINE;
begin
    e := ENGINE_get_first();
    while e <> nil do
    begin
       ENGINE_register_ciphers(e);
       e := ENGINE_get_next(e);
    end;
end;


function ENGINE_set_default_ciphers( e : PENGINE):integer;
var
  num_nids : integer;
  nids: Pinteger;
begin
    if Assigned(e.ciphers) then begin
        num_nids := e.ciphers(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@cipher_table,
                                         engine_unregister_all_ciphers, e,
                                         nids, num_nids, 1));
    end;
    Result := 1;
end;


function ENGINE_get_cipher_engine( nid : integer):PENGINE;
begin
    Exit(ossl_engine_table_select(@cipher_table, nid,
                                    'OPENSSL_FILE', 0{OPENSSL_LINE}));
end;


function ENGINE_get_cipher( e : PENGINE; nid : integer):PEVP_CIPHER;
var
  ret : PEVP_CIPHER;

  fn : TENGINE_CIPHERS_PTR;
begin
    fn := ENGINE_get_ciphers(e);
    if (not Assigned(fn))  or  (0>= fn(e, @ret, nil, nid)) then  begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_CIPHER);
        Exit(nil);
    end;
    Result := ret;
end;


function ENGINE_get_ciphers(const e : PENGINE):TENGINE_CIPHERS_PTR;
begin
    Result := e.ciphers;
end;


function ENGINE_set_ciphers( e : PENGINE; f : TENGINE_CIPHERS_PTR):integer;
begin
    e.ciphers := f;
    Result := 1;
end;

end.
