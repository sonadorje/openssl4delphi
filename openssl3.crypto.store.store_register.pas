unit openssl3.crypto.store.store_register;

interface
uses OpenSSL.Api;

type
  Tdoall = procedure(p1: POSSL_STORE_LOADER);
  Tdoallarg = procedure(p1: POSSL_STORE_LOADER ; p2: Pointer);

  procedure ossl_store_destroy_loaders_int;

  function lh_OSSL_STORE_LOADER_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC):Plhash_st_OSSL_STORE_LOADER;
  procedure lh_OSSL_STORE_LOADER_free( lh : Plhash_st_OSSL_STORE_LOADER);
  procedure lh_OSSL_STORE_LOADER_flush( lh : Plhash_st_OSSL_STORE_LOADER);
  function lh_OSSL_STORE_LOADER_error( lh : Plhash_st_OSSL_STORE_LOADER):integer;
  function lh_OSSL_STORE_LOADER_num_items( lh : Plhash_st_OSSL_STORE_LOADER):Cardinal;
  procedure lh_OSSL_STORE_LOADER_node_stats_bio(const lh : Plhash_st_OSSL_STORE_LOADER; &out : PBIO);
  procedure lh_OSSL_STORE_LOADER_node_usage_stats_bio(const lh : Plhash_st_OSSL_STORE_LOADER; &out : PBIO);
  procedure lh_OSSL_STORE_LOADER_stats_bio(const lh : Plhash_st_OSSL_STORE_LOADER; &out : PBIO);
  function lh_OSSL_STORE_LOADER_get_down_load( lh : Plhash_st_OSSL_STORE_LOADER):Cardinal;
  procedure lh_OSSL_STORE_LOADER_set_down_load( lh : Plhash_st_OSSL_STORE_LOADER; dl : Cardinal);
  procedure lh_OSSL_STORE_LOADER_doall( lh : Plhash_st_OSSL_STORE_LOADER; doall : Tdoall);
  procedure lh_OSSL_STORE_LOADER_doall_arg( lh : Plhash_st_OSSL_STORE_LOADER; doallarg : Tdoallarg; arg : Pointer);

  var
     loader_register: PLHASH_st_OSSL_STORE_LOADER  = nil;
     registry_lock: PCRYPTO_RWLOCK = nil;

implementation
uses openssl3.crypto.lhash, openssl3.crypto.lh_stats, OpenSSL3.threads_none;

function lh_OSSL_STORE_LOADER_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC):Plhash_st_OSSL_STORE_LOADER;
begin
 Result := Plhash_st_OSSL_STORE_LOADER (OPENSSL_LH_new(hfn, cfn));
end;


procedure lh_OSSL_STORE_LOADER_free( lh : Plhash_st_OSSL_STORE_LOADER);
begin
 OPENSSL_LH_free(POPENSSL_LHASH (lh));
end;


procedure lh_OSSL_STORE_LOADER_flush( lh : Plhash_st_OSSL_STORE_LOADER);
begin
 OPENSSL_LH_flush(POPENSSL_LHASH (lh));
end;


function lh_OSSL_STORE_LOADER_error( lh : Plhash_st_OSSL_STORE_LOADER):integer;
begin
 Exit(OPENSSL_LH_error(POPENSSL_LHASH (lh)));
end;


function lh_OSSL_STORE_LOADER_num_items( lh : Plhash_st_OSSL_STORE_LOADER):Cardinal;
begin
 Exit(OPENSSL_LH_num_items(POPENSSL_LHASH (lh)));
end;


procedure lh_OSSL_STORE_LOADER_node_stats_bio(const lh : Plhash_st_OSSL_STORE_LOADER; &out : PBIO);
begin
 OPENSSL_LH_node_stats_bio(POPENSSL_LHASH (lh), out);
end;


procedure lh_OSSL_STORE_LOADER_node_usage_stats_bio(const lh : Plhash_st_OSSL_STORE_LOADER; &out : PBIO);
begin
 OPENSSL_LH_node_usage_stats_bio(POPENSSL_LHASH (lh), out);
end;


procedure lh_OSSL_STORE_LOADER_stats_bio(const lh : Plhash_st_OSSL_STORE_LOADER; &out : PBIO);
begin
 OPENSSL_LH_stats_bio(POPENSSL_LHASH (lh), out);
end;


function lh_OSSL_STORE_LOADER_get_down_load( lh : Plhash_st_OSSL_STORE_LOADER):Cardinal;
begin
 Exit(OPENSSL_LH_get_down_load(POPENSSL_LHASH (lh)));
end;


procedure lh_OSSL_STORE_LOADER_set_down_load( lh : Plhash_st_OSSL_STORE_LOADER; dl : Cardinal);
begin
 OPENSSL_LH_set_down_load(POPENSSL_LHASH (lh), dl);
end;


procedure lh_OSSL_STORE_LOADER_doall( lh : Plhash_st_OSSL_STORE_LOADER; doall : Tdoall);
begin
 OPENSSL_LH_doall(POPENSSL_LHASH (lh), TOPENSSL_LH_DOALL_FUNC(doall));
end;


procedure lh_OSSL_STORE_LOADER_doall_arg( lh : Plhash_st_OSSL_STORE_LOADER; doallarg : Tdoallarg; arg : Pointer);
begin
 OPENSSL_LH_doall_arg(POPENSSL_LHASH (lh), TOPENSSL_LH_DOALL_FUNCARG(doallarg), arg);
end;



procedure ossl_store_destroy_loaders_int;
begin
    lh_OSSL_STORE_LOADER_free(loader_register);
    loader_register := nil;
    CRYPTO_THREAD_lock_free(registry_lock);
    registry_lock := nil;
end;


end.
