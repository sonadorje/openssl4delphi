unit openssl3.crypto.engine.tb_asnmth;

interface
uses OpenSSL.Api;

type
  TENGINE_FIND_STR = record
    e : PENGINE;
    ameth : PEVP_PKEY_ASN1_METHOD;
    str : PUTF8Char;
    len : integer;
  end;
  PENGINE_FIND_STR = ^TENGINE_FIND_STR;

procedure engine_pkey_asn1_meths_free( e : PENGINE);
function ENGINE_pkey_asn1_find_str(pe : PPENGINE;const str : PUTF8Char; len : integer):PEVP_PKEY_ASN1_METHOD;
procedure look_str_cb( nid : integer; sk : Pstack_st_ENGINE; def : PENGINE; arg : Pointer);
function ENGINE_get_pkey_asn1_meth_engine( nid : integer):PENGINE;
function ENGINE_get_pkey_asn1_meth( e : PENGINE; nid : integer):PEVP_PKEY_ASN1_METHOD;
function ENGINE_get_pkey_asn1_meths(const e : PENGINE): TENGINE_PKEY_ASN1_METHS_PTR;

var
  pkey_asn1_meth_table: PENGINE_TABLE  = nil;

function ENGINE_set_default_pkey_asn1_meths( e : PENGINE):integer;
procedure engine_unregister_all_pkey_asn1_meths;
function ENGINE_register_pkey_asn1_meths( e : PENGINE):integer;

implementation


uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.asn1.ameth_lib, openssl3.crypto.engine.eng_table;




function ENGINE_register_pkey_asn1_meths( e : PENGINE):integer;
var
  num_nids : integer;
  nids: Pinteger;
begin
    if Assigned(e.pkey_asn1_meths) then
    begin
        num_nids := e.pkey_asn1_meths(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@pkey_asn1_meth_table,
                                         engine_unregister_all_pkey_asn1_meths,
                                         e, nids, num_nids, 0));
    end;
    Result := 1;
end;

procedure engine_unregister_all_pkey_asn1_meths;
begin
    engine_table_cleanup(@pkey_asn1_meth_table);
end;



function ENGINE_set_default_pkey_asn1_meths( e : PENGINE):integer;
var
  num_nids : integer;
  nids: Pinteger;
begin
    if Assigned(e.pkey_asn1_meths) then
    begin
        num_nids := e.pkey_asn1_meths(e, nil, @nids, 0);
        if num_nids > 0 then
           Exit(engine_table_register(@pkey_asn1_meth_table,
                                         engine_unregister_all_pkey_asn1_meths,
                                         e, nids, num_nids, 1));
    end;
    Result := 1;
end;

function ENGINE_get_pkey_asn1_meths(const e : PENGINE): TENGINE_PKEY_ASN1_METHS_PTR;
begin
    Result := e.pkey_asn1_meths;
end;

function ENGINE_get_pkey_asn1_meth( e : PENGINE; nid : integer):PEVP_PKEY_ASN1_METHOD;
var
  ret : PEVP_PKEY_ASN1_METHOD;
  fn : TENGINE_PKEY_ASN1_METHS_PTR;
begin
    fn := ENGINE_get_pkey_asn1_meths(e);
    if (not Assigned(fn))  or  (0>=fn(e, @ret, nil, nid)) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD);
        Exit(nil);
    end;
    Result := ret;
end;



function ENGINE_get_pkey_asn1_meth_engine( nid : integer):PENGINE;
begin
    Exit(ossl_engine_table_select(@pkey_asn1_meth_table, nid,
                                    'OPENSSL_FILE', 0{OPENSSL_LINE}));
end;

procedure look_str_cb( nid : integer; sk : Pstack_st_ENGINE; def : PENGINE; arg : Pointer);
var
  lk : PENGINE_FIND_STR;
  i : integer;
  e : PENGINE;
  ameth : PEVP_PKEY_ASN1_METHOD;
begin
    lk := arg;
    if lk.ameth <> nil then exit;
    for i := 0 to sk_ENGINE_num(sk)-1 do
    begin
        e := sk_ENGINE_value(sk, i);
        e.pkey_asn1_meths(e, @ameth, nil, nid);
        if (ameth <> nil)
                 and  (Length(ameth.pem_str) = lk.len)
                 and  (strncasecmp(ameth.pem_str, lk.str, lk.len) = 0)  then
        begin
            lk.e := e;
            lk.ameth := ameth;
            exit;
        end;
    end;
end;



function ENGINE_pkey_asn1_find_str(pe : PPENGINE;const str : PUTF8Char; len : integer):PEVP_PKEY_ASN1_METHOD;
var
  fstr : TENGINE_FIND_STR;
begin
    fstr.e := nil;
    fstr.ameth := nil;
    fstr.str := str;
    fstr.len := len;
    if 0 >= get_result(CRYPTO_THREAD_run_once(@engine_lock_init, do_engine_lock_init_ossl_) > 0,
                      do_engine_lock_init_ossl_ret_ , 0) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock ) then
        Exit(nil);
    engine_table_doall(pkey_asn1_meth_table, look_str_cb, @fstr);
    { If found obtain a structural reference to engine }
    if fstr.e <> nil then
    begin
        PostInc(fstr.e.struct_ref);
        ENGINE_REF_PRINT(fstr.e, 0, 1);
    end;
    pe^ := fstr.e;
    CRYPTO_THREAD_unlock(global_engine_lock);
    Result := fstr.ameth;
end;

procedure engine_pkey_asn1_meths_free( e : PENGINE);
var
  i : integer;

  pkm : PEVP_PKEY_ASN1_METHOD;
  pknids: PInteger;
  npknids : integer;
begin
{$POINTERMATH ON}
    if Assigned(e.pkey_asn1_meths) then
    begin
        npknids := e.pkey_asn1_meths(e, nil, @pknids, 0);
        for i := 0 to npknids-1 do
        begin
            if e.pkey_asn1_meths(e, @pkm, nil, pknids[i]) >0 then
            begin
                EVP_PKEY_asn1_free(pkm);
            end;
        end;
    end;
{$POINTERMATH OFF}
end;



end.
