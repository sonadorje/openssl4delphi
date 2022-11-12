unit openssl3.crypto.ffc.ffc_backend;

interface
uses OpenSSL.Api;

function ossl_ffc_params_fromdata(ffc : PFFC_PARAMS;const params : POSSL_PARAM):integer;

implementation
uses
  openssl3.crypto.mem, openssl3.crypto.o_str, openssl3.crypto.param_build_set,
  openssl3.crypto.ffc.ffc_dh, openssl3.crypto.params, openssl3.crypto.ffc.ffc_params,
  openssl3.crypto.bn.bn_lib;


function ossl_ffc_params_fromdata(ffc : PFFC_PARAMS;const params : POSSL_PARAM):integer;
var
  prm, param_p, param_q, param_g : POSSL_PARAM;
  p, q, g, j : PBIGNUM;
  i : integer;
  group : PDH_NAMED_GROUP;
  p1 : POSSL_PARAM;
  props : PUTF8Char;
  label _err;
begin
    p := nil;
    q := nil;
    g := nil;
    j := nil;
    if ffc = nil then Exit(0);
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if prm <> nil then
    begin
        {
         * In a no-dh build we just go straight to err because we have no
         * support for this.
         }
{$IFNDEF OPENSSL_NO_DH}
        group := nil;
        group := ossl_ffc_name_to_dh_named_group(prm.data);
        if (prm.data_type <> OSSL_PARAM_UTF8_STRING)
             or  (prm.data = nil)
             or  ( (group = nil) or
                   (0>= ossl_ffc_named_group_set_pqg(ffc, group)) ) then
{$ENDIF}
            goto _err ;
    end;
    param_p := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_g := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);
    param_q := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
    if (param_p <> nil)  and   (0>= OSSL_PARAM_get_BN(param_p, @p ))
         or  ( (param_q <> nil)  and (0>= OSSL_PARAM_get_BN(param_q, @q)) )
         or  ( (param_g <> nil)  and (0>= OSSL_PARAM_get_BN(param_g, @g))) then
        goto _err ;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_GINDEX);
    if (prm <> nil) then
    begin
        if  0>= OSSL_PARAM_get_int(prm, @i) then
            goto _err ;
        ffc.gindex := i;
    end;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_PCOUNTER);
    if prm <> nil then
    begin
        if  0>= OSSL_PARAM_get_int(prm, @i) then
            goto _err ;
        ffc.pcounter := i;
    end;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_COFACTOR);
    if (prm <> nil)  and   (0>= OSSL_PARAM_get_BN(prm, @j)) then
        goto _err ;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_H);
    if prm <> nil then
    begin
        if  0>= OSSL_PARAM_get_int(prm, @i) then
            goto _err ;
        ffc.h := i;
    end;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_SEED);
    if prm <> nil then
    begin
        if prm.data_type <> OSSL_PARAM_OCTET_STRING then
            goto _err ;
        if  0>= ossl_ffc_params_set_seed(ffc, prm.data, prm.data_size)  then
            goto _err ;
    end;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ);
    if prm <> nil then
    begin
        if  0>= OSSL_PARAM_get_int(prm, @i) then
            goto _err ;
        ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_PQ, i);
    end;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_VALIDATE_G);
    if prm <> nil then
    begin
        if  0>= OSSL_PARAM_get_int(prm, @i) then
            goto _err ;
        ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_G, i);
    end;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY);
    if prm <> nil then
    begin
        if  0>= OSSL_PARAM_get_int(prm, @i) then
            goto _err ;
        ossl_ffc_params_enable_flags(ffc, FFC_PARAM_FLAG_VALIDATE_LEGACY, i);
    end;
    prm := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST);
    if prm <> nil then
    begin
        props := nil;
        if prm.data_type <> OSSL_PARAM_UTF8_STRING then
           goto _err ;
        p1 := OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS);
        if p1 <> nil then
        begin
            if p1.data_type <> OSSL_PARAM_UTF8_STRING then
                goto _err ;
        end;
        if  0>= ossl_ffc_set_digest(ffc, prm.data, props)  then
            goto _err ;
    end;
    ossl_ffc_params_set0_pqg(ffc, p, q, g);
    ossl_ffc_params_set0_j(ffc, j);
    Exit(1);
 _err:
    BN_free(j);
    BN_free(p);
    BN_free(q);
    BN_free(g);
    Result := 0;
end;




end.
