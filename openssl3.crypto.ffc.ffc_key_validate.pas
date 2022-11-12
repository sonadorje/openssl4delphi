unit openssl3.crypto.ffc.ffc_key_validate;

interface
uses OpenSSL.Api;

function ossl_ffc_validate_public_key_partial(const params : PFFC_PARAMS; pub_key : PBIGNUM; ret : PInteger):integer;
function ossl_ffc_validate_private_key(const upper, priv : PBIGNUM; ret : PInteger):integer;
 function ossl_ffc_validate_public_key(const params : PFFC_PARAMS; pub_key : PBIGNUM; ret : PInteger):integer;

implementation
uses
  openssl3.crypto.mem, openssl3.crypto.o_str, openssl3.crypto.param_build_set,
  openssl3.crypto.ffc.ffc_dh, openssl3.crypto.params,
  openssl3.crypto.ffc.ffc_params, openssl3.crypto.bn.bn_exp,
  openssl3.crypto.bn.bn_shift,
  openssl3.crypto.bn.bn_ctx, openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_word;









function ossl_ffc_validate_public_key(const params : PFFC_PARAMS; pub_key : PBIGNUM; ret : PInteger):integer;
var
  ok : integer;

  tmp : PBIGNUM;

  ctx : PBN_CTX;
  label _err;
begin
    ok := 0;
    tmp := nil;
    ctx := nil;
    if  0>= ossl_ffc_validate_public_key_partial(params, pub_key, ret) then
        Exit(0);
    if params.q <> nil then
    begin
        ctx := BN_CTX_new_ex(nil);
        if ctx = nil then
          goto _err ;
        BN_CTX_start(ctx);
        tmp := BN_CTX_get(ctx);
        { Check pub_key^q = 1 mod p }
        if (tmp = nil)  or
           (0>= BN_mod_exp(tmp, pub_key, params.q, params.p, ctx)) then
            goto _err ;
        if  not BN_is_one(tmp) then
        begin
            ret^  := ret^  or FFC_ERROR_PUBKEY_INVALID;
            goto _err ;
        end;
    end;
    ok := 1;
 _err:
    if ctx <> nil then
    begin
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    end;
    Result := ok;
end;
function ossl_ffc_validate_private_key(const upper, priv : PBIGNUM; ret : PInteger):integer;
var
  ok : int;
  label _err;
begin
    ok := (0);
    ret^ := 0;
    if BN_cmp(priv, BN_value_one() ) < 0then
    begin
        ret^  := ret^  or FFC_ERROR_PRIVKEY_TOO_SMALL;
        goto _err ;
    end;
    if BN_cmp(priv, upper) >= 0 then
    begin
        ret^  := ret^  or FFC_ERROR_PRIVKEY_TOO_LARGE;
        goto _err ;
    end;
    ok := 1;
_err:
    Result := ok;
end;

function ossl_ffc_validate_public_key_partial(const params : PFFC_PARAMS; pub_key : PBIGNUM; ret : PInteger):integer;
var
  ok : integer;

  tmp : PBIGNUM;

  ctx : PBN_CTX;
  label _err;
begin
    ok := 0;
    tmp := nil;
    ctx := nil;
    ret^ := 0;
    ctx := BN_CTX_new_ex(nil);
    if ctx = nil then goto _err ;
    BN_CTX_start(ctx);
    tmp := BN_CTX_get(ctx);
    { Step(1): Verify pub_key >= 2 }
    if (tmp = nil)
         or   (0>= BN_set_word(tmp, 1))  then
        goto _err ;
    if BN_cmp(pub_key, tmp)<= 0   then
    begin
        ret^  := ret^  or FFC_ERROR_PUBKEY_TOO_SMALL;
        goto _err ;
    end;
    { Step(1): Verify pub_key <=  p-2 }
    if (BN_copy(tmp, params.p)  = nil)
         or  (0>= BN_sub_word(tmp, 1)) then
        goto _err ;
    if BN_cmp(pub_key, tmp) >= 0then
    begin
        ret^  := ret^  or FFC_ERROR_PUBKEY_TOO_LARGE;
        goto _err ;
    end;
    ok := 1;
 _err:
    if ctx <> nil then
    begin
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    end;
    Result := ok;
end;





end.
