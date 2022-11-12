unit OpenSSL3.crypto.rsa_mp;

interface
uses OpenSSL.Api;

function ossl_rsa_multip_calc_product( rsa : PRSA):integer;
procedure ossl_rsa_multip_info_free( pinfo : PRSA_PRIME_INFO);
procedure ossl_rsa_multip_info_free_ex( pinfo : PRSA_PRIME_INFO);
function ossl_rsa_multip_cap( bits : integer):integer;


implementation
uses openssl3.crypto.rsa.rsa_lib, openssl3.crypto.rsa_local,
     openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.bn.bn_lib, openssl3.crypto.bn.bn_mul;






function ossl_rsa_multip_cap( bits : integer):integer;
var
  cap : integer;
begin
    cap := 5;
    if bits < 1024 then
      cap := 2
    else if (bits < 4096) then
        cap := 3
    else if (bits < 8192) then
        cap := 4;
    if cap > RSA_MAX_PRIME_NUM then
       cap := RSA_MAX_PRIME_NUM;
    Result := cap;
end;

procedure ossl_rsa_multip_info_free_ex( pinfo : PRSA_PRIME_INFO);
begin
    { free pp and pinfo only }
    BN_clear_free(pinfo.pp);
    OPENSSL_free(Pointer(pinfo));
end;




procedure ossl_rsa_multip_info_free( pinfo : PRSA_PRIME_INFO);
begin
    { free a RSA_PRIME_INFO structure }
    BN_clear_free(pinfo.r);
    BN_clear_free(pinfo.d);
    BN_clear_free(pinfo.t);
    ossl_rsa_multip_info_free_ex(pinfo);
end;




function ossl_rsa_multip_calc_product( rsa : PRSA):integer;
var
  pinfo : PRSA_PRIME_INFO;

  p1, p2 : PBIGNUM;

  ctx : PBN_CTX;

  i, rv,ex_primes : integer;
  label _err;
begin
    p1 := nil;
p2 := nil;
    ctx := nil;
    rv := 0;
    ex_primes := sk_RSA_PRIME_INFO_num(rsa.prime_infos);
    if ex_primes <= 0 then
    begin
        { invalid }
        goto _err ;
    end;
    ctx := BN_CTX_new( );
    if ctx =  nil then
        goto _err ;
    { calculate pinfo.pp = p * q for first 'extra' prime }
    p1 := rsa.p;
    p2 := rsa.q;
    for i := 0 to ex_primes-1 do
    begin
        pinfo := sk_RSA_PRIME_INFO_value(rsa.prime_infos, i);
        if pinfo.pp = nil then
        begin
            pinfo.pp := BN_secure_new();
            if pinfo.pp = nil then goto _err ;
        end;
        if  0>= BN_mul(pinfo.pp, p1, p2, ctx )then
            goto _err ;
        { save previous one }
        p1 := pinfo.pp;
        p2 := pinfo.r;
    end;
    rv := 1;
 _err:
    BN_CTX_free(ctx);
    Result := rv;
end;


end.
