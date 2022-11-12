unit openssl3.crypto.dsa.dsa_gen;

interface
uses OpenSSL.Api;

function ossl_dsa_generate_ffc_parameters( dsa : PDSA; &type, pbits, qbits : integer; cb : PBN_GENCB):integer;

implementation
uses openssl3.crypto.ffc.ffc_params_generate;

function ossl_dsa_generate_ffc_parameters( dsa : PDSA; &type, pbits, qbits : integer; cb : PBN_GENCB):integer;
var
  ret, res : integer;
begin
    ret := 0;
{$IFNDEF FIPS_MODULE}
    if &type = DSA_PARAMGEN_TYPE_FIPS_186_2 then
       ret := ossl_ffc_params_FIPS186_2_generate(dsa.libctx, @dsa.params,
                                                 FFC_PARAM_TYPE_DSA,
                                                 pbits, qbits, @res, cb)
    else
{$ENDIF}
        ret := ossl_ffc_params_FIPS186_4_generate(dsa.libctx, @dsa.params,
                                                 FFC_PARAM_TYPE_DSA,
                                                 pbits, qbits, @res, cb);
    if ret > 0 then
       Inc(dsa.dirty_cnt);
    Result := ret;
end;


end.
