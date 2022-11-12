unit openssl3.crypto.ec.ecdsa_vrf;

interface
uses OpenSSL.Api;

 function ECDSA_do_verify(const dgst : PByte; dgst_len : integer;const sig : PECDSA_SIG; eckey : PEC_KEY):integer;
  function _ECDSA_verify(&type : integer;const dgst : PByte; dgst_len : integer;const sigbuf : PByte; sig_len : integer; eckey : PEC_KEY):integer;

implementation
uses openssl3.err;

function ECDSA_do_verify(const dgst : PByte; dgst_len : integer;const sig : PECDSA_SIG; eckey : PEC_KEY):integer;
begin
    if Assigned(eckey.meth.verify_sig ) then
       Exit(eckey.meth.verify_sig(dgst, dgst_len, sig, eckey));
    ERR_raise(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
    Result := -1;
end;


function _ECDSA_verify(&type : integer;const dgst : PByte; dgst_len : integer;const sigbuf : PByte; sig_len : integer; eckey : PEC_KEY):integer;
begin
    if Assigned(eckey.meth.verify ) then
       Exit(eckey.meth.verify(&type, dgst, dgst_len, sigbuf, sig_len,
                                   eckey));
    ERR_raise(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
    Result := -1;
end;


end.
