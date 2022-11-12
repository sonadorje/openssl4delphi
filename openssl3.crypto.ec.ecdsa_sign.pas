unit openssl3.crypto.ec.ecdsa_sign;

interface
 uses OpenSSL.Api;

 //same name as ecdsa_sig.ecdsa_sign
function _ECDSA_sign(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; eckey : PEC_KEY):integer;
function ECDSA_sign_ex(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32;const kinv, r : PBIGNUM; eckey : PEC_KEY):integer;
function ECDSA_do_sign(const dgst : PByte; dlen : integer; eckey : PEC_KEY):PECDSA_SIG;
function ECDSA_do_sign_ex(const dgst : PByte; dlen : integer;const kinv, rp : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;

implementation
uses OpenSSL3.Err;






function ECDSA_do_sign_ex(const dgst : PByte; dlen : integer;const kinv, rp : PBIGNUM; eckey : PEC_KEY):PECDSA_SIG;
begin
    if Assigned(eckey.meth.sign_sig) then
       Exit(eckey.meth.sign_sig(dgst, dlen, kinv, rp, eckey));
    ERR_raise(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
    Result := nil;
end;



function ECDSA_do_sign(const dgst : PByte; dlen : integer; eckey : PEC_KEY):PECDSA_SIG;
begin
    Result := ECDSA_do_sign_ex(dgst, dlen, nil, nil, eckey);
end;

function ECDSA_sign_ex(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32;const kinv, r : PBIGNUM; eckey : PEC_KEY):integer;
begin
    if Assigned(eckey.meth.sign) then
       Exit(eckey.meth.sign(_type, dgst, dlen, sig, siglen, kinv, r, eckey));
    ERR_raise(ERR_LIB_EC, EC_R_OPERATION_NOT_SUPPORTED);
    Result := 0;
end;



function _ECDSA_sign(_type : integer;const dgst : PByte; dlen : integer; sig : PByte; siglen : Puint32; eckey : PEC_KEY):integer;
begin
    Result := ECDSA_sign_ex(_type, dgst, dlen, sig, siglen, nil, nil, eckey);
end;


end.
