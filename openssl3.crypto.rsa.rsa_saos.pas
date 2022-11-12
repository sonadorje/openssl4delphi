unit openssl3.crypto.rsa.rsa_saos;

interface
uses OpenSSL.Api;


function RSA_sign_ASN1_OCTET_STRING(&type : integer;const m : PByte; m_len : uint32; sigret : PByte; siglen : Puint32; rsa : PRSA):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.asn1.tasn_typ,
     OpenSSL3.crypto.rsa.rsa_crpt;

function RSA_sign_ASN1_OCTET_STRING(&type : integer;const m : PByte; m_len : uint32; sigret : PByte; siglen : Puint32; rsa : PRSA):integer;
var
  sig : TASN1_OCTET_STRING;
  i, j, ret : integer;
  p, s : PByte;
begin
    ret := 1;
    sig.&type := V_ASN1_OCTET_STRING;
    sig.length := m_len;
    sig.data := PByte( m);

    i := i2d_ASN1_OCTET_STRING(@sig, nil);
    j := RSA_size(rsa);
    if i > (j - RSA_PKCS1_PADDING_SIZE ) then
    begin
        ERR_raise(ERR_LIB_RSA, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
        Exit(0);
    end;
    s := OPENSSL_malloc(Uint32(j) + 1);
    if s = nil then
    begin
        ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    p := s;
    i2d_ASN1_OCTET_STRING(@sig, @p);
    i := RSA_private_encrypt(i, s, sigret, rsa, RSA_PKCS1_PADDING);
    if i <= 0 then
      ret := 0
    else
      siglen^ := i;
    OPENSSL_clear_free(Pointer(s), Uint32 (j) + 1);
    Result := ret;
end;




end.
