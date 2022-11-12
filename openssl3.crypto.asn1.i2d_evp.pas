unit openssl3.crypto.asn1.i2d_evp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses openssl.api;

type
  type_and_structure_st = record

    output_type,
    output_structure : PUTF8Char;
  end;
  Ptype_and_structure_st = ^type_and_structure_st;

function i2d_provided(const a : PEVP_PKEY; selection : integer;{const} output_info: Ptype_and_structure_st; pp : PPByte):integer;
function i2d_KeyParams(const a : PEVP_PKEY; pp : PPByte):integer;
function i2d_KeyParams_bio(bp : PBIO;const pkey : PEVP_PKEY):integer;
function i2d_PrivateKey(const a : Pointer; pp : PPByte):integer;
function i2d_PublicKey(const a : PEVP_PKEY; pp : PPByte):integer;

implementation
uses openssl3.crypto.encode_decode.encoder_pkey,     openssl3.crypto.encode_decode.encoder_lib,
     openssl3.crypto.encode_decode.encoder_meth,     openssl3.crypto.evp.evp_pkey,
     openssl3.crypto.asn1.p8_pkey,                   openssl3.crypto.evp.p_lib,
     OpenSSL3.crypto.rsa.rsa_asn1,                   openssl3.crypto.evp.p_legacy,
     openssl3.crypto.dsa.dsa_asn1,                   openssl3.crypto.ec.ec_asn1,
     openssl3.crypto.evp, OpenSSL3.Err,              openssl3.crypto.asn1.a_i2d_fp ;

function i2d_provided(const a : PEVP_PKEY; selection : integer;{const} output_info: Ptype_and_structure_st; pp : PPByte):integer;
var
    ctx        : POSSL_ENCODER_CTX;
    ret        : integer;
    len        : size_t;
    pp_was_null : integer;
begin
    ctx := nil;
    ret := -1;
    while (ret = -1)  and  (output_info.output_type <> nil) do
    begin

        {
         * The i2d_ calls don't take a boundary length for *pp.  However,
         * OSSL_ENCODER_to_data needs one, so we make one up.  Because
         * OSSL_ENCODER_to_data decrements this number by the amount of
         * bytes written, we need to calculate the length written further
         * down, when pp <> nil.
         }
        len := INT_MAX;
        pp_was_null := int( (pp = nil)  or  (pp^ = nil));
        ctx := OSSL_ENCODER_CTX_new_for_pkey(a, selection,
                                            output_info.output_type,
                                            output_info.output_structure,
                                            nil);
        if ctx = nil then Exit(-1);
        if OSSL_ENCODER_to_data(ctx, pp, @len) > 0 then
        begin
            if pp_was_null > 0 then
                ret := int(len)
            else
                ret := INT_MAX - int(len);
        end;
        OSSL_ENCODER_CTX_free(ctx);
        ctx := nil;
        Inc(output_info);
    end;
    if ret = -1 then
       ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE);
    Result := ret;
end;


function i2d_KeyParams(const a : PEVP_PKEY; pp : PPByte):integer;
const
  output_info : array[0..1] of type_and_structure_st = (
    (output_type: 'DER'; output_structure :'type-specific'),
    (output_type: nil; output_structure :nil));

begin
    if evp_pkey_is_provided(a)  then
    begin

        Exit(i2d_provided(a, EVP_PKEY_KEY_PARAMETERS, @output_info, pp));
    end;
    if (a.ameth <> nil)  and  (Assigned(a.ameth.param_encode)) then
       Exit(a.ameth.param_encode(a, pp));
    ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE);
    Result := -1;
end;


function i2d_KeyParams_bio(bp : PBIO;const pkey : PEVP_PKEY):integer;
var
  p1: Pointer;
begin
    if Boolean(1) then
       Exit(ASN1_i2d_bio(@i2d_KeyParams, bp, pkey))
    else
       Exit(ASN1_i2d_bio(nil, bp, PEVP_PKEY(0)));

    //Result := ASN1_i2d_bio_of(EVP_PKEY, i2d_KeyParams, bp, pkey);
end;


function i2d_PrivateKey(const a : Pointer; pp : PPByte):integer;
const
  output_info : array[0..2] of type_and_structure_st = (
    (output_type: 'DER'; output_structure :'type-specific'),
    (output_type: 'DER'; output_structure :'PrivateKeyInfo'),
    (output_type: nil; output_structure :nil));
var
   p8 : PPKCS8_PRIV_KEY_INFO;
   ret : integer;
begin
    if evp_pkey_is_provided(a) then
    begin
       Exit(i2d_provided(a, EVP_PKEY_KEYPAIR, @output_info, @pp));
    end;
    if (PEVP_PKEY(a).ameth <> nil)  and  (Assigned(PEVP_PKEY(a).ameth.old_priv_encode)) then
    begin
        Exit(PEVP_PKEY(a).ameth.old_priv_encode(a, @pp));
    end;
    if (PEVP_PKEY(a).ameth <> nil)  and  (Assigned(PEVP_PKEY(a).ameth.priv_encode)) then
    begin
        p8 := EVP_PKEY2PKCS8(a);
        ret := 0;
        if p8 <> nil then
        begin
            ret := i2d_PKCS8_PRIV_KEY_INFO(p8, pp);
            PKCS8_PRIV_KEY_INFO_free(p8);
        end;
        Exit(ret);
    end;
    ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
    Result := -1;
end;


function i2d_PublicKey(const a : PEVP_PKEY; pp : PPByte):integer;
 const output_info: array[0..2] of type_and_structure_st = (
   (output_type:'DER'; output_structure :'type-specific'),
   (output_type:'blob'; output_structure :nil ),
   { for EC }
   (output_type: nil; output_structure :nil));

begin
    if evp_pkey_is_provided(a) then
    begin

        Exit(i2d_provided(a, EVP_PKEY_PUBLIC_KEY, @output_info, @pp));
    end;
    case (EVP_PKEY_get_base_id(a)) of
        EVP_PKEY_RSA:
            Exit(i2d_RSAPublicKey(EVP_PKEY_get0_RSA(a), pp));
    {$IFNDEF OPENSSL_NO_DSA}
        EVP_PKEY_DSA:
            Exit(i2d_DSAPublicKey(EVP_PKEY_get0_DSA(a), pp));
    {$ENDIF}
    {$IFNDEF OPENSSL_NO_EC}
        EVP_PKEY_EC:
            Exit(i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(a), pp));
    {$ENDIF}
        else
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
            Exit(-1);
        end;
    end;
end;


end.
