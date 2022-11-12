unit OpenSSL3.crypto.ct.ct_x509v3;

interface
uses OpenSSL.Api;

 function x509_ext_d2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : long):Pstack_st_SCT;
 function set_sct_list_source( s : Pstack_st_SCT; source : sct_source_t):integer;
 function i2r_SCT_LIST( method : PX509V3_EXT_METHOD; sct_list : Pstack_st_SCT; _out : PBIO; indent : integer):integer;
 function i2s_poison(const method : PX509V3_EXT_METHOD; val : Pointer):PUTF8Char;
 function s2i_poison(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):Pointer;
 function ocsp_ext_d2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : long):Pstack_st_SCT;

var
   ossl_v3_ct_scts: array[0..2] of TX509V3_EXT_METHOD;

implementation

uses OpenSSL3.crypto.ct.ct_sct, OpenSSL3.crypto.ct.ct_oct,
     openssl3.crypto.o_str,
     OpenSSL3.crypto.ct.ct_prn, openssl3.crypto.asn1.tasn_typ,
     openssl3.include.openssl.ct;






function ocsp_ext_d2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : long):Pstack_st_SCT;
var
  s : Pstack_st_SCT;
begin
    s := d2i_SCT_LIST(a, pp, len);
    if set_sct_list_source(s, SCT_SOURCE_OCSP_STAPLED_RESPONSE) <> 1  then
    begin
        SCT_LIST_free(s);
        a^ := nil;
        Exit(nil);
    end;
    Result := s;
end;



function i2s_poison(const method : PX509V3_EXT_METHOD; val : Pointer):PUTF8Char;
begin
    OPENSSL_strdup(Result ,'NULL' );
end;


function s2i_poison(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const str : PUTF8Char):Pointer;
begin
   Result := ASN1_NULL_new();
end;

function i2r_SCT_LIST( method : PX509V3_EXT_METHOD; sct_list : Pstack_st_SCT; _out : PBIO; indent : integer):integer;
begin
    SCT_LIST_print(sct_list, _out, indent, ' '#10 , nil);
    Result := 1;
end;

function set_sct_list_source( s : Pstack_st_SCT; source : sct_source_t):integer;
var
  i, res : integer;
begin
    if s <> nil then
    begin
        for i := 0 to sk_SCT_num(s)-1 do
        begin
            res := SCT_set_source(sk_SCT_value(s, i), source);
            if res <> 1 then
            begin
                Exit(0);
            end;
        end;
    end;
    Result := 1;
end;




function x509_ext_d2i_SCT_LIST(a : PPstack_st_SCT;const pp : PPByte; len : long):Pstack_st_SCT;
var
  s : Pstack_st_SCT;
begin
     s := d2i_SCT_LIST(a, pp, len);
     if set_sct_list_source(s, SCT_SOURCE_X509V3_EXTENSION) <> 1  then
     begin
         SCT_LIST_free(s);
         a^ := nil;
         Exit(nil);
     end;
     Result := s;
end;

initialization
  // X509v3 extension in certificates that contains SCTs */
    ossl_v3_ct_scts[0] := get_V3_EXT_METHOD( NID_ct_precert_scts, 0,
    nil, nil,
    PX509V3_EXT_FREE(@SCT_LIST_free)^,
    PX509V3_EXT_D2I(@x509_ext_d2i_SCT_LIST)^,
    PX509V3_EXT_I2D(@i2d_SCT_LIST)^,
    nil, nil,
    nil, nil,
    PX509V3_EXT_I2R(@i2r_SCT_LIST)^, nil,
    nil );

    // X509v3 extension to mark a certificate as a pre-certificate */
     ossl_v3_ct_scts[1] := get_V3_EXT_METHOD( NID_ct_precert_poison, 0, ASN1_NULL_it,
    nil, nil, nil, nil,
    i2s_poison, s2i_poison,
    nil, nil,
    nil, nil,
    nil );

    // OCSP extension that contains SCTs */
     ossl_v3_ct_scts[2] := get_V3_EXT_METHOD( NID_ct_cert_scts, 0, nil,
    nil, PX509V3_EXT_FREE(@SCT_LIST_free)^,
    PX509V3_EXT_D2I(@ocsp_ext_d2i_SCT_LIST)^, PX509V3_EXT_I2D(@i2d_SCT_LIST)^,
    nil, nil,
    nil, nil,
    PX509V3_EXT_I2R(@i2r_SCT_LIST)^, nil,
    nil )
end.
