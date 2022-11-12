unit openssl3.crypto.ec.ec_support;

interface
uses OpenSSL.Api;

type
  ec_name2nid_st = record
    name: PUTF8Char;
    nid: int;
  end;
  TEC_NAME2NID = ec_name2nid_st;

const
    curve_list: array[0..81] of TEC_NAME2NID = (
    (* prime field curves *)
    (* secg curves *)
    (name: 'secp112r1'; nid: NID_secp112r1 ),
    (name: 'secp112r2'; nid: NID_secp112r2 ),
    (name: 'secp128r1'; nid: NID_secp128r1 ),
    (name: 'secp128r2'; nid: NID_secp128r2 ),
    (name: 'secp160k1'; nid: NID_secp160k1 ),
    (name: 'secp160r1'; nid: NID_secp160r1 ),
    (name: 'secp160r2'; nid: NID_secp160r2 ),
    (name: 'secp192k1'; nid: NID_secp192k1 ),
    (name: 'secp224k1'; nid: NID_secp224k1 ),
    (name: 'secp224r1'; nid: NID_secp224r1 ),
    (name: 'secp256k1'; nid: NID_secp256k1 ),
    (name: 'secp384r1'; nid: NID_secp384r1 ),
    (name: 'secp521r1'; nid: NID_secp521r1 ),
    (* X9.62 curves *)
    (name: 'prime192v1'; nid: NID_X9_62_prime192v1 ),
    (name: 'prime192v2'; nid: NID_X9_62_prime192v2 ),
    (name: 'prime192v3'; nid: NID_X9_62_prime192v3 ),
    (name: 'prime239v1'; nid: NID_X9_62_prime239v1 ),
    (name: 'prime239v2'; nid: NID_X9_62_prime239v2 ),
    (name: 'prime239v3'; nid: NID_X9_62_prime239v3 ),
    (name: 'prime256v1'; nid: NID_X9_62_prime256v1 ),
    (* characteristic two field curves *)
    (* NIST/SECG curves *)
    (name: 'sect113r1'; nid: NID_sect113r1 ),
    (name: 'sect113r2'; nid: NID_sect113r2 ),
    (name: 'sect131r1'; nid: NID_sect131r1 ),
    (name: 'sect131r2'; nid: NID_sect131r2 ),
    (name: 'sect163k1'; nid: NID_sect163k1 ),
    (name: 'sect163r1'; nid: NID_sect163r1 ),
    (name: 'sect163r2'; nid: NID_sect163r2 ),
    (name: 'sect193r1'; nid: NID_sect193r1 ),
    (name: 'sect193r2'; nid: NID_sect193r2 ),
    (name: 'sect233k1'; nid: NID_sect233k1 ),
    (name: 'sect233r1'; nid: NID_sect233r1 ),
    (name: 'sect239k1'; nid: NID_sect239k1 ),
    (name: 'sect283k1'; nid: NID_sect283k1 ),
    (name: 'sect283r1'; nid: NID_sect283r1 ),
    (name: 'sect409k1'; nid: NID_sect409k1 ),
    (name: 'sect409r1'; nid: NID_sect409r1 ),
    (name: 'sect571k1'; nid: NID_sect571k1 ),
    (name: 'sect571r1'; nid: NID_sect571r1 ),
    (* X9.62 curves *)
    (name: 'c2pnb163v1'; nid: NID_X9_62_c2pnb163v1 ),
    (name: 'c2pnb163v2'; nid: NID_X9_62_c2pnb163v2 ),
    (name: 'c2pnb163v3'; nid: NID_X9_62_c2pnb163v3 ),
    (name: 'c2pnb176v1'; nid: NID_X9_62_c2pnb176v1 ),
    (name: 'c2tnb191v1'; nid: NID_X9_62_c2tnb191v1 ),
    (name: 'c2tnb191v2'; nid: NID_X9_62_c2tnb191v2 ),
    (name: 'c2tnb191v3'; nid: NID_X9_62_c2tnb191v3 ),
    (name: 'c2pnb208w1'; nid: NID_X9_62_c2pnb208w1 ),
    (name: 'c2tnb239v1'; nid: NID_X9_62_c2tnb239v1 ),
    (name: 'c2tnb239v2'; nid: NID_X9_62_c2tnb239v2 ),
    (name: 'c2tnb239v3'; nid: NID_X9_62_c2tnb239v3 ),
    (name: 'c2pnb272w1'; nid: NID_X9_62_c2pnb272w1 ),
    (name: 'c2pnb304w1'; nid: NID_X9_62_c2pnb304w1 ),
    (name: 'c2tnb359v1'; nid: NID_X9_62_c2tnb359v1 ),
    (name: 'c2pnb368w1'; nid: NID_X9_62_c2pnb368w1 ),
    (name: 'c2tnb431r1'; nid: NID_X9_62_c2tnb431r1 ),
    (*
     * the WAP/WTLS curves [unlike SECG, spec has its own OIDs for curves
     * from X9.62]
     *)
    (name: 'wap-wsg-idm-ecid-wtls1'; nid: NID_wap_wsg_idm_ecid_wtls1 ),
    (name: 'wap-wsg-idm-ecid-wtls3'; nid: NID_wap_wsg_idm_ecid_wtls3 ),
    (name: 'wap-wsg-idm-ecid-wtls4'; nid: NID_wap_wsg_idm_ecid_wtls4 ),
    (name: 'wap-wsg-idm-ecid-wtls5'; nid: NID_wap_wsg_idm_ecid_wtls5 ),
    (name: 'wap-wsg-idm-ecid-wtls6'; nid: NID_wap_wsg_idm_ecid_wtls6 ),
    (name: 'wap-wsg-idm-ecid-wtls7'; nid: NID_wap_wsg_idm_ecid_wtls7 ),
    (name: 'wap-wsg-idm-ecid-wtls8'; nid: NID_wap_wsg_idm_ecid_wtls8 ),
    (name: 'wap-wsg-idm-ecid-wtls9'; nid: NID_wap_wsg_idm_ecid_wtls9 ),
    (name: 'wap-wsg-idm-ecid-wtls10'; nid: NID_wap_wsg_idm_ecid_wtls10 ),
    (name: 'wap-wsg-idm-ecid-wtls11'; nid: NID_wap_wsg_idm_ecid_wtls11 ),
    (name: 'wap-wsg-idm-ecid-wtls12'; nid: NID_wap_wsg_idm_ecid_wtls12 ),
    (* IPSec curves *)
    (name: 'Oakley-EC2N-3'; nid: NID_ipsec3 ),
    (name: 'Oakley-EC2N-4'; nid: NID_ipsec4 ),
    (* brainpool curves *)
    (name: 'brainpoolP160r1'; nid: NID_brainpoolP160r1 ),
    (name: 'brainpoolP160t1'; nid: NID_brainpoolP160t1 ),
    (name: 'brainpoolP192r1'; nid: NID_brainpoolP192r1 ),
    (name: 'brainpoolP192t1'; nid: NID_brainpoolP192t1 ),
    (name: 'brainpoolP224r1'; nid: NID_brainpoolP224r1 ),
    (name: 'brainpoolP224t1'; nid: NID_brainpoolP224t1 ),
    (name: 'brainpoolP256r1'; nid: NID_brainpoolP256r1 ),
    (name: 'brainpoolP256t1'; nid: NID_brainpoolP256t1 ),
    (name: 'brainpoolP320r1'; nid: NID_brainpoolP320r1 ),
    (name: 'brainpoolP320t1'; nid: NID_brainpoolP320t1 ),
    (name: 'brainpoolP384r1'; nid: NID_brainpoolP384r1 ),
    (name: 'brainpoolP384t1'; nid: NID_brainpoolP384t1 ),
    (name: 'brainpoolP512r1'; nid: NID_brainpoolP512r1 ),
    (name: 'brainpoolP512t1'; nid: NID_brainpoolP512t1 ),
    (* SM2 curve *)
    (name: 'SM2'; nid: NID_sm2 )
);
 nist_curves: array[0..14] of TEC_NAME2NID = (
    (name: 'B-163'; nid:NID_sect163r2),
    (name: 'B-233'; nid:NID_sect233r1),
    (name: 'B-283'; nid:NID_sect283r1),
    (name: 'B-409'; nid:NID_sect409r1),
    (name: 'B-571'; nid:NID_sect571r1),
    (name: 'K-163'; nid:NID_sect163k1),
    (name: 'K-233'; nid:NID_sect233k1),
    (name: 'K-283'; nid:NID_sect283k1),
    (name: 'K-409'; nid:NID_sect409k1),
    (name: 'K-571'; nid:NID_sect571k1),
    (name: 'P-192'; nid:NID_X9_62_prime192v1),
    (name: 'P-224'; nid:NID_secp224r1),
    (name: 'P-256'; nid:NID_X9_62_prime256v1),
    (name: 'P-384'; nid:NID_secp384r1),
    (name: 'P-521'; nid:NID_secp521r1)
);

 function OSSL_EC_curve_nid2name( nid : integer):PUTF8Char;
 function ossl_ec_curve_name2nid(const name : PUTF8Char):integer;
 function ossl_ec_curve_nist2nid_int(const name : PUTF8Char):integer;
 function ossl_ec_curve_nid2nist_int( nid : integer):PUTF8Char;

implementation


function ossl_ec_curve_nid2nist_int( nid : integer):PUTF8Char;
var
    i           : size_t;
begin
    for i := 0 to Length(nist_curves)-1 do
    begin
        if nist_curves[i].nid = nid then
           Exit(nist_curves[i].name);
    end;
    Result := nil;
end;







function ossl_ec_curve_nist2nid_int(const name : PUTF8Char):integer;
var
    i           : size_t;

begin
    for i := 0 to Length(nist_curves)-1 do
    begin
        if strcmp(nist_curves[i].name, name ) = 0 then
            Exit(nist_curves[i].nid);
    end;
    Result := NID_undef;
end;

function ossl_ec_curve_name2nid(const name : PUTF8Char):integer;
var
    i          : size_t;

    nid        : integer;

begin
    if name <> nil then
    begin
        nid := ossl_ec_curve_nist2nid_int(name);
        if nid <> NID_undef then
            Exit(nid);
        for i := 0 to Length(curve_list)-1 do
        begin
            if strcasecmp(curve_list[i].name, name) = 0  then
                Exit(curve_list[i].nid);
        end;
    end;
    Result := NID_undef;
end;

function OSSL_EC_curve_nid2name( nid : integer):PUTF8Char;
var
    i          : size_t;
begin
    if nid <= 0 then Exit(nil);
    for i := 0 to Length(curve_list)-1 do
    begin
        if curve_list[i].nid = nid then
           Exit(curve_list[i].name);
    end;
    Result := nil;
end;


end.
