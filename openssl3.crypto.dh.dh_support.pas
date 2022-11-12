unit openssl3.crypto.dh.dh_support;

interface
uses OpenSSL.Api;

const  dhtype2id: array[0..3] of TDH_GENTYPE_NAME2ID =
(
    (name: 'group'; id:DH_PARAMGEN_TYPE_GROUP;&type:TYPE_ANY ),
    (name: 'generator'; id:DH_PARAMGEN_TYPE_GENERATOR;&type:TYPE_DH ),
    (name: 'fips186_4'; id:DH_PARAMGEN_TYPE_FIPS_186_4;&type:TYPE_DHX ),
    (name: 'fips186_2'; id:DH_PARAMGEN_TYPE_FIPS_186_2;&type:TYPE_DHX )
);

function ossl_dh_gen_type_name2id(const name : PUTF8Char; &type : integer):integer;
function ossl_dh_gen_type_id2name( id : integer):PUTF8Char;


implementation

uses
  OpenSSL3.common, openssl3.crypto.mem, openssl3.err, openssl3.crypto.dh.dh_lib,
  openssl3.crypto.ffc.ffc_params, openssl3.crypto.param_build_set,
  openssl3.crypto.ffc.ffc_backend, openssl3.crypto.dh.dh_group_params,
  openssl3.crypto.params, openssl3.crypto.bn.bn_lib;






function ossl_dh_gen_type_id2name( id : integer):PUTF8Char;
var
    i         : size_t;

begin
    for i := 0 to Length(dhtype2id) - 1 do
    begin
        if dhtype2id[i].id = id then
           Exit(dhtype2id[i].name);
    end;
    Result := nil;
end;

function ossl_dh_gen_type_name2id(const name : PUTF8Char; &type : integer):integer;
var
    i         : size_t;

begin
    for i := 0 to Length(dhtype2id)-1 do
    begin
        if ( (dhtype2id[i].&type = TYPE_ANY) or (&type = dhtype2id[i].&type ) )  and
             (strcmp(dhtype2id[i].name, name) = 0) then
            Exit(dhtype2id[i].id);
    end;
    Result := -1;
end;





end.
