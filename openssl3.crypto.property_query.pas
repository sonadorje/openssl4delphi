unit openssl3.crypto.property_query;

interface
 uses OpenSSL.Api;

function ossl_property_has_optional(const query : POSSL_PROPERTY_LIST):integer;
function property_idx_cmp(const keyp, compare : Pointer):integer;
function ossl_property_get_string_value(libctx : POSSL_LIB_CTX;const prop : POSSL_PROPERTY_DEFINITION):PUTF8Char;
function ossl_property_find_property(const list : POSSL_PROPERTY_LIST; libctx : POSSL_LIB_CTX;const name : PUTF8Char):POSSL_PROPERTY_DEFINITION;

implementation
uses openssl3.crypto.property_string, openssl3.crypto.bsearch;


function ossl_property_get_string_value(libctx : POSSL_LIB_CTX;const prop : POSSL_PROPERTY_DEFINITION):PUTF8Char;
var
  value : PUTF8Char;
begin
    value := nil;
    if (prop <> nil)  and  (prop.&type = OSSL_PROPERTY_TYPE_STRING) then
       value := ossl_property_value_str(libctx, prop.v.str_val);
    Result := value;
end;

function property_idx_cmp(const keyp, compare : Pointer):integer;
var
  key : OSSL_PROPERTY_IDX;
  defn : POSSL_PROPERTY_DEFINITION;
begin
    key := POSSL_PROPERTY_IDX(keyp)^;
    defn := POSSL_PROPERTY_DEFINITION(compare);
    Result := key - defn.name_idx;
end;

function ossl_property_find_property(const list : POSSL_PROPERTY_LIST; libctx : POSSL_LIB_CTX;const name : PUTF8Char):POSSL_PROPERTY_DEFINITION;
var
  name_idx : OSSL_PROPERTY_IDX;
begin
    name_idx := ossl_property_name(libctx, name, 0 );
    if (list = nil)  or  (name = nil)
         or  (name_idx =  0) then
        Exit(nil);
    Result := ossl_bsearch(@name_idx, @list.properties[0], list.num_properties,
                           property_idx_cmp, 0);
end;

function ossl_property_has_optional(const query : POSSL_PROPERTY_LIST):integer;
begin
    Result := get_result(query.has_optional>0 , 1 , 0);
end;



end.
