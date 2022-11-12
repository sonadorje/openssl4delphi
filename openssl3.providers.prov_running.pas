unit openssl3.providers.prov_running;

interface
uses openssl.api;

 procedure ossl_set_error_state(const _type : PUTF8Char);
  function ossl_prov_is_running:Boolean;

implementation


procedure ossl_set_error_state(const _type : PUTF8Char);
begin

end;


function ossl_prov_is_running:Boolean;
begin
    Result := true;
end;


end.
