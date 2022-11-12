unit openssl3.core_dispatch;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

//core_dispatch.h OSSL_CORE_MAKE_FUNC(void,core_new_error,(const OSSL_CORE_HANDLE *prov))
interface

uses OpenSSL.Api;


   
function OSSL_FUNC_core_new_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_new_error_fn;
function OSSL_FUNC_core_set_error_debug(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_set_error_debug_fn;
function OSSL_FUNC_core_vset_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_vset_error_fn;
function _OSSL_FUNC_keymgmt_export(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;

implementation


function _OSSL_FUNC_keymgmt_export(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;
begin
   Result := opf.method.Code; //OSSL_FUNC_keymgmt_export_fn *)opf.function;
end;





function OSSL_FUNC_core_vset_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_vset_error_fn;
begin
   Result := TOSSL_FUNC_core_vset_error_fn (opf._function);
end;

function OSSL_FUNC_core_set_error_debug(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_set_error_debug_fn;
begin
  RESULT := TOSSL_FUNC_core_set_error_debug_fn (opf._function);
end;


function OSSL_FUNC_core_new_error(const opf : POSSL_DISPATCH):TOSSL_FUNC_core_new_error_fn;
begin
  Result := TOSSL_FUNC_core_new_error_fn (opf._function);
end;


end.
