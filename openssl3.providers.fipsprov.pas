unit openssl3.providers.fipsprov;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, openssl3.core_dispatch;

procedure ERR_new();
procedure ERR_set_debug(const func : PUTF8Char);
procedure ERR_set_error(lib, reason : integer;const fmt : string);
function ERR_PACK( lib : integer; func : PUTF8Char; reason : integer):uint32;

var
  c_new_error            : TOSSL_FUNC_core_new_error_fn ;
  c_set_error_debug      : TOSSL_FUNC_core_set_error_debug_fn ;
  c_vset_error           : TOSSL_FUNC_core_vset_error_fn ;
  c_set_error_mark       : TOSSL_FUNC_core_set_error_mark_fn;
  c_clear_last_error_mark: TOSSL_FUNC_core_clear_last_error_mark_fn;

function ERR_set_mark:integer;
function ERR_clear_last_mark:integer;

implementation


function ERR_clear_last_mark:integer;
begin
    Result := c_clear_last_error_mark(nil);
end;



function ERR_set_mark:integer;
begin
    Result := c_set_error_mark(nil);
end;



function ERR_PACK( lib : integer; func : PUTF8Char; reason : integer):uint32;
begin
   result :=  ((uint32(lib)    and ERR_LIB_MASK   )  shl  ERR_LIB_OFFSET) or ((uint32(reason) and ERR_REASON_MASK))
end;



procedure ERR_set_error(lib, reason : integer;const fmt : string);
begin
    c_vset_error(nil, ERR_PACK(lib, 0, reason), fmt);
end;

procedure ERR_set_debug(const func : PUTF8Char);
begin
    c_set_error_debug(nil, func);
end;

procedure ERR_new();
begin
    c_new_error(nil);
end;

end.
