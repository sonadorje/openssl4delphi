unit OpenSSL3.e_os;

interface
uses {$IFDEF MSWINDOWS} windows, {$ENDIF} OpenSSL.Api;

function get_last_sys_error(): Integer;
procedure set_sys_error(e: Integer);

implementation

procedure set_sys_error(e: Integer);
begin
{$IFDEF MSWINDOWS}
    SetLastError(e);
{$ELSE}
    errno=(e);
{$ENDIF}
end;

function get_last_sys_error(): Integer;
begin
{$IFDEF MSWINDOWS}
   Result := GetLastError();
{$ELSE}
   Result := errno ;
{$ENDIF}
end;

end.
