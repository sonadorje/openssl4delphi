unit directory_win;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses

  Windows,  OpenSSL.Api;

function OPENSSL_DIR_read(ctx : PPOPENSSL_DIR_CTX;const directory : PUTF8Char):PUTF8Char;
function OPENSSL_DIR_end( ctx : PPOPENSSL_DIR_CTX):integer;

implementation
uses OpenSSL3.Err, libc.error;

function OPENSSL_DIR_read(ctx : PPOPENSSL_DIR_CTX;const directory : PUTF8Char):PUTF8Char;
var
  wdir : PChar;
  index : size_t;
  s :AnsiString;
  len_0, len : size_t;
begin
  if (ctx = nil)  or  (directory = nil) then
  begin
    _errno := EINVAL;
    Exit(0);
  end;
  _errno := 0;
  if ctx^ = nil then
  begin
    ctx^ := malloc(sizeof(TOPENSSL_DIR_CTX));
    if ctx^ = nil then
    begin
      _errno := ENOMEM;
      Exit(0);
    end;
    memset( ctx^, 0, sizeof(TOPENSSL_DIR_CTX));
    if sizeof(WideChar) <> sizeof(char)  then
    begin
      wdir := nil;
      { len_0 denotes string length *with* trailing 0 }
      index := 0; len_0 := Length(directory) + 1;
      wdir := (malloc(len_0 * sizeof(WideChar)));
      if wdir = nil then
      begin
        free(ctx^);
        ctx^ := nil;
        _errno := ENOMEM;
        Exit(0);
      end;
      s := directory;
      if 0>= MultiByteToWideChar(CP_ACP, 0, PAnsiChar(s), len_0, PwideChar(wdir),
                               len_0) then
      begin
        for index := 0 to len_0-1 do
        begin
          wdir[index] := WideCHAR(directory[index]);
        end;
      end;
      ctx^.handle := FindFirstFile(wdir, (ctx^).ctx);
      free(wdir);
    end
    else
    begin
      ctx^.handle := FindFirstFile({$IFNDEF FPC}PWideChar{$ELSE}PAnsiChar{$ENDIF}(directory), ctx^.ctx);
    end;
    if ctx^.handle = INVALID_HANDLE_VALUE then
    begin
      free( ctx^);
      ctx^ := nil;
      _errno := EINVAL;
      Exit(0);
    end;
  end
  else
  begin
    if FindNextFile(ctx^.handle, ctx^.ctx) = FALSE then
    begin
      Exit(0);
    end;
  end;
  if sizeof(WideChar) <> sizeof(UTF8char)  then
  begin
    wdir := @ctx^.ctx.cFileName;
    len_0 := 0;
    while (wdir[len_0] <> #0) and  (len_0 < sizeof(ctx^.entry_name) - 1) do
    begin
      Inc(len_0);
    end;
    Inc(len_0);
    if 0>= WideCharToMultiByte(CP_ACP, 0, PWideChar(wdir), len_0,
                             @ctx^.entry_name, sizeof(ctx^.entry_name),
                             nil, 0) then
    begin
      for index := 0 to len_0-1 do
      begin
        ctx^.entry_name[index] := UTF8Char(wdir[index]);
      end;
    end;
  end
  else
  begin
    strncpy(ctx^.entry_name, @ctx^.ctx.cFileName,
            sizeof(ctx^.entry_name) - 1);
  end;
  len := sizeof(ctx^.entry_name);
  ctx^.entry_name[len - 1] := #0;
  Result := ctx^.entry_name;
end;


function OPENSSL_DIR_end( ctx : PPOPENSSL_DIR_CTX):integer;
begin
  if (ctx <> nil)  and  (ctx^ <> nil) then
  begin
    FindClose((ctx^).handle);
    free( ctx^);
    ctx^ := nil;
    Exit(1);
  end;
  _errno := EINVAL;
  Result := 0;
end;

end.
