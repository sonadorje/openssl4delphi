unit openssl3.crypto.getenv;

interface
uses OpenSSL.Api,
    {$IF defined(MSWINDOWS)}
        {$IFNDEF FPC}Winapi.Windows,{$ELSE}windows, {$ENDIF} libc.win,
    {$ENDIF}
     Types;

function ossl_safe_getenv(const name : PUTF8Char):PUTF8Char;

implementation
uses openssl3.crypto.mem, openssl3.crypto.uid;

function ossl_safe_getenv(const name : PUTF8Char):PUTF8Char;
var
  val : PUTF8Char;
  vallen : integer;
  namew, valw : PWideChar;
  envlen, dwFlags : DWORD;
  rsize, fsize : integer;
  curacp : cardinal;
  s: AnsiString;
begin
{$IF defined(MSWINDOWS)  and  (CP_UTF8>0)}
    if GetEnvironmentVariableW('OPENSSL_WIN32_UTF8' , nil, 0) <> 0  then
    begin
        val := nil;
        vallen := 0;
        namew := nil;
        valw := nil;
        envlen := 0;
        dwFlags := MB_ERR_INVALID_CHARS;
        curacp := GetACP();
        {
         * For the code pages listed below, dwFlags must be set to 0.
         * Otherwise, the function fails with ERROR_INVALID_FLAGS.
         }
        if (curacp = 50220)  or  (curacp = 50221)  or  (curacp = 50222)  or
           (curacp = 50225)  or  (curacp = 50227)  or  (curacp = 50229)  or
           ( (57002 <= curacp)  and  (curacp <=57011) ) or  (curacp = 65000)  or
            (curacp = 42)  then
            dwFlags := 0;
        { query for buffer len }
        s := name;
        rsize := MultiByteToWideChar(curacp, dwFlags, PAnsiChar(s), -1, nil, 0);
        { if name is valid string and can be converted to wide string }
        if rsize > 0 then
           namew := AllocMem{_malloca}(rsize * sizeof(WCHAR));
        if nil <> namew then
        begin
            { convert name to wide string }
            s := name;
            fsize := MultiByteToWideChar(curacp, dwFlags, PAnsiChar(s){name}, -1, namew, rsize);
            { if conversion is ok, then determine value string size in wchars }
            if fsize > 0 then
               envlen := GetEnvironmentVariableW(namew, nil, 0);
        end;
        if envlen > 0 then
           valw := AllocMem{_malloca}(envlen * sizeof(WCHAR));
        if nil <> valw then
        begin
            { if can get env value as wide string }
            if GetEnvironmentVariableW(namew, valw, envlen) < envlen then  begin
                { determine value string size in utf-8 }
                vallen := WideCharToMultiByte(CP_UTF8, 0, valw, -1, nil, 0,
                                             nil, nil);
            end;
        end;
        if vallen > 0 then
           val := OPENSSL_malloc(vallen);
        if nil <> val then
        begin
            { convert value string from wide to utf-8 }
            s := val;
            if (WideCharToMultiByte(CP_UTF8, 0, valw, -1, PAnsiChar(s){val}, vallen,
                                    nil, nil) = 0) then
            begin
                OPENSSL_free(Pointer(val));
                val := nil;
            end;
        end;
        if nil <> namew then FreeMem{_freea}(namew);
        if nil <> valw then FreeMem{_freea}(valw);
        Exit(val);
    end;
{$ENDIF}
{$IF defined(__GLIBC__)  and  defined(__GLIBC_PREREQ)}
{$IF __GLIBC_PREREQ(2, 17)}
#  define SECURE_GETENV
    Exit(secure_getenv(name));
{$ENDIF}
{$ENDIF}
{$IFNDEF SECURE_GETENV}
    if OPENSSL_issetugid>0 then
        Exit(nil);
    s := name;
    Exit(getenv(PAnsiChar(s)));
{$ENDIF}
end;


end.
