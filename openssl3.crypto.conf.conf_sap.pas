unit openssl3.crypto.conf.conf_sap;

interface
uses OpenSSL.Api, SysUtils;

function ossl_config_int(const settings : POPENSSL_INIT_SETTINGS):integer;

var
  openssl_configured:int = 0;

 procedure ossl_no_config_int;

implementation


uses openssl3.crypto.conf.conf_mod;



procedure ossl_no_config_int;
begin
    openssl_configured := 1;
end;

function ossl_config_int(const settings : POPENSSL_INIT_SETTINGS):integer;
var
  ret      : integer;
  filename,
  appname  : PUTF8Char;
  flags    : Cardinal;
begin
    ret := 0;
    if openssl_configured >0 then Exit(1);
    if settings <> nil then
       filename := settings.filename
    else
       filename := nil;
    if settings <> nil then
       appname := settings.appname
    else
       appname := nil;
    if settings <> nil then
       flags := settings.flags
    else
       flags := DEFAULT_CONF_MFLAGS;
{$IFDEF OPENSSL_INIT_DEBUG}
    WriteLn(Format('OPENSSL_INIT: ossl_config_int(%s, %s, %lu)',[filename, appname, flags]));
{$ENDIF}
{$IFNDEF OPENSSL_SYS_UEFI}
    ret := CONF_modules_load_file(filename, appname, flags);
{$ENDIF}
    openssl_configured := 1;
    Result := ret;
end;


end.
