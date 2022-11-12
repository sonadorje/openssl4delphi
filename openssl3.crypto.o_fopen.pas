unit openssl3.crypto.o_fopen;
{$I config.inc}

interface
uses OpenSSL.Api, SysUtils, Classes,
     {$IFDEF MSWINDOWS}
       {$IFNDEF FPC}Winapi.Windows,{$ELSE}windows, {$ENDIF} libc.win,
     {$ENDIF}
     Types;


 function openssl_fopen(const filename: PUTF8Char; _mode: String):PFILE;

 const
    ENOENT = 2;
    EBADF  = 9;


//https://stackoverflow.com/questions/24882246/unable-to-use-cs-obj-files-compiled-by-cl-exe-in-delphi-xe4-win64-platform

implementation
uses
      OpenSSL3.Err;



//https://stackoverflow.com/questions/45126837/how-to-use-multibytetowidechar-in-delphi
function openssl_fopen(const filename: PUTF8Char; _mode: String):PFILE;
begin
   if FileExists(filename) then
   begin
      {if mode = 'rb' then
         Ret := fileopen(filename, fmOpenRead)
      else
      if mode = 'rw' then
         Ret := fileopen(filename, fmOpenWrite); }

      if _mode = 'rb' then
{$IFDEF _MSWINDOWS}
        Result := TFilestream.Create(FileName, fmOpenRead);
{$ELSE}
        Result := fopen(filename, 'r');
{$ENDIF}
   end
   else
      raise Exception.Create('Conf file' + string(filename) + 'not exists!');

   //Result := @ret;
end;

end.
