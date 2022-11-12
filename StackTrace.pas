unit StackTrace;

interface

uses
  SysUtils, Classes, JclDebug;

implementation

function GetExceptionStackInfoProc(P: PExceptionRecord): Pointer;
var
  LLines: TStringList;
  LText: String;
  LResult: PUTF8Char;
  jcl_sil: TJclStackInfoList;
begin
  LLines := TStringList.Create;
  try
    jcl_sil:=TJclStackInfoList.Create(True, 7, p.ExceptAddr, False, nil, nil);
    try
      jcl_sil.AddToStrings(LLines, true, true, true, true);
    finally
      FreeAndNil(jcl_sil);
    end;
    LText := LLines.Text;
    LResult := StrAlloc(Length(LText));
    StrCopy(LResult, PUTF8Char(LText));
    Result := LResult;
  finally
    LLines.Free;
  end;
end;


function GetStackInfoStringProc(Info: Pointer): string;
begin
  Result := string(PUTF8Char(Info));
end;

procedure CleanUpStackInfoProc(Info: Pointer);
begin
  StrDispose(PUTF8Char(Info));
end;

initialization
// Start the Jcl exception tracking and register our Exception
// stack trace provider.
if JclStartExceptionTracking then
begin
  Exception.GetExceptionStackInfoProc := GetExceptionStackInfoProc;
  Exception.GetStackInfoStringProc := GetStackInfoStringProc;
  Exception.CleanUpStackInfoProc := CleanUpStackInfoProc;
end;

finalization
// Stop Jcl exception tracking and unregister our provider.
if JclExceptionTrackingActive then
begin
  Exception.GetExceptionStackInfoProc := nil;
  Exception.GetStackInfoStringProc := nil;
  Exception.CleanUpStackInfoProc := nil;
  JclStopExceptionTracking;
end;

end.
