unit openssl3.crypto.cryptolib;

interface
uses SysUtils;

function ossl_assert(x: integer): integer;

implementation


procedure OPENSSL_die(const &message, filename : string; lineNumber : integer; ErrorAddr: Pointer);
var
  S: String;
begin

    s := Format('%s:%d: OpenSSL internal error: %s, address $%x'#10,
                      [filename, lineNumber, &message, Pred(Integer(ErrorAddr))]);
{$IF not defined(_WIN32)}
    abort();
{$ELSE}
     (* Win32 abort() customarily shows a dialog, but we just did that... *)

{$if  not defined(_WIN32_WCE)}
    raise Exception.Create(S);
{$endif}
    Halt(3);
{$ENDIF}
end;

procedure AssertErrorHandler(const Message, Filename: {$IFNDEF FPC}string{$ELSE}ShortString{$ENDIF};  LineNumber: Integer; ErrorAddr: Pointer);
{ No local variables. Not compiler generated temporary variables. }
{ Using the call stack here will cause Access Violation errors. }
begin
  OPENSSL_die(Message, Filename, LineNumber, ErrorAddr);
  //raise EMyAssert.Create('Boom!');
end;

function ossl_assert_int(expr : integer):integer;
begin
  AssertErrorProc := AssertErrorHandler;
  Assert(expr <> 0);
  Result := expr;
end;

(* # define ossl_assert(x) ossl_assert_int((x) != 0, "Assertion failed: "#x, \
                                         __FILE__, __LINE__)
  int ossl_assert_int(int expr, const PUTF8Char exprstr,
                                              const PUTF8Char file, int line)
{
    if (!expr)
        OPENSSL_die(exprstr, file, line);

    return expr;
}
*)
function ossl_assert(x: integer): Integer;
begin
  result := ossl_assert_int(x);
end;

end.
