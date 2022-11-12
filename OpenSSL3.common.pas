unit OpenSSL3.common;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_assert(x: Boolean): Boolean;
//function HAS_PREFIX(str, pre: PUTF8Char): Boolean;
function CHECK_AND_SKIP_PREFIX(var str: PUTF8Char; pre: PUTF8Char) : Integer;
function HAS_PREFIX(str, pre: PUTF8Char): Boolean;
function ossl_is_absolute_path(const path: PUTF8Char): int;
function ossl_ends_with_dirsep({const} path: PUTF8Char): int;
function HAS_CASE_PREFIX(s, p: PUTF8Char): Boolean;
function CHECK_AND_SKIP_CASE_PREFIX(str, pre: PUTF8Char): int;

implementation

uses openssl3.crypto.cryptlib;


function CHECK_AND_SKIP_CASE_PREFIX(str, pre: PUTF8Char): int;
begin
    str := str + sizeof(pre) - 1;
    Result := get_result(HAS_CASE_PREFIX(str, pre) , 1 , 0);
end;

function HAS_CASE_PREFIX(s, p: PUTF8Char): Boolean;
begin
   Result := (strncasecmp(s, p, sizeof(p) - 1) = 0)
end;

function ossl_ends_with_dirsep({const} path: PUTF8Char): int;
begin
    if (path^ <> #0) then
        path := path + length(path) - 1;
{$if defined(__VMS)}
    if (path^ = ']') or (path^ = '>') or (path^ = ':') then
        Exit(1);
{$elseif defined(MSWINDOWS)}
    if (path^ = '\') then
        Exit(1);
{$endif}
    Result := Int(path^ = '/');
end;

function ossl_is_absolute_path(const path: PUTF8Char): int;
begin
{$if defined( __VMS)}
    if (strchr(path, ':') <> NULL
        or ((path[0] = '[' or path[0] = '<')
            and path[1] <> '.' and path[1] <> '-'
            and path[1] <> ']' and path[1] <> '>'))
        exit( 1;
{$elseif defined(MSWINDOWS) }
    if (path[0] = '\')
        or ( (path[0] <> #0) and (path[1] = ':') ) then
        exit( 1);
{$endif}
    exit(Int(path[0] = '/'));
end;

function CHECK_AND_SKIP_PREFIX(var str: PUTF8Char; pre: PUTF8Char): int;
begin
    if HAS_PREFIX(str, pre) then
    begin
       str := str + strsize(pre) - 1;
       Exit(1);
    end
    else
       Exit(0);
end;

(* Check if |pre|, which must be a string literal, is a prefix of |str| *)
//#define HAS_PREFIX(str, pre) (strncmp(str, pre "", sizeof(pre) - 1) == 0)
function HAS_PREFIX(str, pre: PUTF8Char): Boolean;
begin
  Result :=  strncmp(str, pre, strSize(pre)-1) = 0 ;
end;


{$IFNDEF FPC}
procedure AssertErrorHandler(const Message, Filename: string;  LineNumber: Integer; ErrorAddr: Pointer);
{ No local variables. Not compiler generated temporary variables. }
{ Using the call stack here will cause Access Violation errors. }
begin
  //OPENSSL_die(Message, Filename, LineNumber, ErrorAddr);
  //raise EMyAssert.Create('Boom!');
end;
{$ELSE}
procedure AssertErrorHandler(const Message, Filename: Shortstring;  LineNumber: LongInt; ErrorAddr: Pointer);
{ No local variables. Not compiler generated temporary variables. }
{ Using the call stack here will cause Access Violation errors. }
begin
  //OPENSSL_die(Message, Filename, LineNumber, ErrorAddr);
  //raise EMyAssert.Create('Boom!');
end;

{$ENDIF}
function ossl_assert_int(expr : Boolean):Boolean;
begin
  AssertErrorProc := AssertErrorHandler;
  Assert(expr);
  Result := (expr);
end;

function ossl_assert(x: Boolean): Boolean;
begin
  result := ossl_assert_int(Integer(x) <> 0);
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




end.
