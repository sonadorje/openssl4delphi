unit openssl3.include.internal.refcount;

interface
uses {$IFDEF  MSWINDOWS}
        Windows,
     {$ENDIF}
   OpenSSL.Api;

function CRYPTO_UP_REF(var val,  ret : Integer; lock : Pointer):integer;
function CRYPTO_DOWN_REF(var val, ret : Integer; lock : Pointer):integer;
procedure REF_PRINT_COUNT(text: PUTF8Char; _object: Pointer);// PDSO);
procedure REF_ASSERT_ISNT(test: Boolean);
 procedure REF_PRINT_EX(text: PUTF8Char; count: Integer; _object: PDSO);



implementation

uses openssl3.crypto.cryptlib;

function CRYPTO_UP_REF(var val, ret : Integer; lock : Pointer):integer;
begin
{$IFDEF  MSWINDOWS}
     ret := InterlockedExchangeAdd(val, 1) + 1;
    // ret^ := InterlockedExchangeAdd64(PInt64(val)^, 1) + 1;

    Result := 1;

{$ENDIF}
end;


{$IFNDEF FPC}
procedure AssertErrorHandler(const Message, Filename: string;  LineNumber: Integer; ErrorAddr: Pointer);
{ No local variables. Not compiler generated temporary variables. }
{ Using the call stack here will cause Access Violation errors. }
begin
  OPENSSL_die('refcount error', Filename, LineNumber, ErrorAddr);
  //raise EMyAssert.Create('Boom!');
end;
{$ELSE}
procedure AssertErrorHandler(const Message, Filename: shortstring;  LineNumber: LongInt; ErrorAddr: Pointer);
{ No local variables. Not compiler generated temporary variables. }
{ Using the call stack here will cause Access Violation errors. }
begin
  OPENSSL_die('refcount error', Filename, LineNumber, ErrorAddr);
  //raise EMyAssert.Create('Boom!');
end;

{$ENDIF}
procedure REF_ASSERT_ISNT(test: Boolean);
begin
  AssertErrorProc := AssertErrorHandler;
  if test then
     Assert(test);

end;

procedure REF_PRINT_EX(text: PUTF8Char; count: Integer; _object: PDSO);
begin
    //OSSL_TRACE3(REF_COUNT, '%p:%4d:%s'#10, (_object), (count), (text));
end;

procedure REF_PRINT_COUNT(text: PUTF8Char; _object: Pointer);//PDSO);
begin
    REF_PRINT_EX(text, PDSO(_object).references, Pointer(_object))
end;

function CRYPTO_DOWN_REF(var val, ret : Integer; lock : Pointer):integer;
begin
{$IFDEF  MSWINDOWS}

    ret := InterlockedExchangeAdd(val, -1) - 1;

    //ret^ := InterlockedExchangeAdd64(PInt64(val)^, -1) - 1;

    Result := 1;
{$ENDIF}

end;
end.
