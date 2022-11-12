unit openssl3.internal.refcount;

interface
uses {$IFDEF  MSWINDOWS} Winapi.Windows, {$ENDIF}
    OpenSSL.Api;

function CRYPTO_DOWN_REF( val, ret : PInteger; lock : Pointer):integer;
procedure REF_PRINT_COUNT(text: PUTF8Char; _object: Pointer);// PDSO);
procedure REF_ASSERT_ISNT(test: Boolean);

implementation
uses openssl3.crypto.cryptlib;

procedure AssertErrorHandler(const Message, Filename: string;  LineNumber: Integer; ErrorAddr: Pointer);
{ No local variables. Not compiler generated temporary variables. }
{ Using the call stack here will cause Access Violation errors. }
begin
  OPENSSL_die('refcount error', Filename, LineNumber, ErrorAddr);
  //raise EMyAssert.Create('Boom!');
end;

procedure REF_ASSERT_ISNT(test: Boolean);
begin
  AssertErrorProc := AssertErrorHandler;
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

function CRYPTO_DOWN_REF( val, ret : PInteger; lock : Pointer):integer;
begin
    ret^ := InterlockedExchangeAdd(val, -1) - 1;
    Result := 1;
end;

end.
