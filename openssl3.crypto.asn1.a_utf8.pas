unit openssl3.crypto.asn1.a_utf8;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
   TUNICODE_CONSTANTS = (
    SURROGATE_MIN = $d800,
    SURROGATE_MAX = $dfff,
    UNICODE_MAX   = $10ffff,
    UNICODE_LIMIT
   );
function UTF8_getc(const str : PByte; len : integer; val : PUInt32):integer;
  function UTF8_putc( str : PByte; len : integer; value : Cardinal):integer;

function is_unicode_surrogate( value : Cardinal):Boolean;
  function is_unicode_valid( value : Cardinal):Boolean;

implementation


function is_unicode_surrogate( value : Cardinal):Boolean;
begin
    Result := (value >= Int(SURROGATE_MIN))  and  (value <= Int(SURROGATE_MAX));
end;


function is_unicode_valid( value : Cardinal):Boolean;
begin
    Result := (value <= Int(UNICODE_MAX))  and  (not is_unicode_surrogate(value));
end;



function UTF8_getc(const str : PByte; len : integer; val : PUInt32):integer;
var
  p : PByte;

  value : Cardinal;

  ret : integer;
begin
    if len <= 0 then Exit(0);
    p := str;
    { Check syntax and work out the encoded value (if correct) }
    if (p^ and $80) = 0 then
    begin
        value := PostInc(p)^ and $7f;
        ret := 1;
    end
    else
    if (( p^ and $e0) = $c0) then
    begin
        if len < 2 then Exit(-1);
        if (p[1] and $c0) <> $80 then
            Exit(-3);
        value := ( PostInc(p)^ and $1f)  shl  6;
        value  := value  or ( PostInc(p)^ and $3f);
        if value < $80 then Exit(-4);
        ret := 2;
    end
    else
    if (( p^ and $f0) = $e0) then
    begin
        if len < 3 then Exit(-1);
        if ( (p[1] and $c0 ) <> $80)
             or  ((p[2] and $c0) <> $80)  then
            Exit(-3);
        value := ( PostInc(p)^ and $f)  shl  12;
        value  := value  or (( PostInc(p)^ and $3f)  shl  6);
        value  := value  or ( PostInc(p)^ and $3f);
        if value < $800 then Exit(-4);
        if is_unicode_surrogate(value )then
            Exit(-2);
        ret := 3;
    end
    else
    if (( p^ and $f8) = $f0) then
    begin
        if len < 4 then Exit(-1);
        if  ((p[1] and $c0) <> $80)
             or  ((p[2] and $c0) <> $80)
             or  ((p[3] and $c0) <> $80) then
            Exit(-3);
        value := (ulong( PostInc(p)^ and $7))  shl  18;
        value  := value  or (( PostInc(p)^ and $3f)  shl  12);
        value  := value  or (( PostInc(p)^ and $3f)  shl  6);
        value  := value  or ( PostInc(p)^ and $3f);
        if value < $10000 then Exit(-4);
        ret := 4;
    end
    else
        Exit(-2);
    val^ := value;
    Result := ret;
end;


function UTF8_putc( str : PByte; len : integer; value : Cardinal):integer;
begin
    if nil = str then
       len := 4                { Maximum we will need }
    else if (len <= 0) then
        Exit(-1);
    if value < $80 then
    begin
        if str <> nil then
           str^ := Byte( value);
        Exit(1);
    end;
    if value < $800 then
    begin
        if len < 2 then
            Exit(-1);
        if str <> nil then
        begin
            PostInc(str)^ :=  Byte(((value  shr  6) and $1f) or $c0);
            str^ := Byte((value and $3f) or $80);
        end;
        Exit(2);
    end;
    if value < $10000 then
    begin
        if is_unicode_surrogate(value) then
            Exit(-2);
        if len < 3 then Exit(-1);
        if str <> nil then
        begin
            PostInc(str)^ :=  Byte(((value  shr  12) and $f) or $e0);
            PostInc(str)^ :=  Byte(((value  shr  6) and $3f) or $80);
            str^ := Byte((value and $3f) or $80);
        end;
        Exit(3);
    end;
    if value < Int(UNICODE_LIMIT) then
    begin
        if len < 4 then
            Exit(-1);
        if str <> nil then
        begin
            PostInc(str)^ :=  Byte(((value  shr  18) and $7) or $f0);
            PostInc(str)^ :=  Byte(((value  shr  12) and $3f) or $80);
            PostInc(str)^ :=  Byte(((value  shr  6) and $3f) or $80);
            str^ := Byte((value and $3f) or $80);
        end;
        Exit(4);
    end;
    Result := -2;
end;


end.
