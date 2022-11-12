unit Sscanf;

interface
uses SysUtils, math;

type
  EDeformatError = class(Exception);
  TSearchOptions = set of (soMatchCase, soWholeWord, soBackwards);
  { A set of chars. }
  TSetOfChars = SysUtils.TSysCharSet;
  { Floating-point type with best precision. }
  Float = {$ifdef FPC} Math.Float {$else} Extended {$endif};
  PFloat = {$ifdef FPC} Math.PFloat {$else} PExtended {$endif};

const
  AllChars = [Low(AnsiChar) .. High(AnsiChar)];
  DefaultWordBorders = AllChars - ['a'..'z', 'A'..'Z', '0'..'9', '_'];
  WhiteSpaces = [' ', #9, #10, #13];
  SimpleAsciiCharacters = [#32 .. #126];

{ Like standard TryStrToFloat, but always uses dot (.) as a decimal separator
  for the floating point numbers, regardless of the user's locale settings.

  Also it doesn't Trim the argument (so whitespace around number is @italic(not) tolerated),
  and in general ignores locale (standard StrToFloat looks at ThousandSeparator). }
function TryStrToFloatDot(const S: String; out Value: Single): Boolean; overload;
function TryStrToFloatDot(const S: String; out Value: Double): Boolean; overload;
{$if not defined(EXTENDED_EQUALS_DOUBLE) and not defined(FPC)}
function TryStrToFloatDot(const S: String; out Value: Extended): Boolean; overload;
{$endif}

{ Like standard StrToFloat, but always uses dot (.) as a decimal separator
  for the floating point numbers, regardless of the user's locale settings.

  Also it doesn't Trim the argument (so whitespace around number is @italic(not) tolerated),
  and in general ignores locale (standard StrToFloat looks at ThousandSeparator). }
function StrToFloatDot(const S: String): Extended;
function CopyPos(const s: string; StartPosition, EndPosition: integer): string;
function SCharIs(const S: String; const Index: Integer; const C: char): Boolean; overload;
function SCharIs(const S: String; const Index: Integer; const chars: TSetOfChars): Boolean; overload;
function ArrayPosStr(const A: string; const Arr: array of string): Integer; overload;

implementation

{ arrays searching ---------------------------------------- }

function ArrayPosStr(const A: string; const Arr: array of string): Integer;
begin
  for Result := 0 to High(Arr) do
    if Arr[Result] = A then
      Exit;
  Result := -1;
end;

function SCharIs(const S: String; const Index: Integer; const C: Char): Boolean;
begin
  Result := (Index <= Length(S)) and (S[Index] = C)
end;

function SCharIs(const S: string; const Index: integer; const Chars: TSetOfChars): Boolean;
begin
  Result := (Index <= Length(S)) and CharInSet(S[Index], chars);
end;

function CopyPos(const s: string; StartPosition, EndPosition: integer): string;
begin
  result := Copy(s, StartPosition, EndPosition - StartPosition + 1);
end;


function TryStrToFloatDot(const S: String; out Value: Single): Boolean;
var
  Err: Integer;
begin
  Val(S, Value, Err);
  Result := Err = 0;
end;

function TryStrToFloatDot(const S: String; out Value: Double): Boolean;
var
  Err: Integer;
begin
  Val(S, Value, Err);
  Result := Err = 0;
end;

{$if not defined(EXTENDED_EQUALS_DOUBLE) and not defined(FPC)}
function TryStrToFloatDot(const S: String; out Value: Extended): Boolean;
var
  Err: Integer;
begin
  Val(S, Value, Err);
  Result := Err = 0;
end;
{$endif}

function StrToFloatDot(const S: String): Extended;
var
  Err: Integer;
begin
  Val(S, Result, Err);
  if Err <> 0 then
    raise EConvertError.CreateFmt('"%s" is an invalid float', [S]);
end;

function TryDeFormat(Data: Ansistring; const Format: Ansistring;
  const args: array of pointer;
  const IgnoreCase: boolean;
  const RelaxedWhitespaceChecking: boolean): integer;
var datapos, formpos: integer;
  function ReadExtendedData: Extended;
  var dataposstart: integer;
  begin
   {pierwszy znak liczby moze byc + lub -. Potem musza byc same cyfry.}
   if not CharInSet(data[datapos], ['0'..'9', '+', '-']) then
    raise EDeformatError.CreateFmt('float not found in data ''%s'' on position %d', [data, datapos]);
   dataposstart := datapos;
   Inc(datapos);
   while (datapos <= Length(data)) and
     CharInSet(data[datapos], ['0'..'9','.', 'e','E', '-', '+']) do
    Inc(datapos);
   { Note that StrToFloatDot may still raise EConvertError.
     The argument contains only valid characters, but they may not form a valid number,
     e.g. '123....456' or 'eee' or '1+2'. }
   result := StrToFloatDot(CopyPos(data, dataposstart, datapos-1));
  end;

  function ReadInt64Data: Int64;
  var dataposstart: integer;
  begin
   {pierwszy znak integera moze byc + lub -. Potem musza byc same cyfry.}
   if not CharInSet(data[datapos], ['0'..'9', '+', '-']) then
    raise EDeformatError.CreateFmt('integer not found in data ''%s'' on position %d', [data, datapos]);
   dataposstart := datapos;
   Inc(datapos);
   while (datapos <= Length(data)) and CharInSet(data[datapos], ['0'..'9']) do
    Inc(datapos);
   {ponizszy StrToInt tez moze spowodowac blad jesli np.
    wyszedl nam string '-' lub '+'}
   result := StrToInt(CopyPos(data, dataposstart, datapos-1));
  end;

  function ReadStringData: string;
  var dataposstart: integer;
  begin
   dataposstart := datapos;
   while (datapos <= Length(data)) and
         (not CharInSet(data[datapos], WhiteSpaces)) do Inc(datapos);
   result := CopyPos(data, dataposstart, datapos-1);
  end;

  function ReadTypeSpecifier: string;
  {odczytaj type specifier z kropka z format. Przesun formpos}
  var formposstart: integer;
  begin
   formposstart := formpos;
   repeat
    if formpos > Length(format) then
     raise EDeformatError.Create('type specifier incorrect in  format '''+format+'''');
    if format[formpos] = '.' then
     break else
     Inc(formpos);
   until false;
   result := CopyPos(format, formposstart, formpos-1);
   Inc(formpos); { omin kropke '.' w format }
  end;

  procedure CheckBlackChar(formatchar: UTF8Char);
  var BlackCharsCheck: boolean;
  begin
   if IgnoreCase then
    BlackCharsCheck := SameText(Data[datapos], format[formpos]) else
    BlackCharsCheck := Data[datapos] = format[formpos];
   if not BlackCharsCheck then
    raise EDeformatError.CreateFmt('data (%s) and format (%s) don''t match', [data, format]);
  end;

  procedure CheckFormatNotEnd;
  begin
    if formpos > Length(format) then
      raise EDeformatError.Create('Unexpected end of format : "'+format+'"');
  end;
type
  { Define it only locally, remember String = AnsiString or UnicodeString. }
  PString = ^String;
var
  TypeSpecifier: String;
begin
 datapos := 1;
 formpos := 1;
 result := 0; { no args done yet }
 { Skip whitespace and the beginning of data }
 if RelaxedWhitespaceChecking then
   while SCharIs(Data, DataPos, WhiteSpaces) do Inc(DataPos);
 while formpos <= Length(Format) do
 begin
  {datapos > Length(data) -> means Data has ended but Format not.
   OK, so we can exit, because we are doing only TryDeFormat.
   Real DeFormat should check our result if it wishes to check that we parsed
   whole Format.}
  if datapos > Length(data) then
  begin
    { Actually, if next thing in format is %s, we can parse it too
      (string will just be '') }
    if Format[FormPos] = '%' then
    begin
      Inc(formpos);
      CheckFormatNotEnd;
      if Format[FormPos] = 's' then
      begin
        PString(args[result])^ := ReadStringData;
        Inc(formpos);
        Inc(result);
      end;
    end;
    Exit;
  end;
  {1 or more whitespace in format means 1 or more whitespaces in data}
  if RelaxedWhitespaceChecking and CharInSet(format[formpos], WhiteSpaces) then
  begin
   if not SCharIs(Data, datapos, WhiteSpaces) then
    raise EDeformatError.Create('Whitespace not found in data "' + data +
      '" as requested by format "' + format + '"');
   repeat Inc(formpos) until not SCharIs(format, formpos, WhiteSpaces);
   repeat Inc(datapos) until not SCharIs(data, datapos, WhiteSpaces);
  end else
  {%+something means "read this from data", %% means "read %"}
  if format[formpos] = '%' then
  begin
   Inc(formpos);
   CheckFormatNotEnd;
   try
    case format[formpos] of
     '%':begin
          CheckBlackChar('%');
          Inc(formpos);
          Inc(datapos);
         end;
     's':begin
          PString(args[result])^:=ReadStringData;
          Inc(formpos);
          Inc(result);
         end;
     'd':begin
          PInteger(args[result])^:=ReadInt64Data;
          Inc(formpos);
          Inc(result);
         end;
     'f':begin
          PFloat(args[result])^:=ReadExtendedData;
          Inc(formpos);
          Inc(result);
         end;
     '.':begin
          Inc(formpos);
          TypeSpecifier := ReadTypeSpecifier;
          case ArrayPosStr(TypeSpecifier,
            ['single', 'double', 'extended', 'integer', 'cardinal']) of
           0: PSingle(args[result])^:=ReadExtendedData;
           1: PDouble(args[result])^:=ReadExtendedData;
           2: PExtended(args[result])^:=ReadExtendedData;
           3: PInteger(args[result])^:=ReadInt64Data;
           4: PCardinal(args[result])^:=ReadInt64Data;
           else raise EDeformatError.CreateFmt('Incorrect type specifier "%s"', [TypeSpecifier]);
          end;
          Inc(result);
         end;
     else raise EDeformatError.Create('incorrect format specifier after "%" sign : '''+format+'''');
    end;
   except
    on E: EConvertError do raise EDeformatError.Create('convert error - '+E.Message)
   end;
  end else
  begin
   CheckBlackChar(format[formpos]);
   Inc(datapos);
   Inc(formpos);
  end;
 end;
 if RelaxedWhitespaceChecking then
   while SCharIs(Data, DataPos, WhiteSpaces) do Inc(DataPos);
 if datapos <= Length(data) then
  raise EDeformatError.CreateFmt(
    'data ''%s'' too long - unexpected end of format ''%s''', [Data, Format]);
end;
end.
