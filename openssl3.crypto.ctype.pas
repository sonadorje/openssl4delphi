unit openssl3.crypto.ctype;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

{$if defined(CHARSET_EBCDIC) and not defined(CHARSET_EBCDIC_TEST)}
static const int case_change = 0x40;
{$else }
 const case_change: int  = $20;
{$endif}

const // 1d arrays
  CTYPE_MASK_lower = $1;
  CTYPE_MASK_upper = $2;
  CTYPE_MASK_digit = $4;
  CTYPE_MASK_space = $8;
  CTYPE_MASK_xdigit = $10;
  CTYPE_MASK_blank = $20;
  CTYPE_MASK_cntrl = $40;
  CTYPE_MASK_graph = $80;
  CTYPE_MASK_print = $100;
  CTYPE_MASK_punct = $200;
  CTYPE_MASK_base64 = $400;
  CTYPE_MASK_asn1print = $800;
  CTYPE_MASK_alpha = (CTYPE_MASK_lower or CTYPE_MASK_upper);
  CTYPE_MASK_alnum = (CTYPE_MASK_alpha or CTYPE_MASK_digit);
  CTYPE_MASK_ascii = ( not 0);
  ctype_char_map : array[0..127] of word = (
    {00nul}CTYPE_MASK_cntrl, {01soh}CTYPE_MASK_cntrl,
    {02stx}CTYPE_MASK_cntrl, {03etx}CTYPE_MASK_cntrl,
    {04eot}CTYPE_MASK_cntrl, {05enq}CTYPE_MASK_cntrl,
    {06ack}CTYPE_MASK_cntrl, {07\a}CTYPE_MASK_cntrl,
    {08\b}CTYPE_MASK_cntrl,
    {09\t}CTYPE_MASK_blank or CTYPE_MASK_cntrl or CTYPE_MASK_space,
    {0A\n}CTYPE_MASK_cntrl or CTYPE_MASK_space,
    {0B\v}CTYPE_MASK_cntrl or CTYPE_MASK_space,
    {0C\f}CTYPE_MASK_cntrl or CTYPE_MASK_space,
    {0D\r}CTYPE_MASK_cntrl or CTYPE_MASK_space, {0Eso}CTYPE_MASK_cntrl,
    {0Fsi}CTYPE_MASK_cntrl, {10dle}CTYPE_MASK_cntrl,
    {11dc1}CTYPE_MASK_cntrl, {12dc2}CTYPE_MASK_cntrl,
    {13dc3}CTYPE_MASK_cntrl, {14dc4}CTYPE_MASK_cntrl,
    {15nak}CTYPE_MASK_cntrl, {16syn}CTYPE_MASK_cntrl,
    {17etb}CTYPE_MASK_cntrl, {18can}CTYPE_MASK_cntrl,
    {19em}CTYPE_MASK_cntrl, {1Asub}CTYPE_MASK_cntrl,
    {1Besc}CTYPE_MASK_cntrl, {1Cfs}CTYPE_MASK_cntrl,
    {1Dgs}CTYPE_MASK_cntrl, {1Ers}CTYPE_MASK_cntrl,
    {1Fus}CTYPE_MASK_cntrl,
    {20}CTYPE_MASK_blank or CTYPE_MASK_print or CTYPE_MASK_space or CTYPE_MASK_asn1print,
    {21!}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {22'}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct, {23#}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct, {24$}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct, {25%}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct, {26&}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct, {27'}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    {28(}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    {29)}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    {2A*}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {2B+}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {2C,
    }CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    {2D-}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    {2E.}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    (* 2F / *)CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {300}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {311}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {322}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {333}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {344}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {355}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {366}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {377}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {388}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {399}CTYPE_MASK_digit or CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {3A:}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    {3B;}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {3C<}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {3D=}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {3E>}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {3F?}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct or CTYPE_MASK_asn1print,
    {40@}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {41A}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {42B}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {43C}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {44D}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {45E}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {46F}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {47G}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {48H}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {49I}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {4AJ}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {4BK}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {4CL}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {4DM}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {4EN}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {4FO}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {50P}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {51Q}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {52R}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {53S}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {54T}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {55U}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {56V}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {57W}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {58X}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {59Y}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {5AZ}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_upper or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {5B[}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {5C\}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {5D]}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {5E^}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {5F_}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {60`}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {61a}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {62b}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {63c}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {64d}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {65e}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {66f}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_xdigit or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {67g}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {68h}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {69i}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {6Aj}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {6Bk}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {6Cl}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {6Dm}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {6En}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {6Fo}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {70p}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {71q}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {72r}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {73s}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {74t}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {75u}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {76v}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {77w}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {78x}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {79y}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {7Az}CTYPE_MASK_graph or CTYPE_MASK_lower or CTYPE_MASK_print or CTYPE_MASK_base64 or CTYPE_MASK_asn1print,
    {7B{}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {7C or }CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    (*7D '}' *)CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {7E~}CTYPE_MASK_graph or CTYPE_MASK_print or CTYPE_MASK_punct,
    {7Fdel}CTYPE_MASK_cntrl );

function ossl_tolower( c : UTF8Char):UTF8Char;
function ossl_isdigit(c: UTF8Char):Boolean;
function ossl_ctype_check( c : integer; mask : uint32):Boolean;
function ossl_isspace(c: UTF8Char): Boolean;
function ossl_isalpha(c: UTF8Char): Boolean;
function ossl_isalnum(c: UTF8Char): Boolean;
function ossl_isxdigit(c: UTF8Char): Boolean;
function ossl_isprint(c: UTF8Char): Boolean;
function ossl_isbase64(c: UTF8Char):Boolean;
function ossl_iscntrl(c: UTF8Char): Boolean;
function ossl_fromascii(c: Uint): uint;
function ossl_isasn1print(c: int): Boolean;
function ossl_isascii(c: int): Boolean;
function ossl_toascii(c: int8): int8;
function ossl_isupper(c: UTF8Char):Boolean;

implementation

function ossl_isupper(c: UTF8Char):Boolean;
begin
   Result := ossl_ctype_check(Ord(c), CTYPE_MASK_upper)
end;

function ossl_toascii(c: int8): int8;
begin
   Result := (c)
end;

function ossl_isascii(c: int): Boolean;
begin
   Result := ((c and not 127) = 0)
end;

function ossl_isasn1print(c: int): Boolean;
begin
   Result := ossl_ctype_check(c, CTYPE_MASK_asn1print);
end;

function ossl_fromascii(c: Uint): uint;
begin
  Exit(c)
end;

function  ossl_iscntrl(c: UTF8Char): Boolean;
begin
   Result := ossl_ctype_check(Ord(c), CTYPE_MASK_cntrl);
end;

function ossl_isbase64(c: UTF8Char): Boolean;
begin
  Result := ossl_ctype_check(Ord(c), CTYPE_MASK_base64);
end;

function ossl_isprint(c: UTF8Char): Boolean;
begin
   Result :=        (ossl_ctype_check(Ord(c), CTYPE_MASK_print))
end;

function ossl_isxdigit(c: UTF8Char): Boolean;
begin
   Result := (ossl_ctype_check(Ord(c), CTYPE_MASK_xdigit))
end;

function ossl_isalnum(c: UTF8Char): Boolean;
begin
   Result :=  (ossl_ctype_check(Ord(c), CTYPE_MASK_alnum))
end;

function ossl_isalpha(c: UTF8Char): Boolean;
begin
   Result := (ossl_ctype_check(Ord(c), CTYPE_MASK_alpha))
end;

function ossl_isspace(c: UTF8Char): Boolean;
begin
   Result := (ossl_ctype_check(Ord(c), CTYPE_MASK_space))
end;

function ossl_isdigit(c: UTF8Char):Boolean;
begin
   Result := ossl_ctype_check(Ord(c), CTYPE_MASK_digit);
end;


function ossl_ctype_check( c : integer; mask : uint32):Boolean;
var
  max, a : integer;
  p: PWord;
begin
   p := @ctype_char_map;
   max := sizeof(ctype_char_map) div sizeof(p^);
   a := ossl_toascii(c);
   Result := (a >= 0)  and  (a < max)  and  ((ctype_char_map[a] and mask) <> 0);
end;


function ossl_tolower( c : UTF8Char): UTF8Char;
begin
  if isupper(c) then
     Result := UTF8Char (Ord(c)  xor  case_change)
  else
     Result := c;
end;

end.
