unit openssl3.crypto.asn1.tasn_typ;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;


function ASN1_OCTET_STRING_it:PASN1_ITEM;
function ASN1_BIT_STRING_it:PASN1_ITEM;
function ASN1_OBJECT_it:PASN1_ITEM;
function ASN1_NULL_it:PASN1_ITEM;
function ASN1_INTEGER_it:PASN1_ITEM;
function ASN1_ANY_it:PASN1_ITEM;
 function i2d_ASN1_OCTET_STRING(const a : PASN1_OCTET_STRING; _out : PPByte):integer;
 function ASN1_BIT_STRING_new:PASN1_BIT_STRING;
 procedure ASN1_BIT_STRING_free( x : PASN1_BIT_STRING);
 function ASN1_INTEGER_new:PASN1_INTEGER;
  procedure ASN1_INTEGER_free( x : PASN1_INTEGER);
  function ASN1_TYPE_new:PASN1_TYPE;
  procedure ASN1_TYPE_free( a : PASN1_TYPE);
  function ASN1_NULL_new: PASN1_NULL;
  procedure ASN1_NULL_free( a : PASN1_NULL);
  function ASN1_OCTET_STRING_new:PASN1_OCTET_STRING;
  procedure ASN1_OCTET_STRING_free( x : PASN1_OCTET_STRING);


  function ASN1_UTF8STRING_it:PASN1_ITEM;
  function d2i_ASN1_UTF8STRING(a : PPASN1_UTF8STRING;const _in : PPByte; len : long):PASN1_UTF8STRING;
  function i2d_ASN1_UTF8STRING(const a : PASN1_UTF8STRING; _out : PPByte):integer;
  function ASN1_UTF8STRING_new:PASN1_UTF8STRING;
  procedure ASN1_UTF8STRING_free( x : PASN1_UTF8STRING);
  function d2i_ASN1_SET_ANY(a : PPASN1_SEQUENCE_ANY;const _in : PPByte; len : long):PASN1_SEQUENCE_ANY;
  function i2d_ASN1_SET_ANY(const a : PASN1_SEQUENCE_ANY; _out : PPByte):integer;
   function d2i_ASN1_SEQUENCE_ANY(a : PPASN1_SEQUENCE_ANY;const _in : PPByte; len : long):PASN1_SEQUENCE_ANY;
  function i2d_ASN1_SEQUENCE_ANY(const a : PASN1_SEQUENCE_ANY; _out : PPByte):integer;
  function ASN1_SET_ANY_it:PASN1_ITEM;
  function ASN1_SEQUENCE_ANY_it:PASN1_ITEM;
  function i2d_ASN1_TYPE(const a : PASN1_TYPE; _out : PPByte):integer;
  function d2i_ASN1_TYPE(a : PPASN1_TYPE;const _in : PPByte; len : long):PASN1_TYPE;
  function ASN1_PRINTABLE_it:PASN1_ITEM;
  function ASN1_IA5STRING_new:PASN1_IA5STRING;
  function ASN1_IA5STRING_it:PASN1_ITEM;
  function d2i_ASN1_IA5STRING(a : PPASN1_IA5STRING;const _in : PPByte; len : long):PASN1_IA5STRING;
  function i2d_ASN1_IA5STRING(const a : PASN1_IA5STRING; _out : PPByte):integer;
  procedure ASN1_IA5STRING_free( x : PASN1_IA5STRING);
  function ASN1_BOOLEAN_it:PASN1_ITEM;
  function d2i_ASN1_OCTET_STRING(a : PPASN1_OCTET_STRING;const _in : PPByte; len : long):PASN1_OCTET_STRING;
  function i2d_ASN1_INTEGER(const a : PASN1_INTEGER; _out : PPByte):integer;
  function d2i_ASN1_INTEGER(a : PPASN1_INTEGER;const _in : PPByte; len : long):PASN1_INTEGER;
  function d2i_ASN1_ENUMERATED(a : PPASN1_ENUMERATED;const _in : PPByte; len : long):PASN1_ENUMERATED;
  function ASN1_ENUMERATED_it:PASN1_ITEM;
   procedure ASN1_ENUMERATED_free( x : PASN1_ENUMERATED);
  function ASN1_GENERALIZEDTIME_it:PASN1_ITEM;
  function d2i_ASN1_GENERALIZEDTIME(a : PPASN1_GENERALIZEDTIME;const _in : PPByte; len : long):PASN1_GENERALIZEDTIME;
  function i2d_ASN1_GENERALIZEDTIME(const a : PASN1_GENERALIZEDTIME; _out : PPByte):integer;
  function ASN1_GENERALIZEDTIME_new:PASN1_GENERALIZEDTIME;
  procedure ASN1_GENERALIZEDTIME_free( x : PASN1_GENERALIZEDTIME);
  function DISPLAYTEXT_it:PASN1_ITEM;
   procedure ASN1_PRINTABLESTRING_free( x : PASN1_PRINTABLESTRING);
   function DIRECTORYSTRING_it:PASN1_ITEM;
  function ASN1_PRINTABLESTRING_it:PASN1_ITEM;
   function d2i_ASN1_PRINTABLESTRING(a : PPASN1_PRINTABLESTRING;const _in : PPByte; len : long):PASN1_PRINTABLESTRING;
  function i2d_ASN1_PRINTABLESTRING(const a : PASN1_PRINTABLESTRING; _out : PPByte):integer;
  function ASN1_PRINTABLESTRING_new:PASN1_PRINTABLESTRING;
   function ASN1_SEQUENCE_it:PASN1_ITEM;



var
  ASN1_SET_ANY_item_tt, ASN1_SEQUENCE_ANY_item_tt : TASN1_TEMPLATE;

implementation

uses
  openssl3.crypto.stack, openssl3.crypto.mem, openssl3.crypto.asn1.tasn_enc,
  openssl3.crypto.asn1.asn1_lib, openssl3.crypto.asn1.tasn_fre,
  openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_dec;

var
  SEQUENCE_local_it : TASN1_ITEM;
function ASN1_SEQUENCE_it:PASN1_ITEM;
begin
    SEQUENCE_local_it := get_ASN1_ITEM($0, 16, Pointer(0) , 0,
                  Pointer(0) , 0, 'ASN1_SEQUENCE' );
    Result := @SEQUENCE_local_it;
end;

function d2i_ASN1_PRINTABLESTRING(a : PPASN1_PRINTABLESTRING;const _in : PPByte; len : long):PASN1_PRINTABLESTRING;
begin
 Result := PASN1_PRINTABLESTRING(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_PRINTABLESTRING_it));
end;


function i2d_ASN1_PRINTABLESTRING(const a : PASN1_PRINTABLESTRING; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASN1_PRINTABLESTRING_it);
end;


function ASN1_PRINTABLESTRING_new:PASN1_PRINTABLESTRING;
begin
    Result := ASN1_STRING_type_new(19);
end;

var
  PRINTABLESTRING_local_it : TASN1_ITEM;
function ASN1_PRINTABLESTRING_it:PASN1_ITEM;
begin
    PRINTABLESTRING_local_it := get_ASN1_ITEM($0, 19, Pointer(0) , 0,
                           Pointer(0) , 0, 'ASN1_PRINTABLESTRING');
    Result := @PRINTABLESTRING_local_it;
end;

var
  DIRECTORYSTRING_local_it : TASN1_ITEM;
function DIRECTORYSTRING_it:PASN1_ITEM;
begin
    DIRECTORYSTRING_local_it := get_ASN1_ITEM($5, $0002 or $0004 or $0800 or $0100 or $2000,
            Pointer(0) , 0, Pointer(0) , sizeof(TASN1_STRING), 'DIRECTORYSTRING');
    Result := @DIRECTORYSTRING_local_it;
end;


procedure ASN1_PRINTABLESTRING_free( x : PASN1_PRINTABLESTRING);
begin
 ASN1_STRING_free(PASN1_STRING(x));
end;

var
  DISPLAYTEXT_local_it : TASN1_ITEM;
function DISPLAYTEXT_it:PASN1_ITEM;
begin
   DISPLAYTEXT_local_it := get_ASN1_ITEM($5, $0010 or $0040 or $0800 or $2000,
                             Pointer(0) , 0, Pointer(0) , sizeof(TASN1_STRING), ' DISPLAYTEXT');

   Result := @DISPLAYTEXT_local_it;
end;

var
  GENERALIZEDTIME_local_it : TASN1_ITEM;
function ASN1_GENERALIZEDTIME_it:PASN1_ITEM;
begin
   GENERALIZEDTIME_local_it := get_ASN1_ITEM( $0, 24, Pointer(0) , 0, Pointer(0) , 0, 'ASN1_GENERALIZEDTIME');
   Result := @GENERALIZEDTIME_local_it;
end;


function d2i_ASN1_GENERALIZEDTIME(a : PPASN1_GENERALIZEDTIME;const _in : PPByte; len : long):PASN1_GENERALIZEDTIME;
begin
   Result := PASN1_GENERALIZEDTIME(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_GENERALIZEDTIME_it));
end;


function i2d_ASN1_GENERALIZEDTIME(const a : PASN1_GENERALIZEDTIME; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASN1_GENERALIZEDTIME_it);
end;


function ASN1_GENERALIZEDTIME_new:PASN1_GENERALIZEDTIME;
begin
   Result := PASN1_GENERALIZEDTIME(ASN1_STRING_type_new(24));
end;


procedure ASN1_GENERALIZEDTIME_free( x : PASN1_GENERALIZEDTIME);
begin
  ASN1_STRING_free(PASN1_STRING(x));
end;


procedure ASN1_ENUMERATED_free( x : PASN1_ENUMERATED);
begin
   ASN1_STRING_free(PASN1_STRING(x));
end;

var
   ENUMERATED_local_it: TASN1_ITEM ;
function ASN1_ENUMERATED_it:PASN1_ITEM;
begin
  ENUMERATED_local_it := get_ASN1_ITEM($0, 10, Pointer(0) , 0, Pointer(0) , 0, 'ASN1_ENUMERATED');
  Result := @ENUMERATED_local_it;
end;



function d2i_ASN1_ENUMERATED(a : PPASN1_ENUMERATED;const _in : PPByte; len : long):PASN1_ENUMERATED;
begin
 result := PASN1_ENUMERATED(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_ENUMERATED_it));
end;

function d2i_ASN1_INTEGER(a : PPASN1_INTEGER;const _in : PPByte; len : long):PASN1_INTEGER;
begin
   Result := PASN1_INTEGER( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_INTEGER_it));
end;

function i2d_ASN1_INTEGER(const a : PASN1_INTEGER; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASN1_INTEGER_it);
end;

function d2i_ASN1_OCTET_STRING(a : PPASN1_OCTET_STRING;const _in : PPByte; len : long):PASN1_OCTET_STRING;
begin
   Result := PASN1_OCTET_STRING(ASN1_item_d2i(PPASN1_VALUE(a), _in, len,
                                              ASN1_OCTET_STRING_it));
end;

var
  BOOLEAN_local_it: TASN1_ITEM ;
function ASN1_BOOLEAN_it:PASN1_ITEM;
begin
   BOOLEAN_local_it := get_ASN1_ITEM($0, 1, Pointer(0) , 0, Pointer(0) , -1, 'ASN1_BOOLEAN');
   result := @BOOLEAN_local_it;
end;


var
  IA5STRING_local_it: TASN1_ITEM ;
function ASN1_IA5STRING_it:PASN1_ITEM;
begin
   IA5STRING_local_it := get_ASN1_ITEM($0, 22, Pointer(0) , 0,
                             Pointer(0) , 0, 'ASN1_IA5STRING');

   result := @IA5STRING_local_it;
end;


function d2i_ASN1_IA5STRING(a : PPASN1_IA5STRING;const _in : PPByte; len : long):PASN1_IA5STRING;
begin
   result := PASN1_IA5STRING(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_IA5STRING_it));
end;


function i2d_ASN1_IA5STRING(const a : PASN1_IA5STRING; _out : PPByte):integer;
begin
   result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASN1_IA5STRING_it);
end;


procedure ASN1_IA5STRING_free( x : PASN1_IA5STRING);
begin
  ASN1_STRING_free(PASN1_STRING(x));
end;


function ASN1_IA5STRING_new:PASN1_IA5STRING;
begin
   result := PASN1_IA5STRING(ASN1_STRING_type_new(22));
end;

var
  PRINTABLE_local_it: TASN1_ITEM ;
function ASN1_PRINTABLE_it:PASN1_ITEM;
begin
  PRINTABLE_local_it := get_ASN1_ITEM (
                $5, $0001 or  $0002 or  $0004 or  $0010 or  $0400 or  $0100 or  $0800 or  $2000 or  $10000 or  $1000,
                Pointer(0) , 0, Pointer(0) , sizeof(TASN1_STRING), 'ASN1_PRINTABLE');

  result := @PRINTABLE_local_it;
end;



function d2i_ASN1_TYPE(a : PPASN1_TYPE;const _in : PPByte; len : long):PASN1_TYPE;
begin
   Result := PASN1_TYPE( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_ANY_it));
end;


function i2d_ASN1_TYPE(const a : PASN1_TYPE; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE( a), _out, ASN1_ANY_it);
end;

var
  SEQUENCE_ANY_local_it : TASN1_ITEM;
function ASN1_SEQUENCE_ANY_it:PASN1_ITEM;
begin
  SEQUENCE_ANY_local_it := get_ASN1_ITEM( $0, -1, @ASN1_SEQUENCE_ANY_item_tt, 0,
                              nil , 0, 'ASN1_SEQUENCE_ANY' );
  result := @SEQUENCE_ANY_local_it;
end;

function d2i_ASN1_SEQUENCE_ANY(a : PPASN1_SEQUENCE_ANY;const _in : PPByte; len : long):PASN1_SEQUENCE_ANY;
begin
   result := PASN1_SEQUENCE_ANY( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_SEQUENCE_ANY_it));
end;


function i2d_ASN1_SEQUENCE_ANY(const a : PASN1_SEQUENCE_ANY; _out : PPByte):integer;
begin
   result := ASN1_item_i2d(PASN1_VALUE( a), _out, ASN1_SEQUENCE_ANY_it);
end;


function ASN1_SET_ANY_it:PASN1_ITEM;
const local_it: TASN1_ITEM  = (
        itype: $0;
        utype:  -1;
        templates:  @ASN1_SET_ANY_item_tt;
        tcount: 0;
        funcs: Pointer(0) ;
        size: 0;
        sname: 'ASN1_SET_ANY');
begin
   result := @local_it;
end;

function d2i_ASN1_SET_ANY(a : PPASN1_SEQUENCE_ANY;const _in : PPByte; len : long):PASN1_SEQUENCE_ANY;
begin
   result := PASN1_SEQUENCE_ANY( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_SET_ANY_it));
end;


function i2d_ASN1_SET_ANY(const a : PASN1_SEQUENCE_ANY; _out : PPByte):integer;
begin
   result := ASN1_item_i2d(PASN1_VALUE( a), _out, ASN1_SET_ANY_it);
end;

var
   UTF8STRING_local_it: TASN1_ITEM;
function ASN1_UTF8STRING_it:PASN1_ITEM;
begin
   UTF8STRING_local_it := get_ASN1_ITEM($0, 12, Pointer(0), 0, Pointer(0), 0, 'ASN1_UTF8STRING' );
   result := @UTF8STRING_local_it;
end;


function d2i_ASN1_UTF8STRING(a : PPASN1_UTF8STRING;const _in : PPByte; len : long):PASN1_UTF8STRING;
begin
 result := PASN1_UTF8STRING(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ASN1_UTF8STRING_it));
end;


function i2d_ASN1_UTF8STRING(const a : PASN1_UTF8STRING; _out : PPByte):integer;
begin
  result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASN1_UTF8STRING_it);
end;


function ASN1_UTF8STRING_new:PASN1_UTF8STRING;
begin
   result := PASN1_UTF8STRING(ASN1_STRING_type_new(12));
end;


procedure ASN1_UTF8STRING_free( x : PASN1_UTF8STRING);
begin
   ASN1_STRING_free(PASN1_STRING(x));
end;

function ASN1_OCTET_STRING_new:PASN1_OCTET_STRING;
begin
   Result := PASN1_OCTET_STRING(ASN1_STRING_type_new(4));
end;


procedure ASN1_OCTET_STRING_free( x : PASN1_OCTET_STRING);
begin
   ASN1_STRING_free(PASN1_STRING(x));
end;

function ASN1_NULL_new: PASN1_NULL;
begin
 Result := PASN1_NULL(ASN1_item_new(ASN1_NULL_it));
end;


procedure ASN1_NULL_free(a : PASN1_NULL);
begin
 ASN1_item_free(PASN1_VALUE( a), (ASN1_NULL_it()));
end;


procedure ASN1_TYPE_free( a : PASN1_TYPE);
begin
  ASN1_item_free(PASN1_VALUE( a), ASN1_ANY_it);
end;

function ASN1_TYPE_new:PASN1_TYPE;
begin
  Result := PASN1_TYPE( ASN1_item_new(ASN1_ANY_it));
end;

function ASN1_INTEGER_new:PASN1_INTEGER;
begin
   Result := PASN1_INTEGER(ASN1_STRING_type_new(2));
end;


procedure ASN1_INTEGER_free( x : PASN1_INTEGER);
begin
   ASN1_STRING_free(PASN1_STRING(x));
end;

procedure ASN1_BIT_STRING_free( x : PASN1_BIT_STRING);
begin
  ASN1_STRING_free(PASN1_STRING(x));
end;


function ASN1_BIT_STRING_new:PASN1_BIT_STRING;
begin
   Result := PASN1_BIT_STRING(ASN1_STRING_type_new(3));
end;


function i2d_ASN1_OCTET_STRING(const a : PASN1_OCTET_STRING; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASN1_OCTET_STRING_it);
end;

var
  ANY_local_it : TASN1_ITEM;
function ASN1_ANY_it:PASN1_ITEM;
begin
   ANY_local_it := get_ASN1_ITEM($0, -4, Pointer(0), 0, nil, 0, 'ASN1_ANY');
   result := @ANY_local_it;
end;

var
  INTEGER_local_it : TASN1_ITEM;
function ASN1_INTEGER_it:PASN1_ITEM;
begin
  INTEGER_local_it := get_ASN1_ITEM($0, 2, Pointer(0) , 0, Pointer(0) , 0, 'ASN1_INTEGER' );
  Exit(@INTEGER_local_it);
end;

var
  NULL_local_it : TASN1_ITEM;
function ASN1_NULL_it:PASN1_ITEM;
begin
  NULL_local_it := get_ASN1_ITEM( $0, 5, Pointer(0) , 0, Pointer(0) , 0, 'ASN1_NULL');
  result := @NULL_local_it;
end;

var
  OBJECT_local_it : TASN1_ITEM;
function ASN1_OBJECT_it:PASN1_ITEM;
begin
   OBJECT_local_it := get_ASN1_ITEM($0, 6, Pointer(0),
                                    0, Pointer(0), 0, 'ASN1_OBJECT');
   result := @OBJECT_local_it;
end;

var
  BIT_STRING_local_it : TASN1_ITEM;
function ASN1_BIT_STRING_it:PASN1_ITEM;
begin
  BIT_STRING_local_it := get_ASN1_ITEM($0, 3, Pointer(0) , 0, Pointer(0) , 0, 'ASN1_BIT_STRING');
  Result := @BIT_STRING_local_it;
end;


 var
    ASN1_OCTET_local_it: TASN1_ITEM ;
function ASN1_OCTET_STRING_it:PASN1_ITEM;
begin
   ASN1_OCTET_local_it:= get_ASN1_ITEM( $0, 4, Pointer(0) , 0, Pointer(0) , 0, 'ASN1_OCTET_STRING');
   Result := @ASN1_OCTET_local_it;
end;

initialization
    ASN1_SET_ANY_item_tt := get_ASN1_TEMPLATE( ($1 shl 1),
                                0, 0, 'ASN1_SET_ANY', ASN1_ANY_it);

    ASN1_SEQUENCE_ANY_item_tt := get_ASN1_TEMPLATE(($2 shl 1), 0, 0,
                                 'ASN1_SEQUENCE_ANY', ASN1_ANY_it);
end.
