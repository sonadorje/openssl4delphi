unit openssl3.crypto.x509.v3_genn;

interface
uses OpenSSL.Api;

  function GENERAL_NAME_dup(const a : PGENERAL_NAME):PGENERAL_NAME;
  function edipartyname_cmp(const a, b : PEDIPARTYNAME):integer;
  function GENERAL_NAME_cmp( a, b : PGENERAL_NAME):integer;
  function OTHERNAME_cmp( a, b : POTHERNAME):integer;
  procedure GENERAL_NAME_set0_value( a : PGENERAL_NAME; _type : integer; value : Pointer);
  function GENERAL_NAME_get0_value(const a : PGENERAL_NAME; ptype : PInteger):Pointer;
  function GENERAL_NAME_set0_othername( gen : PGENERAL_NAME; oid : PASN1_OBJECT; value : PASN1_TYPE):integer;
  function GENERAL_NAME_get0_otherName(const gen : PGENERAL_NAME; poid : PPASN1_OBJECT; pvalue : PPASN1_TYPE):integer;
   function d2i_GENERAL_NAME(a : PPointer;const _in : PPByte; len : long):Pointer;
  function i2d_GENERAL_NAME(const a : Pointer; _out : PPByte):integer;
  function GENERAL_NAME_new:PGENERAL_NAME;
  procedure GENERAL_NAME_free( a : PGENERAL_NAME);
  function GENERAL_NAME_it:PASN1_ITEM;
  function d2i_OTHERNAME(a : PPOTHERNAME;const _in : PPByte; len : long):POTHERNAME;
  function i2d_OTHERNAME(const a : POTHERNAME; _out : PPByte):integer;
  function OTHERNAME_new:POTHERNAME;
  procedure OTHERNAME_free( a : POTHERNAME);
  function d2i_GENERAL_NAMES(a : PPGENERAL_NAMES;const _in : PPByte; len : long):PGENERAL_NAMES;
  function i2d_GENERAL_NAMES(const a : PGENERAL_NAMES; _out : PPByte):integer;
  function GENERAL_NAMES_new:PGENERAL_NAMES;
  procedure GENERAL_NAMES_free( a : PGENERAL_NAMES);
  function GENERAL_NAMES_it:PASN1_ITEM;
  function OTHERNAME_it:PASN1_ITEM;
  function EDIPARTYNAME_it:PASN1_ITEM;

var
  GENERAL_NAME_ch_tt: array[0..8] of TASN1_TEMPLATE;
  GENERAL_NAMES_item_tt : TASN1_TEMPLATE;
  OTHERNAME_seq_tt, EDIPARTYNAME_seq_tt: array of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.a_dup,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.a_type, OpenSSL3.crypto.x509.x509_cmp,
     openssl3.crypto.asn1.tasn_typ, OpenSSL3.crypto.x509.x_name,
     openssl3.crypto.asn1.a_octet, openssl3.crypto.objects.obj_lib,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.asn1.asn1_lib;





function EDIPARTYNAME_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @EDIPARTYNAME_seq_tt,
                 sizeof(EDIPARTYNAME_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                 sizeof(TEDIPARTYNAME), 'EDIPARTYNAME');
   Result := @local_it;
end;

function OTHERNAME_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM ($1, 16, @OTHERNAME_seq_tt,
                   sizeof(OTHERNAME_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                   sizeof(OTHERNAME), 'OTHERNAME');
  Result := @local_it;
end;


function GENERAL_NAMES_it:PASN1_ITEM;
var
  local_it :TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($0, -1, @GENERAL_NAMES_item_tt, 0,
                            Pointer(0) , 0, 'GENERAL_NAMES');

  Result := @local_it;
end;

function d2i_GENERAL_NAMES(a : PPGENERAL_NAMES;const _in : PPByte; len : long):PGENERAL_NAMES;
begin
  Result := PGENERAL_NAMES(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, GENERAL_NAMES_it));
end;


function i2d_GENERAL_NAMES(const a : PGENERAL_NAMES; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE(a), _out, GENERAL_NAMES_it);
end;


function GENERAL_NAMES_new:PGENERAL_NAMES;
begin
   Result := PGENERAL_NAMES(ASN1_item_new(GENERAL_NAMES_it));
end;


procedure GENERAL_NAMES_free( a : PGENERAL_NAMES);
begin
   ASN1_item_free(PASN1_VALUE( a), GENERAL_NAMES_it);
end;





function d2i_OTHERNAME(a : PPOTHERNAME;const _in : PPByte; len : long):POTHERNAME;
begin
   Result := POTHERNAME( ASN1_item_d2i(PPASN1_VALUE(a), _in, len, OTHERNAME_it));
end;


function i2d_OTHERNAME(const a : POTHERNAME; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, OTHERNAME_it);
end;


function OTHERNAME_new:POTHERNAME;
begin
   Result := POTHERNAME( ASN1_item_new(OTHERNAME_it));
end;


procedure OTHERNAME_free( a : POTHERNAME);
begin
 ASN1_item_free(PASN1_VALUE( a), OTHERNAME_it);
end;


function GENERAL_NAME_it:PASN1_ITEM;
  const
    gn = PGENERAL_NAME(0);
    local_it: TASN1_ITEM  = (
    itype: $2;
    utype:  size_t(@TGENERAL_NAME(nil^).&type);
    templates: @GENERAL_NAME_ch_tt;
    tcount:  sizeof(GENERAL_NAME_ch_tt) div sizeof(TASN1_TEMPLATE);
    funcs: Pointer(0) ;
    size: sizeof(TGENERAL_NAME);
    sname: 'GENERAL_NAME' );
begin
  result := @local_it;
end;




function d2i_GENERAL_NAME(a : PPointer;const _in : PPByte; len : long):Pointer;
begin
   Result :=  PGENERAL_NAME(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, GENERAL_NAME_it));
end;


function i2d_GENERAL_NAME(const a : Pointer; _out : PPByte):integer;
begin
   Result :=  ASN1_item_i2d(PASN1_VALUE( a), _out, GENERAL_NAME_it);
end;


function GENERAL_NAME_new:PGENERAL_NAME;
begin
   Result :=  PGENERAL_NAME(ASN1_item_new(GENERAL_NAME_it));
end;


procedure GENERAL_NAME_free( a : PGENERAL_NAME);
begin
   ASN1_item_free(PASN1_VALUE( a), GENERAL_NAME_it);
end;

function GENERAL_NAME_dup(const a : PGENERAL_NAME):PGENERAL_NAME;
begin
    Result := PGENERAL_NAME(ASN1_dup(i2d_GENERAL_NAME,
                                     d2i_GENERAL_NAME,
                                     PUTF8Char(a)));
end;


function edipartyname_cmp(const a, b : PEDIPARTYNAME):integer;
var
  res : integer;
begin
    if (a = nil)  or  (b = nil) then
    begin
        {
         * Shouldn't be possible in a valid GENERAL_NAME, but we handle it
         * anyway. OTHERNAME_cmp treats nil <> nil so we do the same here
         }
        Exit(-1);
    end;
    if (a.nameAssigner = nil)  and  (b.nameAssigner <> nil) then Exit(-1);
    if (a.nameAssigner <> nil)  and  (b.nameAssigner = nil) then Exit(1);
    { If we get here then both have nameAssigner set, or both unset }
    if a.nameAssigner <> nil then
    begin
        res := ASN1_STRING_cmp(a.nameAssigner, b.nameAssigner);
        if res <> 0 then Exit(res);
    end;
    {
     * partyName is required, so these should never be nil. We treat it in
     * the same way as the a = nil  or  b = nil case above
     }
    if (a.partyName = nil)  or  (b.partyName = nil) then
       Exit(-1);
    Result := ASN1_STRING_cmp(a.partyName, b.partyName);
end;


function GENERAL_NAME_cmp( a, b : PGENERAL_NAME):integer;
begin
    result := -1;
    if (nil = a)  or  (nil = b)  or  (a.&type <> b.&type) then
       Exit(-1);
    case a.&type of
        GEN_X400:
            result := ASN1_TYPE_cmp(a.d.x400Address, b.d.x400Address);
            //break;
        GEN_EDIPARTY:
            result := edipartyname_cmp(a.d.ediPartyName, b.d.ediPartyName);
            //break;
        GEN_OTHERNAME:
            result := OTHERNAME_cmp(a.d.otherName, b.d.otherName);
            //break;
        GEN_EMAIL,
        GEN_DNS,
        GEN_URI:
            result := ASN1_STRING_cmp(a.d.ia5, b.d.ia5);
            //break;
        GEN_DIRNAME:
            result := X509_NAME_cmp(a.d.dirn, b.d.dirn);
            //break;
        GEN_IPADD:
            result := ASN1_OCTET_STRING_cmp(a.d.ip, b.d.ip);
            //break;
        GEN_RID:
            result := _OBJ_cmp(a.d.rid, b.d.rid);
            //break;
    end;
    Result := result;
end;


function OTHERNAME_cmp( a, b : POTHERNAME):integer;
begin
    result := -1;
    if (nil = a)  or  (nil = b) then Exit(-1);
    { Check their type first. }
    result := _OBJ_cmp(a.type_id, b.type_id);
    if result <> 0 then
        Exit(result);
    { Check the value. }
    result := ASN1_TYPE_cmp(a.value, b.value);

end;


procedure GENERAL_NAME_set0_value( a : PGENERAL_NAME; _type : integer; value : Pointer);
begin
    case _type of
    GEN_X400:
        a.d.x400Address := value;
        //break;
    GEN_EDIPARTY:
        a.d.ediPartyName := value;
        //break;
    GEN_OTHERNAME:
        a.d.otherName := value;
        //break;
    GEN_EMAIL,
    GEN_DNS,
    GEN_URI:
        a.d.ia5 := value;
        //break;
    GEN_DIRNAME:
        a.d.dirn := value;
        //break;
    GEN_IPADD:
        a.d.ip := value;
        //break;
    GEN_RID:
        a.d.rid := value;
        //break;
    end;
    a.&type := _type;
end;


function GENERAL_NAME_get0_value(const a : PGENERAL_NAME; ptype : PInteger):Pointer;
begin
    if ptype <> nil then ptype^ := a.&type;
    case a.&type of
    GEN_X400:
        Exit(a.d.x400Address);
    GEN_EDIPARTY:
        Exit(a.d.ediPartyName);
    GEN_OTHERNAME:
        Exit(a.d.otherName);
    GEN_EMAIL,
    GEN_DNS,
    GEN_URI:
        Exit(a.d.ia5);
    GEN_DIRNAME:
        Exit(a.d.dirn);
    GEN_IPADD:
        Exit(a.d.ip);
    GEN_RID:
        Exit(a.d.rid);
    else
        Exit(nil);
    end;
end;


function GENERAL_NAME_set0_othername( gen : PGENERAL_NAME; oid : PASN1_OBJECT; value : PASN1_TYPE):integer;
var
  oth : POTHERNAME;
begin
    oth := OTHERNAME_new();
    if oth = nil then Exit(0);
    ASN1_TYPE_free(oth.value);
    oth.type_id := oid;
    oth.value := value;
    GENERAL_NAME_set0_value(gen, GEN_OTHERNAME, oth);
    Result := 1;
end;


function GENERAL_NAME_get0_otherName(const gen : PGENERAL_NAME; poid : PPASN1_OBJECT; pvalue : PPASN1_TYPE):integer;
begin
    if gen.&type <> GEN_OTHERNAME then Exit(0);
    if poid <> nil then
       poid^ := gen.d.otherName.type_id;
    if pvalue <> nil then
       pvalue^ := gen.d.otherName.value;
    Result := 1;
end;

initialization
  GENERAL_NAME_ch_tt[0] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), 0, size_t(@PGENERAL_NAME(0).d.otherName), 'd.otherName', OTHERNAME_it );
  GENERAL_NAME_ch_tt[1] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), (1), size_t(@PGENERAL_NAME(0).d.rfc822Name), 'd.rfc822Name', ASN1_IA5STRING_it );
  GENERAL_NAME_ch_tt[2] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), (2), size_t(@PGENERAL_NAME(0).d.dNSName), 'd.dNSName', ASN1_IA5STRING_it );
  GENERAL_NAME_ch_tt[3] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), (3), size_t(@PGENERAL_NAME(0).d.x400Address), 'd.x400Address', ASN1_SEQUENCE_it );
  GENERAL_NAME_ch_tt[4] := get_ASN1_TEMPLATE( ((($2  shl  3) or ($2 shl 6))  or  0), (4), size_t(@PGENERAL_NAME(0).d.directoryName), 'd.directoryName', X509_NAME_it );
  GENERAL_NAME_ch_tt[5] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), (5), size_t(@PGENERAL_NAME(0).d.ediPartyName), 'd.ediPartyName', EDIPARTYNAME_it );
  GENERAL_NAME_ch_tt[6] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), (6), size_t(@PGENERAL_NAME(0).d.uniformResourceIdentifier), 'd.uniformResourceIdentifier', ASN1_IA5STRING_it);
  GENERAL_NAME_ch_tt[7] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), (7), size_t(@PGENERAL_NAME(0).d.iPAddress), 'd.iPAddress', ASN1_OCTET_STRING_it );
  GENERAL_NAME_ch_tt[8] := get_ASN1_TEMPLATE( ((($1  shl  3) or ($2 shl 6))  or  0), (8), size_t(@PGENERAL_NAME(0).d.registeredID), 'd.registeredID', ASN1_OBJECT_it);
  GENERAL_NAMES_item_tt := get_ASN1_TEMPLATE( (($2 shl 1)), 0, 0, 'GeneralNames', GENERAL_NAME_it);

  OTHERNAME_seq_tt := [
        get_ASN1_TEMPLATE ( 0, 0, size_t(@POTHERNAME(0).type_id), 'type_id', ASN1_OBJECT_it) ,
        get_ASN1_TEMPLATE ( ((($2 shl 3) or ($2 shl 6)) or (0)), 0, size_t(@POTHERNAME(0).value), 'value', ASN1_ANY_it)
  ];

  EDIPARTYNAME_seq_tt := [
        get_ASN1_TEMPLATE( ((($2 shl 3) or ($2 shl 6)) or (($1))), 0, size_t(@PEDIPARTYNAME(0).nameAssigner), 'nameAssigner', DIRECTORYSTRING_it) ,
        get_ASN1_TEMPLATE( ((($2 shl 3) or ($2 shl 6)) or (0)), (1), size_t(@PEDIPARTYNAME(0).partyName), 'partyName', DIRECTORYSTRING_it)
  ] ;

end.
