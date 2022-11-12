unit OpenSSL3.crypto.x509.v3_admis;

interface
uses OpenSSL.Api;


function ADMISSION_SYNTAX_it:PASN1_ITEM;

function i2r_ADMISSION_SYNTAX(const method : Pv3_ext_method; _in : Pointer; bp : PBIO; ind : integer):integer;
  function NAMING_AUTHORITY_get0_authorityId(const n : PNAMING_AUTHORITY):PASN1_OBJECT;
  procedure NAMING_AUTHORITY_set0_authorityId( n : PNAMING_AUTHORITY; id : PASN1_OBJECT);
  function NAMING_AUTHORITY_get0_authorityURL(const n : PNAMING_AUTHORITY):PASN1_IA5STRING;
  procedure NAMING_AUTHORITY_set0_authorityURL( n : PNAMING_AUTHORITY; u : PASN1_IA5STRING);
  procedure NAMING_AUTHORITY_set0_authorityText( n : PNAMING_AUTHORITY; t : PASN1_STRING);
  procedure ADMISSION_SYNTAX_set0_admissionAuthority( &as : PADMISSION_SYNTAX; aa : PGENERAL_NAME);
  function ADMISSION_SYNTAX_get0_contentsOfAdmissions(const &as : PADMISSION_SYNTAX):Pstack_st_ADMISSIONS;
  procedure ADMISSION_SYNTAX_set0_contentsOfAdmissions( &as : PADMISSION_SYNTAX; a : Pstack_st_ADMISSIONS);
  function ADMISSIONS_get0_admissionAuthority(const a : PADMISSIONS):PGENERAL_NAME;
  procedure ADMISSIONS_set0_admissionAuthority( a : PADMISSIONS; aa : PGENERAL_NAME);
  function ADMISSIONS_get0_namingAuthority(const a : PADMISSIONS):PNAMING_AUTHORITY;
  procedure ADMISSIONS_set0_namingAuthority( a : PADMISSIONS; na : PNAMING_AUTHORITY);
  function ADMISSIONS_get0_professionInfos(const a : PADMISSIONS):PPROFESSION_INFOS;
  procedure ADMISSIONS_set0_professionInfos( a : PADMISSIONS; pi : PPROFESSION_INFOS);
  function PROFESSION_INFO_get0_addProfessionInfo(const pi : PPROFESSION_INFO):PASN1_OCTET_STRING;
  procedure PROFESSION_INFO_set0_addProfessionInfo( pi : PPROFESSION_INFO; aos : PASN1_OCTET_STRING);
  function PROFESSION_INFO_get0_namingAuthority(const pi : PPROFESSION_INFO):PNAMING_AUTHORITY;
  procedure PROFESSION_INFO_set0_namingAuthority( pi : PPROFESSION_INFO; na : PNAMING_AUTHORITY);
  procedure PROFESSION_INFO_set0_professionItems( pi : PPROFESSION_INFO; _as: Pstack_st_ASN1_STRING );
  function PROFESSION_INFO_get0_professionOIDs(const pi : PPROFESSION_INFO):Pstack_st_ASN1_OBJECT;
  procedure PROFESSION_INFO_set0_professionOIDs( pi : PPROFESSION_INFO; po : Pstack_st_ASN1_OBJECT);
  function PROFESSION_INFO_get0_registrationNumber(const pi : PPROFESSION_INFO):PASN1_PRINTABLESTRING;
  procedure PROFESSION_INFO_set0_registrationNumber( pi : PPROFESSION_INFO; rn : PASN1_PRINTABLESTRING);
  function i2r_NAMING_AUTHORITY(const method : Pv3_ext_method; _in : Pointer; bp : PBIO; ind : integer):integer;

  function d2i_ADMISSIONS(a : PPADMISSIONS;const _in : PPByte; len : long):PADMISSIONS;
  function i2d_ADMISSIONS(const a : PADMISSIONS; _out : PPByte):integer;
  function ADMISSIONS_new:PADMISSIONS;
  procedure ADMISSIONS_free( a : PADMISSIONS);
   function ADMISSIONS_it:PASN1_ITEM;

  function d2i_NAMING_AUTHORITY(a : PPNAMING_AUTHORITY;const _in : PPByte; len : long):PNAMING_AUTHORITY;
  function i2d_NAMING_AUTHORITY(const a : PNAMING_AUTHORITY; _out : PPByte):integer;
  function NAMING_AUTHORITY_new:PNAMING_AUTHORITY;
  procedure NAMING_AUTHORITY_free( a : PNAMING_AUTHORITY);
  function NAMING_AUTHORITY_it:PASN1_ITEM;

  function d2i_PROFESSION_INFO(a : PPPROFESSION_INFO;const _in : PPByte; len : long):PPROFESSION_INFO;
  function i2d_PROFESSION_INFO(const a : PPROFESSION_INFO; _out : PPByte):integer;
  function PROFESSION_INFO_new:PPROFESSION_INFO;
  procedure PROFESSION_INFO_free( a : PPROFESSION_INFO);
  function PROFESSION_INFO_it:PASN1_ITEM;

var
  ossl_v3_ext_admission: TX509V3_EXT_METHOD ;
  ADMISSION_SYNTAX_seq_tt, ADMISSIONS_seq_tt, PROFESSION_INFO_seq_tt,
  NAMING_AUTHORITY_seq_tt: array of TASN1_TEMPLATE ;

implementation

uses openssl3.crypto.bio.bio_print, OpenSSL3.crypto.x509.v3_san,
     openssl3.crypto.asn1.a_print,  OpenSSL3.include.openssl.asn1,
     openssl3.crypto.asn1.a_object, openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.x509.v3_genn,  openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.x509.x509_v3 , openssl3.crypto.objects.obj_dat;





function PROFESSION_INFO_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($1, 16, @PROFESSION_INFO_seq_tt,
        sizeof(PROFESSION_INFO_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
        sizeof(TPROFESSION_INFO), 'PROFESSION_INFO');
    Result := @local_it;
end;




function d2i_PROFESSION_INFO(a : PPPROFESSION_INFO;const _in : PPByte; len : long):PPROFESSION_INFO;
begin
 Result := PPROFESSION_INFO(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, PROFESSION_INFO_it));
end;


function i2d_PROFESSION_INFO(const a : PPROFESSION_INFO; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE(a), _out, PROFESSION_INFO_it);
end;


function PROFESSION_INFO_new:PPROFESSION_INFO;
begin
 Result := PPROFESSION_INFO(ASN1_item_new(PROFESSION_INFO_it));
end;


procedure PROFESSION_INFO_free( a : PPROFESSION_INFO);
begin
 ASN1_item_free(PASN1_VALUE(a), PROFESSION_INFO_it);
end;





function NAMING_AUTHORITY_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM($1, 16, @NAMING_AUTHORITY_seq_tt,
               sizeof(NAMING_AUTHORITY_seq_tt) div sizeof(TASN1_TEMPLATE),
         Pointer(0) , sizeof(TNAMING_AUTHORITY), 'NAMING_AUTHORITY');

         Result := @local_it;
end;

function d2i_NAMING_AUTHORITY(a : PPNAMING_AUTHORITY;const _in : PPByte; len : long):PNAMING_AUTHORITY;
begin
   Result := PNAMING_AUTHORITY(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, NAMING_AUTHORITY_it));
end;


function i2d_NAMING_AUTHORITY(const a : PNAMING_AUTHORITY; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, NAMING_AUTHORITY_it);
end;


function NAMING_AUTHORITY_new:PNAMING_AUTHORITY;
begin
   Result := PNAMING_AUTHORITY(ASN1_item_new(NAMING_AUTHORITY_it));
end;


procedure NAMING_AUTHORITY_free( a : PNAMING_AUTHORITY);
begin
   ASN1_item_free(PASN1_VALUE(a), NAMING_AUTHORITY_it);
end;




function ADMISSIONS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM ($1, 16, @ADMISSIONS_seq_tt,
               sizeof(ADMISSIONS_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0),
               sizeof(TADMISSIONS), 'ADMISSIONS');

   Result := @local_it;
end;




function d2i_ADMISSIONS(a : PPADMISSIONS;const _in : PPByte; len : long):PADMISSIONS;
begin
 Result := PADMISSIONS(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, ADMISSIONS_it ));
end;


function i2d_ADMISSIONS(const a : PADMISSIONS; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ADMISSIONS_it );
end;


function ADMISSIONS_new:PADMISSIONS;
begin
 Result := PADMISSIONS(ASN1_item_new(ADMISSIONS_it ));
end;


procedure ADMISSIONS_free( a : PADMISSIONS);
begin
   ASN1_item_free(PASN1_VALUE( a), ADMISSIONS_it);
end;




function i2r_NAMING_AUTHORITY(const method : Pv3_ext_method; _in : Pointer; bp : PBIO; ind : integer):integer;
var
    namingAuthority : PNAMING_AUTHORITY;
    objbuf          : array[0..127] of UTF8Char;
    ln              : PUTF8Char;
    label _err;
begin
    namingAuthority := PNAMING_AUTHORITY(_in);
    if namingAuthority = nil then Exit(0);
    if (namingAuthority.namingAuthorityId = nil)
         and  (namingAuthority.namingAuthorityText = nil)
         and  (namingAuthority.namingAuthorityUrl = nil) then
         Exit(0);
    if BIO_printf(bp, '%*snamingAuthority: ', [ind, '']) <= 0  then
        goto _err ;
    if namingAuthority.namingAuthorityId <> nil then
    begin
      ln := OBJ_nid2ln(OBJ_obj2nid(namingAuthority.namingAuthorityId));
        if BIO_printf(bp, '%*s  admissionAuthorityId: ', [ind, '']) <= 0  then
            goto _err ;
        OBJ_obj2txt(objbuf, sizeof(objbuf), namingAuthority.namingAuthorityId, 1);
        if BIO_printf(bp, '%s%s%s%s\n', [get_result(ln<>nil , ln , ''),
                     get_result(ln<>nil , ' (' , ''), objbuf,
                     get_result(ln<>nil , ' )' , '')]) <= 0 then
            goto _err ;
    end;
    if namingAuthority.namingAuthorityText <> nil then
    begin
        if (BIO_printf(bp, '%*s  namingAuthorityText: ', [ind, '']) <= 0)
             or  (ASN1_STRING_print(bp, namingAuthority.namingAuthorityText) <= 0 )
             or  (BIO_printf(bp, #10, []) <= 0) then
            goto _err ;
    end;
    if namingAuthority.namingAuthorityUrl <> nil then
    begin
        if (BIO_printf(bp, '%*s  namingAuthorityUrl: ', [ind, ''])  <= 0)
             or  (ASN1_STRING_print(bp, PASN1_STRING(namingAuthority.namingAuthorityUrl)) <= 0 )
             or  (BIO_printf(bp, #10, []) <= 0)  then
            goto _err ;
    end;
    Exit(1);
_err:
    Result := 0;
end;

function i2r_ADMISSION_SYNTAX(const method : Pv3_ext_method; _in : Pointer; bp : PBIO; ind : integer):integer;
var
    admission : PADMISSION_SYNTAX;
    i,
    j,
    k         : integer;
    entry     : PADMISSIONS;
    pinfo     : PPROFESSION_INFO;
    val       : PASN1_STRING;
    obj       : PASN1_OBJECT;
    ln        : PUTF8Char;
    objbuf    : array[0..127] of UTF8Char;
    label _err;
begin
    admission := PADMISSION_SYNTAX(_in);
    if admission.admissionAuthority <> nil then
    begin
        if (BIO_printf(bp, '%*sadmissionAuthority:\n', [ind, ''])  <= 0)
             or  (BIO_printf(bp, '%*s  ', [ind, '']) <= 0)
             or  (GENERAL_NAME_print(bp, admission.admissionAuthority) <= 0)
             or  (BIO_printf(bp, #10, []) <= 0) then
            goto _err ;
    end;
    for i := 0 to sk_ADMISSIONS_num(admission.contentsOfAdmissions)-1 do
    begin
        entry := sk_ADMISSIONS_value(admission.contentsOfAdmissions, i);
        if BIO_printf(bp, '%*sEntry %0d:\n', [ind, '', 1 + i]) <= 0  then
           goto _err ;
        if entry.admissionAuthority <> nil then
        begin
            if (BIO_printf(bp, '%*s  admissionAuthority:\n', [ind, ''])  <= 0)
                 or  (BIO_printf(bp, '%*s    ', [ind, '']) <= 0 )
                 or  (GENERAL_NAME_print(bp, entry.admissionAuthority) <= 0)
                 or  (BIO_printf(bp, #10, []) <= 0) then
                goto _err ;
        end;
        if entry.namingAuthority <> nil then
        begin
            if i2r_NAMING_AUTHORITY(method, entry.namingAuthority, bp, ind) <= 0 then
                goto _err ;
        end;
        for j := 0 to sk_PROFESSION_INFO_num(entry.professionInfos)-1 do
        begin
            pinfo := sk_PROFESSION_INFO_value(entry.professionInfos, j);
            if BIO_printf(bp, '%*s  Profession Info Entry %0d:\n', [ind, '', 1 + j]) <= 0  then
                goto _err ;
            if pinfo.registrationNumber <> nil then
            begin
                if (BIO_printf(bp, '%*s    registrationNumber: ', [ind, ''])  <= 0)
                     or  (ASN1_STRING_print(bp, PASN1_STRING(pinfo.registrationNumber)) <= 0 )
                     or  (BIO_printf(bp, #10, []) <= 0) then
                    goto _err ;
            end;
            if pinfo.namingAuthority <> nil then
            begin
                if i2r_NAMING_AUTHORITY(method, pinfo.namingAuthority, bp, ind + 2) <= 0 then
                    goto _err ;
            end;
            if pinfo.professionItems <> nil then
            begin
                if BIO_printf(bp, '%*s    Info Entries:\n', [ind, '']) <= 0 then
                    goto _err ;
                for k := 0 to sk_ASN1_STRING_num(pinfo.professionItems)-1 do
                begin
                    val := sk_ASN1_STRING_value(pinfo.professionItems, k);
                    if (BIO_printf(bp, '%*s      ', [ind, '']) <= 0)
                         or  (ASN1_STRING_print(bp, val) <= 0 )
                         or  (BIO_printf(bp, #10, []) <= 0)  then
                        goto _err ;
                end;
            end;
            if pinfo.professionOIDs <> nil then
            begin
                if BIO_printf(bp, '%*s    Profession OIDs:\n', [ind, '']) <= 0 then
                    goto _err ;
                for k := 0 to sk_ASN1_OBJECT_num(pinfo.professionOIDs)-1 do
                begin
                    obj := sk_ASN1_OBJECT_value(pinfo.professionOIDs, k);
                   ln := OBJ_nid2ln(OBJ_obj2nid(obj));
                    OBJ_obj2txt(objbuf, sizeof(objbuf), obj, 1);
                    if BIO_printf(bp, '%*s      %s%s%s%s\n', [ind, '',
                               get_result(ln<>nil , ln , ''),
                               get_result(ln<>nil , ' (' , ''),
                                   objbuf, get_result(ln<>nil , ')' , '')]) <= 0 then
                        goto _err ;
                end;
            end;
        end;
    end;
    Exit(1);
_err:
    Result := -1;
end;


function NAMING_AUTHORITY_get0_authorityId(const n : PNAMING_AUTHORITY):PASN1_OBJECT;
begin
    Result := n.namingAuthorityId;
end;


procedure NAMING_AUTHORITY_set0_authorityId( n : PNAMING_AUTHORITY; id : PASN1_OBJECT);
begin
    ASN1_OBJECT_free(n.namingAuthorityId);
    n.namingAuthorityId := id;
end;


function NAMING_AUTHORITY_get0_authorityURL(const n : PNAMING_AUTHORITY):PASN1_IA5STRING;
begin
    Result := n.namingAuthorityUrl;
end;


procedure NAMING_AUTHORITY_set0_authorityURL( n : PNAMING_AUTHORITY; u : PASN1_IA5STRING);
begin
    ASN1_IA5STRING_free(n.namingAuthorityUrl);
    n.namingAuthorityUrl := u;
end;


procedure NAMING_AUTHORITY_set0_authorityText( n : PNAMING_AUTHORITY; t : PASN1_STRING);
begin
    ASN1_IA5STRING_free(PASN1_IA5STRING(n.namingAuthorityText));
    n.namingAuthorityText := t;
end;


procedure ADMISSION_SYNTAX_set0_admissionAuthority( &as : PADMISSION_SYNTAX; aa : PGENERAL_NAME);
begin
    GENERAL_NAME_free(&as.admissionAuthority);
    &as.admissionAuthority := aa;
end;


function ADMISSION_SYNTAX_get0_contentsOfAdmissions(const &as : PADMISSION_SYNTAX):Pstack_st_ADMISSIONS;
begin
    Result := &as.contentsOfAdmissions;
end;


procedure ADMISSION_SYNTAX_set0_contentsOfAdmissions( &as : PADMISSION_SYNTAX; a : Pstack_st_ADMISSIONS);
begin
    sk_ADMISSIONS_pop_free(&as.contentsOfAdmissions, ADMISSIONS_free);
    &as.contentsOfAdmissions := a;
end;


function ADMISSIONS_get0_admissionAuthority(const a : PADMISSIONS):PGENERAL_NAME;
begin
    Result := a.admissionAuthority;
end;


procedure ADMISSIONS_set0_admissionAuthority( a : PADMISSIONS; aa : PGENERAL_NAME);
begin
    GENERAL_NAME_free(a.admissionAuthority);
    a.admissionAuthority := aa;
end;


function ADMISSIONS_get0_namingAuthority(const a : PADMISSIONS):PNAMING_AUTHORITY;
begin
    Result := a.namingAuthority;
end;


procedure ADMISSIONS_set0_namingAuthority( a : PADMISSIONS; na : PNAMING_AUTHORITY);
begin
    NAMING_AUTHORITY_free(a.namingAuthority);
    a.namingAuthority := na;
end;


function ADMISSIONS_get0_professionInfos(const a : PADMISSIONS):PPROFESSION_INFOS;
begin
    Result := a.professionInfos;
end;


procedure ADMISSIONS_set0_professionInfos( a : PADMISSIONS; pi : PPROFESSION_INFOS);
begin
    sk_PROFESSION_INFO_pop_free(a.professionInfos, PROFESSION_INFO_free);
    a.professionInfos := pi;
end;


function PROFESSION_INFO_get0_addProfessionInfo(const pi : PPROFESSION_INFO):PASN1_OCTET_STRING;
begin
    Result := pi.addProfessionInfo;
end;


procedure PROFESSION_INFO_set0_addProfessionInfo( pi : PPROFESSION_INFO; aos : PASN1_OCTET_STRING);
begin
    ASN1_OCTET_STRING_free(pi.addProfessionInfo);
    pi.addProfessionInfo := aos;
end;


function PROFESSION_INFO_get0_namingAuthority(const pi : PPROFESSION_INFO):PNAMING_AUTHORITY;
begin
    Result := pi.namingAuthority;
end;


procedure PROFESSION_INFO_set0_namingAuthority( pi : PPROFESSION_INFO; na : PNAMING_AUTHORITY);
begin
    NAMING_AUTHORITY_free(pi.namingAuthority);
    pi.namingAuthority := na;
end;


procedure PROFESSION_INFO_set0_professionItems( pi : PPROFESSION_INFO; _as: Pstack_st_ASN1_STRING );
begin
    sk_ASN1_STRING_pop_free(pi.professionItems, ASN1_STRING_free);
    pi.professionItems := _as;
end;


function PROFESSION_INFO_get0_professionOIDs(const pi : PPROFESSION_INFO):Pstack_st_ASN1_OBJECT;
begin
    Result := pi.professionOIDs;
end;


procedure PROFESSION_INFO_set0_professionOIDs( pi : PPROFESSION_INFO; po : Pstack_st_ASN1_OBJECT);
begin
    sk_ASN1_OBJECT_pop_free(pi.professionOIDs, ASN1_OBJECT_free);
    pi.professionOIDs := po;
end;


function PROFESSION_INFO_get0_registrationNumber(const pi : PPROFESSION_INFO):PASN1_PRINTABLESTRING;
begin
    Result := pi.registrationNumber;
end;


procedure PROFESSION_INFO_set0_registrationNumber( pi : PPROFESSION_INFO; rn : PASN1_PRINTABLESTRING);
begin
    ASN1_PRINTABLESTRING_free(pi.registrationNumber);
    pi.registrationNumber := rn;
end;



function ADMISSION_SYNTAX_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM ($1, 16, @ADMISSION_SYNTAX_seq_tt,
                  sizeof(ADMISSION_SYNTAX_seq_tt) div sizeof(TASN1_TEMPLATE),
                  Pointer(0) , sizeof(TADMISSION_SYNTAX), 'ADMISSION_SYNTAX');

   Result := @local_it;
end;

initialization
   ossl_v3_ext_admission := get_V3_EXT_METHOD(
    NID_x509ExtAdmission,   // .ext_nid = */
    0,                      // .ext_flags = */
    @ADMISSION_SYNTAX_it, // .it = */
    nil, nil, nil, nil,
    nil,                   // .i2s = */
    nil,                   // .s2i = */
    nil,                   // .i2v = */
    nil,                   // .v2i = */
    @i2r_ADMISSION_SYNTAX,  // .i2r = */
    nil,                   // .r2i = */
    nil                    // extension-specific data */
);

   ADMISSION_SYNTAX_seq_tt := [
    get_ASN1_TEMPLATE( (($1)), 0,  size_t(@PADMISSION_SYNTAX(0). admissionAuthority), 'admissionAuthority', GENERAL_NAME_it) ,
    get_ASN1_TEMPLATE( (($2 shl  1)), 0,  size_t(@PADMISSION_SYNTAX(0). contentsOfAdmissions), 'contentsOfAdmissions', ADMISSIONS_it)
   ] ;

   ADMISSIONS_seq_tt := [
    get_ASN1_TEMPLATE ( ((($2 shl 3) or ($2 shl 6))  or  (($1))), 0, size_t(@PADMISSIONS(0).admissionAuthority), 'admissionAuthority', GENERAL_NAME_it) ,
    get_ASN1_TEMPLATE ( ((($2 shl 3) or ($2 shl 6))  or  (($1))), (1), size_t(@PADMISSIONS(0).namingAuthority), 'namingAuthority', NAMING_AUTHORITY_it) ,
    get_ASN1_TEMPLATE ( (($2 shl 1)), 0, size_t(@PADMISSIONS(0).professionInfos), 'professionInfos', PROFESSION_INFO_it)
   ] ;

   NAMING_AUTHORITY_seq_tt := [
    get_ASN1_TEMPLATE( (($1)), 0, size_t(@PNAMING_AUTHORITY(0).namingAuthorityId), 'namingAuthorityId', ASN1_OBJECT_it) ,
    get_ASN1_TEMPLATE( (($1)), 0, size_t(@PNAMING_AUTHORITY(0).namingAuthorityUrl), 'namingAuthorityUrl', ASN1_IA5STRING_it) ,
    get_ASN1_TEMPLATE( (($1)), 0, size_t(@PNAMING_AUTHORITY(0).namingAuthorityText), 'namingAuthorityText', DIRECTORYSTRING_it)
   ] ;

    PROFESSION_INFO_seq_tt := [
        get_ASN1_TEMPLATE( ((($2 shl 3) or ($2 shl 6))  or  (($1))), 0, size_t(@PPROFESSION_INFO(0).namingAuthority), 'namingAuthority', NAMING_AUTHORITY_it) ,
        get_ASN1_TEMPLATE( (($2 shl 1)), 0, size_t(@PPROFESSION_INFO(0).professionItems), 'professionItems', DIRECTORYSTRING_it) ,
        get_ASN1_TEMPLATE( (($2 shl 1) or ($1)), 0, size_t(@PPROFESSION_INFO(0).professionOIDs), 'professionOIDs', ASN1_OBJECT_it) ,
        get_ASN1_TEMPLATE( (($1)), 0, size_t(@PPROFESSION_INFO(0).registrationNumber), 'registrationNumber', ASN1_PRINTABLESTRING_it) ,
        get_ASN1_TEMPLATE( (($1)), 0, size_t(@PPROFESSION_INFO(0).addProfessionInfo), 'addProfessionInfo', ASN1_OCTET_STRING_it)
    ] ;

end.
