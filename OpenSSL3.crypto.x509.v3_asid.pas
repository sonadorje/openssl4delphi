unit OpenSSL3.crypto.x509.v3_asid;

interface
uses OpenSSL.Api;

function ASIdentifiers_it:PASN1_ITEM;
function v2i_ASIdentifiers(const method : Pv3_ext_method; ctx : Pv3_ext_ctx; values : Pstack_st_CONF_VALUE):Pointer;
function d2i_ASIdentifiers(a : PPASIdentifiers;const _in : PPByte; len : long):PASIdentifiers;
  function i2d_ASIdentifiers(const a : PASIdentifiers; _out : PPByte):integer;
  function ASIdentifiers_new:PASIdentifiers;
  procedure ASIdentifiers_free( a : PASIdentifiers);
  function X509v3_asid_add_inherit( asid : PASIdentifiers; which : integer):integer;
  function d2i_ASIdentifierChoice(a : PPASIdentifierChoice;const _in : PPByte; len : long):PASIdentifierChoice;
  function i2d_ASIdentifierChoice(const a : PASIdentifierChoice; _out : PPByte):integer;
  function ASIdentifierChoice_new:PASIdentifierChoice;
  procedure ASIdentifierChoice_free( a : PASIdentifierChoice);
  function ASIdentifierChoice_it:PASN1_ITEM;
  function X509v3_asid_add_id_or_range( asid : PASIdentifiers; which : integer; min, max : PASN1_INTEGER):integer;
   function ASIdOrRange_cmp(a_, b_ : PPASIdOrRange):integer;
  function d2i_ASIdOrRange(a : PPASIdOrRange;const _in : PPByte; len : long):PASIdOrRange;
  function i2d_ASIdOrRange(const a : PASIdOrRange; _out : PPByte):integer;
  function ASIdOrRange_new:PASIdOrRange;
  procedure ASIdOrRange_free( a : PASIdOrRange);
  function ASIdOrRange_it:PASN1_ITEM;

  function d2i_ASRange(a : PPASRange;const _in : PPByte; len : long):PASRange;
  function i2d_ASRange(const a : PASRange; _out : PPByte):integer;
  function ASRange_new:PASRange;
  procedure ASRange_free( a : PASRange);
  function ASRange_it:PASN1_ITEM;
  function X509v3_asid_canonize( asid : PASIdentifiers):integer;
  function ASIdentifierChoice_canonize( choice : PASIdentifierChoice):integer;
  function extract_min_max( aor : PASIdOrRange; min, max : PPASN1_INTEGER):integer;
  function ASIdentifierChoice_is_canonical( choice : PASIdentifierChoice):integer;
   function i2r_ASIdentifiers(const method : PX509V3_EXT_METHOD; ext : Pointer; _out : PBIO; indent : integer):integer;
  function i2r_ASIdentifierChoice(_out : PBIO; choice : PASIdentifierChoice; indent : integer;const msg : PUTF8Char):integer;
  function X509v3_asid_validate_path( ctx : PX509_STORE_CTX):integer;
  function asid_validate_path_internal( ctx : PX509_STORE_CTX; chain : Pstack_st_X509; ext : PASIdentifiers):integer;
  function X509v3_asid_is_canonical( asid : PASIdentifiers):integer;
   function asid_contains( parent, child : PASIdOrRanges):integer;

var
  ossl_v3_asid :TX509V3_EXT_METHOD;
  ASIdentifiers_seq_tt, ASIdentifierChoice_ch_tt,
  ASIdOrRange_ch_tt, ASRange_seq_tt :array of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.bio.bio_print, openssl3.crypto.x509v3, OpenSSL3.common,
     OpenSSL3.Err, OpenSSL3.openssl.conf, OpenSSL3.crypto.x509.v3_utl,
     openssl3.crypto.bio.bio_lib,  openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc,  openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.a_bitstr,  openssl3.crypto.asn1.a_octet,
     openssl3.crypto.asn1.a_int,  openssl3.crypto.bn.bn_lib,
     openssl3.crypto.bn.bn_word,
     openssl3.crypto.o_str, openssl3.crypto.mem, openssl3.crypto.x509;





function asid_contains( parent, child : PASIdOrRanges):integer;
var
  p_min, p_max, c_min, c_max : PASN1_INTEGER;
  p, c : integer;
begin
    p_min := nil;
    p_max := nil;
    c_min := nil;
    c_max := nil;
    if (child = nil)  or  (parent = child) then Exit(1);
    if parent = nil then Exit(0);
    p := 0;
    for c := 0 to sk_ASIdOrRange_num(child)-1 do
    begin
        if 0>=extract_min_max(sk_ASIdOrRange_value(child, c) , @c_min, @c_max) then
            Exit(0);
        while True do
        begin
            Inc(p);
            if p >= sk_ASIdOrRange_num(parent) then
                Exit(0);
            if 0>=extract_min_max(sk_ASIdOrRange_value(parent, p) , @p_min,
                                 @p_max) then
                Exit(0);
            if ASN1_INTEGER_cmp(p_max, c_max) < 0  then
                continue;
            if ASN1_INTEGER_cmp(p_min, c_min) > 0  then
                Exit(0);
            break;
        end;
    end;
    Result := 1;
end;



function X509v3_asid_is_canonical( asid : PASIdentifiers):integer;
begin
    Result := Int( (asid = nil)  or
            ( (ASIdentifierChoice_is_canonical(asid.asnum)>0)  and
              (ASIdentifierChoice_is_canonical(asid.rdi)>0)) );
end;

function asid_validate_path_internal( ctx : PX509_STORE_CTX; chain : Pstack_st_X509; ext : PASIdentifiers):integer;
var
  child_as,child_rdi : PASIdOrRanges;
  i,
  ret,inherit_as, inherit_rdi: integer;
  x        : PX509;
  label _done;
  procedure validation_err( _err_ : integer);
  begin
      if ctx <> nil then
      begin
        ctx.error := _err_;
        ctx.error_depth := i;
        ctx.current_cert := x;
        ret := ctx.verify_cb(0, ctx);
      end
      else
      begin
        ret := 0;
      end;
      //if 0>=ret then goto_done;
  end;
begin
    child_as := nil; child_rdi := nil;
    ret := 1; inherit_as := 0; inherit_rdi := 0;
    if (not ossl_assert( (chain <> nil)  and  (sk_X509_num(chain) > 0) ))
             or  (not ossl_assert( (ctx <> nil)  or  (ext <> nil) ))
             or  (not ossl_assert( (ctx = nil)  or  (Assigned(ctx.verify_cb)) )) then
    begin
        if ctx <> nil then
            ctx.error := X509_V_ERR_UNSPECIFIED;
        Exit(0);
    end;
    {
     * Figure out where to start.  If we don't have an extension to
     * check, we're done.  Otherwise, check canonical form and
     * set up for walking up the chain.
     }
    if ext <> nil then
    begin
        i := -1;
        x := nil;
    end
    else
    begin
        i := 0;
        x := sk_X509_value(chain, i);
        ext := x.rfc3779_asid;
        if ext = nil then
            goto _done;
    end;
    if 0>=X509v3_asid_is_canonical(ext) then
    begin
        validation_err(X509_V_ERR_INVALID_EXTENSION);
        if 0>=ret then goto _done;
    end;
    if ext.asnum <> nil then
    begin
        case ext.asnum.&type of
        ASIdentifierChoice_inherit:
            inherit_as := 1;
            //break;
        ASIdentifierChoice_asIdsOrRanges:
            child_as := ext.asnum.u.asIdsOrRanges;
            //break;
        end;
    end;
    if ext.rdi <> nil then
    begin
        case ext.rdi.&type of
        ASIdentifierChoice_inherit:
            inherit_rdi := 1;
            //break;
        ASIdentifierChoice_asIdsOrRanges:
            child_rdi := ext.rdi.u.asIdsOrRanges;
            //break;
        end;
    end;
    {
     * Now walk up the chain.  Extensions must be in canonical form, no
     * cert may list resources that its parent doesn't list.
     }
    PostInc(i);
    while i < sk_X509_num(chain) do
    begin
        x := sk_X509_value(chain, i);
        if not ossl_assert(x <> nil) then
        begin
            if ctx <> nil then
               ctx.error := X509_V_ERR_UNSPECIFIED;
            Exit(0);
        end;
        if x.rfc3779_asid = nil then
        begin
            if (child_as <> nil)  or  (child_rdi <> nil) then
            begin
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                if 0>=ret then goto _done;
            end;
            continue;
        end;
        if 0>=X509v3_asid_is_canonical(x.rfc3779_asid) then
        begin
            validation_err(X509_V_ERR_INVALID_EXTENSION);
            if 0>=ret then goto _done;
        end;
        if (x.rfc3779_asid.asnum = nil)  and  (child_as <> nil) then
        begin
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            if 0>=ret then goto _done;
            child_as := nil;
            inherit_as := 0;
        end;
        if (x.rfc3779_asid.asnum <> nil)  and
           (x.rfc3779_asid.asnum.&type = ASIdentifierChoice_asIdsOrRanges) then
        begin
            if  (inherit_as > 0) or
                (asid_contains(x.rfc3779_asid.asnum.u.asIdsOrRanges,
                                 child_as) > 0) then
            begin
                child_as := x.rfc3779_asid.asnum.u.asIdsOrRanges;
                inherit_as := 0;
            end
            else
            begin
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                if 0>=ret then goto _done;
            end;
        end;
        if (x.rfc3779_asid.rdi = nil)  and  (child_rdi <> nil) then
        begin
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            if 0>=ret then goto _done;
            child_rdi := nil;
            inherit_rdi := 0;
        end;
        if (x.rfc3779_asid.rdi <> nil)  and
           (x.rfc3779_asid.rdi.&type = ASIdentifierChoice_asIdsOrRanges) then
        begin
            if (inherit_rdi > 0)  or
               (asid_contains(x.rfc3779_asid.rdi.u.asIdsOrRanges,
                              child_rdi) > 0)  then
            begin
                child_rdi := x.rfc3779_asid.rdi.u.asIdsOrRanges;
                inherit_rdi := 0;
            end
            else
            begin
                validation_err(X509_V_ERR_UNNESTED_RESOURCE);
                if 0>=ret then goto _done;
            end;
        end;
        PostInc(i);
    end;
    {
     * Trust anchor can't inherit.
     }
    if not ossl_assert(x <> nil) then
    begin
        if ctx <> nil then
            ctx.error := X509_V_ERR_UNSPECIFIED;
        Exit(0);
    end;
    if x.rfc3779_asid <> nil then
    begin
        if (x.rfc3779_asid.asnum <> nil)  and
           (x.rfc3779_asid.asnum.&type = ASIdentifierChoice_inherit) then
        begin
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            if 0>=ret then goto _done;
        end;
        if (x.rfc3779_asid.rdi <> nil)  and
           (x.rfc3779_asid.rdi.&type = ASIdentifierChoice_inherit) then
        begin
            validation_err(X509_V_ERR_UNNESTED_RESOURCE);
            if 0>=ret then goto _done;
        end;
    end;
 _done:
    Result := ret;
end;


function X509v3_asid_validate_path( ctx : PX509_STORE_CTX):integer;
begin
    if (ctx.chain = nil)
             or  (sk_X509_num(ctx.chain) = 0)
             or  (not Assigned(ctx.verify_cb))  then
    begin
        ctx.error := X509_V_ERR_UNSPECIFIED;
        Exit(0);
    end;
    Result := asid_validate_path_internal(ctx, ctx.chain, nil);
end;


function i2r_ASIdentifierChoice(_out : PBIO; choice : PASIdentifierChoice; indent : integer;const msg : PUTF8Char):integer;
var
  i : integer;

  s : PUTF8Char;

  aor : PASIdOrRange;
begin
    if choice = nil then
       Exit(1);
    BIO_printf(_out, ' %*s%s:\n' , [indent, ' ' , msg]);
    case choice.&type of
    ASIdentifierChoice_inherit:
        BIO_printf(_out, ' %*sinherit\n' , [indent + 2, ' '] );
        //break;
    ASIdentifierChoice_asIdsOrRanges:
    begin
        for i := 0 to sk_ASIdOrRange_num(choice.u.asIdsOrRanges)-1 do
        begin
            aor := sk_ASIdOrRange_value(choice.u.asIdsOrRanges, i);
            case aor.&type of
                ASIdOrRange_id:
                begin
                    s := i2s_ASN1_INTEGER(nil, aor.u.id);
                    if s = nil then
                        Exit(0);
                    BIO_printf(_out, ' %*s%s\n' , [indent + 2, ' ' , s]);
                    OPENSSL_free(s);
                end;
                ASIdOrRange_range:
                begin
                    s := i2s_ASN1_INTEGER(nil, aor.u.range.min);
                    if s = nil then
                        Exit(0);
                    BIO_printf(_out, ' %*s%s-' , [indent + 2, ' ' , s]);
                    OPENSSL_free(s);
                    s := i2s_ASN1_INTEGER(nil, aor.u.range.max);
                    if s = nil then
                        Exit(0);
                    BIO_printf(_out, ' %s'#10 , [s]);
                    OPENSSL_free(s);
                end;
                else
                    Exit(0);
            end;
        end;
    end;
    else
        Exit(0);
    end;
    Result := 1;
end;



function i2r_ASIdentifiers(const method : PX509V3_EXT_METHOD; ext : Pointer; _out : PBIO; indent : integer):integer;
var
  asid : PASIdentifiers;
begin
    asid := ext;
    Result := Int( (i2r_ASIdentifierChoice(_out, asid.asnum, indent,
                                   ' Autonomous System Numbers' )>0)  and
                   (i2r_ASIdentifierChoice(_out, asid.rdi, indent,
                                   ' Routing Domain Identifiers' )>0) );
end;

function ASIdentifierChoice_is_canonical( choice : PASIdentifierChoice):integer;
var
  a_max_plus_one,
  orig           : PASN1_INTEGER;
  bn             : PBIGNUM;
  i,
  ret            : integer;
  a,
  b              : PASIdOrRange;
  a_min,
  a_max,
  b_min,
  b_max          : PASN1_INTEGER;

  label _done;
  function get_bn: PBIGNUM;
  begin
     bn := BN_new() ;
     Result := bn;
  end;
begin
    a_max_plus_one := nil;
    bn := nil;
    ret := 0;
    {
     * Empty element or inheritance is canonical.
     }
    if (choice = nil)  or  (choice.&type = ASIdentifierChoice_inherit) then
       Exit(1);
    {
     * If not a list, or if empty list, it's broken.
     }
    if (choice.&type <> ASIdentifierChoice_asIdsOrRanges)  or
       (sk_ASIdOrRange_num(choice.u.asIdsOrRanges) = 0)  then
        Exit(0);
    {
     * It's a list, check it.
     }
    for i := 0 to sk_ASIdOrRange_num(choice.u.asIdsOrRanges) - 1-1 do
    begin
        a := sk_ASIdOrRange_value(choice.u.asIdsOrRanges, i);
        b := sk_ASIdOrRange_value(choice.u.asIdsOrRanges, i + 1);
        a_min := nil;
        a_max := nil;
        b_min := nil;
        b_max := nil;
        if (0>= extract_min_max(a, @a_min, @a_max))  or
           (0>= extract_min_max(b, @b_min, @b_max))  then
            goto _done ;
        {
         * Punt misordered list, overlapping start, or inverted range.
         }
        if (ASN1_INTEGER_cmp(a_min, b_min) >= 0)  or
           (ASN1_INTEGER_cmp(a_min, a_max) > 0)  or
           (ASN1_INTEGER_cmp(b_min, b_max) > 0)  then
            goto _done ;
        {
         * Calculate a_max + 1 to check for adjacency.
         }
        if ( (bn = nil)  and  (get_bn = nil) )  or
           ( ASN1_INTEGER_to_BN(a_max, bn) = nil ) or
           (0>= BN_add_word(bn, 1)) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _done ;
        end;
        orig := a_max_plus_one;
        a_max_plus_one := BN_to_ASN1_INTEGER(bn, orig);
        if (a_max_plus_one =  nil) then
        begin
            a_max_plus_one := orig;
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _done ;
        end;
        {
         * Punt if adjacent or overlapping.
         }
        if ASN1_INTEGER_cmp(a_max_plus_one, b_min) >= 0 then
            goto _done ;
    end;
    {
     * Check for inverted range.
     }
    i := sk_ASIdOrRange_num(choice.u.asIdsOrRanges) - 1;
    begin
        a := sk_ASIdOrRange_value(choice.u.asIdsOrRanges, i);
        if (a <> nil)  and  (a.&type = ASIdOrRange_range) then
        begin
            if (0>= extract_min_max(a, @a_min, @a_max))
                     or  (ASN1_INTEGER_cmp(a_min, a_max) > 0)  then
                goto _done ;
        end;
    end;
    ret := 1;
 _done:
    ASN1_INTEGER_free(a_max_plus_one);
    BN_free(bn);
    Result := ret;
end;

function extract_min_max( aor : PASIdOrRange; min, max : PPASN1_INTEGER):integer;
begin
    if not ossl_assert(aor <> nil) then
        Exit(0);
    case aor.&type of
        ASIdOrRange_id:
        begin
            min^ := aor.u.id;
            max^ := aor.u.id;
            Exit(1);
        end;
        ASIdOrRange_range:
        begin
            min^ := aor.u.range.min;
            max^ := aor.u.range.max;
            Exit(1);
        end;
    end;
    Result := 0;
end;




function ASIdentifierChoice_canonize( choice : PASIdentifierChoice):integer;
var
  a_max_plus_one,
  orig           : PASN1_INTEGER;
  bn             : PBIGNUM;
  i,
  ret            : integer;
  a,
  b              : PASIdOrRange;
  b_min, b_max,
  a_min          : PASN1_INTEGER;
  r              : PASRange;
  a_max          : PASN1_INTEGER;
  label _err, _done;

  function get_bn: PBIGNUM;
  begin
     bn := BN_new() ;
     Result := bn;
  end;
begin
    a_max_plus_one := nil;
    bn := nil;
    ret := 0;
    {
     * Nothing to do for empty element or inheritance.
     }
    if (choice = nil)  or  (choice.&type = ASIdentifierChoice_inherit) then
       Exit(1);
    {
     * If not a list, or if empty list, it's broken.
     }
    if (choice.&type <> ASIdentifierChoice_asIdsOrRanges)  or
       ( sk_ASIdOrRange_num(choice.u.asIdsOrRanges) = 0)  then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        Exit(0);
    end;
    {
     * We have a non-empty list.  Sort it.
     }
    sk_ASIdOrRange_sort(choice.u.asIdsOrRanges);
    {
     * Now check for errors and suboptimal encoding, rejecting the
     * former and fixing the latter.
     }
    i := 0;
    while i<= sk_ASIdOrRange_num(choice.u.asIdsOrRanges) - 1-1 do
    begin
        a := sk_ASIdOrRange_value(choice.u.asIdsOrRanges, i);
        b := sk_ASIdOrRange_value(choice.u.asIdsOrRanges, i + 1);
        a_min := nil; a_max := nil; b_min := nil; b_max := nil;
        if (0>= extract_min_max(a, @a_min, @a_max)) or
           (0>= extract_min_max(b, @b_min, @b_max))  then
            goto _done ;
        {
         * Make sure we're properly sorted (paranoia).
         }
        if not ossl_assert(ASN1_INTEGER_cmp(a_min, b_min) <= 0)  then
            goto _done ;
        {
         * Punt inverted ranges.
         }
        if (ASN1_INTEGER_cmp(a_min, a_max) > 0)  or
           (ASN1_INTEGER_cmp(b_min, b_max) > 0) then
            goto _done ;
        {
         * Check for overlaps.
         }
        if ASN1_INTEGER_cmp(a_max, b_min) >= 0  then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
            goto _done ;
        end;
        {
         * Calculate a_max + 1 to check for adjacency.
         }

        if ( (bn = nil)  and  (get_bn = nil) )  or
           ( ASN1_INTEGER_to_BN(a_max, bn) = nil)  or
           ( 0 >= BN_add_word(bn, 1)) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _done ;
        end;
        orig := a_max_plus_one;
        a_max_plus_one := BN_to_ASN1_INTEGER(bn, orig);
        if (a_max_plus_one = nil) then
        begin
            a_max_plus_one := orig;
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _done ;
        end;
        {
         * If a and b are adjacent, merge them.
         }
        if ASN1_INTEGER_cmp(a_max_plus_one, b_min) = 0  then
        begin
            case a.&type of
                ASIdOrRange_id:
                begin
                    r := OPENSSL_malloc(sizeof(r^));
                    if r = nil then
                    begin
                        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                        goto _done ;
                    end;
                    r.min := a_min;
                    r.max := b_max;
                    a.&type := ASIdOrRange_range;
                    a.u.range := r;
                end;
                ASIdOrRange_range:
                begin
                    ASN1_INTEGER_free(a.u.range.max);
                    a.u.range.max := b_max;
                end;
            end;

            case b.&type of
            ASIdOrRange_id:
                b.u.id := nil;
                //break;
            ASIdOrRange_range:
                b.u.range.max := nil;
                //break;
            end;
            ASIdOrRange_free(b);
            sk_ASIdOrRange_delete(choice.u.asIdsOrRanges, i + 1);
            Dec(i);
            continue;
        end;
        Inc(i);
    end;
    {
     * Check for final inverted range.
     }
    i := sk_ASIdOrRange_num(choice.u.asIdsOrRanges) - 1;
    begin
        a := sk_ASIdOrRange_value(choice.u.asIdsOrRanges, i);
        if (a <> nil)  and  (a.&type = ASIdOrRange_range) then
        begin
            if (0>= extract_min_max(a, @a_min, @a_max))
                     or  (ASN1_INTEGER_cmp(a_min, a_max) > 0) then
                goto _done ;
        end;
    end;
    { Paranoia }
    if not ossl_assert(ASIdentifierChoice_is_canonical(choice)>0) then
        goto _done ;
    ret := 1;
 _done:
    ASN1_INTEGER_free(a_max_plus_one);
    BN_free(bn);
    Result := ret;
end;




function X509v3_asid_canonize( asid : PASIdentifiers):integer;
begin
    Result := Int( (asid = nil)  or
                   ( (ASIdentifierChoice_canonize(asid.asnum) > 0)  and
                     (ASIdentifierChoice_canonize(asid.rdi) > 0 ) ) );
end;



function ASRange_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @ASRange_seq_tt,
                         sizeof(ASRange_seq_tt) div sizeof(TASN1_TEMPLATE),
             Pointer(0) , sizeof(ASRange), ' ASRange');

   Result := @local_it;
end;




function d2i_ASRange(a : PPASRange;const _in : PPByte; len : long):PASRange;
begin
 Result := PASRange(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, ASRange_it));
end;


function i2d_ASRange(const a : PASRange; _out : PPByte):integer;
begin
 Result := ASN1_item_i2d(PASN1_VALUE( a), _out, ASRange_it);
end;


function ASRange_new:PASRange;
begin
 Result := PASRange(ASN1_item_new(ASRange_it));
end;


procedure ASRange_free( a : PASRange);
begin
 ASN1_item_free(PASN1_VALUE( a), ASRange_it);
end;




function ASIdOrRange_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($2, size_t(@PASIdOrRange(0).&type) ,
                   @ASIdOrRange_ch_tt, sizeof(ASIdOrRange_ch_tt) div sizeof(TASN1_TEMPLATE),
                   Pointer(0) , sizeof(ASIdOrRange), ' ASIdOrRange');
   Result := @local_it;
end;

function d2i_ASIdOrRange(a : PPASIdOrRange;const _in : PPByte; len : long):PASIdOrRange;
begin
   Result := PASIdOrRange(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, ASIdOrRange_it));
end;


function i2d_ASIdOrRange(const a : PASIdOrRange; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASIdOrRange_it);
end;


function ASIdOrRange_new:PASIdOrRange;
begin
   Result := PASIdOrRange(ASN1_item_new(ASIdOrRange_it));
end;


procedure ASIdOrRange_free( a : PASIdOrRange);
begin
 ASN1_item_free(PASN1_VALUE( a), (ASIdOrRange_it));
end;


function ASIdOrRange_cmp( a_, b_ : PPASIdOrRange):integer;
var
  a, b : PASIdOrRange;

  r : integer;
begin
    a := a_^;
    b := b_^;
    assert( ( (a.&type = ASIdOrRange_id)  and  (a.u.id <> nil) )  or
            ( (a.&type = ASIdOrRange_range)  and  (a.u.range <> nil)  and
             (a.u.range.min <> nil)  and  (a.u.range.max <> nil) ) );
    assert( ( (b.&type = ASIdOrRange_id)  and  (b.u.id <> nil) )  or
            ( (b.&type = ASIdOrRange_range)  and  (b.u.range <> nil)  and
              (b.u.range.min <> nil)  and  (b.u.range.max <> nil) ) );
    if (a.&type = ASIdOrRange_id)  and  (b.&type = ASIdOrRange_id) then
       Exit(ASN1_INTEGER_cmp(a.u.id, b.u.id));
    if (a.&type = ASIdOrRange_range)  and  (b.&type = ASIdOrRange_range) then
    begin
        r := ASN1_INTEGER_cmp(a.u.range.min, b.u.range.min);
        Exit(get_result(r <> 0 , r , ASN1_INTEGER_cmp(a.u.range.max,
                                             b.u.range.max)));
    end;
    if a.&type = ASIdOrRange_id then
       Exit(ASN1_INTEGER_cmp(a.u.id, b.u.range.min))
    else
        Result := ASN1_INTEGER_cmp(a.u.range.min, b.u.id);
end;


function X509v3_asid_add_id_or_range( asid : PASIdentifiers; which : integer; min, max : PASN1_INTEGER):integer;
var
  choice : PPASIdentifierChoice;
  aor : PASIdOrRange;
  label _err;
begin
    if asid = nil then Exit(0);
    case which of
    V3_ASID_ASNUM:
        choice := @asid.asnum;
        //break;
    V3_ASID_RDI:
        choice := @asid.rdi;
        //break;
    else
        Exit(0);
    end;
    if (choice^ <> nil)  and  (choice^.&type = ASIdentifierChoice_inherit) then
        Exit(0);
    if choice^ = nil then
    begin
        choice^ := ASIdentifierChoice_new();
        if choice^ = nil then
            Exit(0);
        choice^.u.asIdsOrRanges := sk_ASIdOrRange_new(ASIdOrRange_cmp);
        if choice^.u.asIdsOrRanges = nil then
            Exit(0);
        (choice^).&type := ASIdentifierChoice_asIdsOrRanges;
    end;
    aor := ASIdOrRange_new();
    if aor  = nil then
        Exit(0);
    if max = nil then
    begin
        aor.&type := ASIdOrRange_id;
        aor.u.id := min;
    end
    else
    begin
        aor.&type := ASIdOrRange_range;
        aor.u.range := ASRange_new();
        if aor.u.range = nil then
            goto _err ;
        ASN1_INTEGER_free(aor.u.range.min);
        aor.u.range.min := min;
        ASN1_INTEGER_free(aor.u.range.max);
        aor.u.range.max := max;
    end;
    if 0>= (sk_ASIdOrRange_push(choice^.u.asIdsOrRanges, aor)) then
        goto _err ;
    Exit(1);
 _err:
    ASIdOrRange_free(aor);
    Result := 0;
end;




function ASIdentifierChoice_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM ($2, size_t(@PASIdentifierChoice(0).&type) ,
                         @ASIdentifierChoice_ch_tt,
             sizeof(ASIdentifierChoice_ch_tt) div sizeof(TASN1_TEMPLATE),
             Pointer(0) , sizeof(ASIdentifierChoice), ' ASIdentifierChoice');

  Result := @local_it;
end;






function d2i_ASIdentifierChoice(a : PPASIdentifierChoice;const _in : PPByte; len : long):PASIdentifierChoice;
begin
   Result := PASIdentifierChoice( ASN1_item_d2i(PPASN1_VALUE( a), _in, len, ASIdentifierChoice_it));
end;


function i2d_ASIdentifierChoice(const a : PASIdentifierChoice; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ASIdentifierChoice_it);
end;


function ASIdentifierChoice_new:PASIdentifierChoice;
begin
   Result := PASIdentifierChoice( ASN1_item_new(ASIdentifierChoice_it));
end;


procedure ASIdentifierChoice_free( a : PASIdentifierChoice);
begin
 ASN1_item_free(PASN1_VALUE( a), ASIdentifierChoice_it);
end;




function X509v3_asid_add_inherit( asid : PASIdentifiers; which : integer):integer;
var
  choice : PPASIdentifierChoice;
begin
    if asid = nil then Exit(0);
    case which of
    V3_ASID_ASNUM:
        choice := @asid.asnum;
        //break;
    V3_ASID_RDI:
        choice := @asid.rdi;
        //break;
    else
        Exit(0);
    end;
    if choice^ = nil then
    begin
        choice^ := ASIdentifierChoice_new();
        if ( choice^ = nil) then
            Exit(0);
        choice^.u.inherit := ASN1_NULL_new();
        if ( choice^.u.inherit = nil) then
            Exit(0);
        (choice^).&type := ASIdentifierChoice_inherit;
    end;
    Result := int(choice^.&type = ASIdentifierChoice_inherit);
end;





function d2i_ASIdentifiers(a : PPASIdentifiers;const _in : PPByte; len : long):PASIdentifiers;
begin
   Result := PASIdentifiers(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, ASIdentifiers_it));
end;


function i2d_ASIdentifiers(const a : PASIdentifiers; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE( a), _out, ASIdentifiers_it);
end;


function ASIdentifiers_new:PASIdentifiers;
begin
   Result := PASIdentifiers(ASN1_item_new(ASIdentifiers_it));
end;


procedure ASIdentifiers_free( a : PASIdentifiers);
begin
 ASN1_item_free(PASN1_VALUE( a), ASIdentifiers_it);
end;

function v2i_ASIdentifiers(const method : Pv3_ext_method; ctx : Pv3_ext_ctx; values : Pstack_st_CONF_VALUE):Pointer;
var
  min, max : PASN1_INTEGER;
  asid : PASIdentifiers;
  i : integer;
  val : PCONF_VALUE;
  i1, i2, i3, is_range, which : integer;
  s : PUTF8Char;
  label _err;
begin
    min := nil; max := nil;
    asid := nil;
    asid := ASIdentifiers_new();
    if asid = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to sk_CONF_VALUE_num(values)-1 do
    begin
        val := sk_CONF_VALUE_value(values, i);
        i1 := 0; i2 := 0; i3 := 0; is_range := 0; which := 0;
        {
         * Figure out whether this is an AS or an RDI.
         }
        if 0>= ossl_v3_name_cmp(val.name, ' AS')  then
        begin
            which := V3_ASID_ASNUM;
        end
        else
        if (0>= ossl_v3_name_cmp(val.name, ' RDI' )) then
        begin
            which := V3_ASID_RDI;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_NAME_ERROR);
            X509V3_conf_add_error_name_value(val);
            goto _err ;
        end;
        {
         * Handle inheritance.
         }
        if strcmp(val.value, ' inherit') = 0 then
        begin
            if X509v3_asid_add_inherit(asid, which) > 0 then
                continue;
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_INHERITANCE);
            X509V3_conf_add_error_name_value(val);
            goto _err ;
        end;
        {
         * Number, range, or mistake, pick it apart and figure out which.
         }
        i1 := strspn(val.value, ' 0123456789' );
        if val.value[i1] = #0 then
        begin
            is_range := 0;
        end
        else
        begin
            is_range := 1;
            i2 := i1 + strspn(val.value + i1, '  '#9 );
            if val.value[i2] <> '-' then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_ASNUMBER);
                X509V3_conf_add_error_name_value(val);
                goto _err ;
            end;
            PostInc(i2);
            i2 := i2 + strspn(val.value + i2, '  '#9 );
            i3 := i2 + strspn(val.value + i2, ' 0123456789' );
            if val.value[i3] <> #0 then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_ASRANGE);
                X509V3_conf_add_error_name_value(val);
                goto _err ;
            end;
        end;
        {
         * Syntax is ok, read and add it.
         }
        if 0>= is_range then
        begin
            if 0>= X509V3_get_value_int(val, @min) then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
        end
        else
        begin
            OPENSSL_strdup(s, val.value);
            if s = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            s[i1] := #0;
            min := s2i_ASN1_INTEGER(nil, s);
            max := s2i_ASN1_INTEGER(nil, s + i2);
            OPENSSL_free(s);
            if (min = nil)  or  (max = nil) then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            if ASN1_INTEGER_cmp(min, max) > 0 then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
                goto _err ;
            end;
        end;
        if 0>= X509v3_asid_add_id_or_range(asid, which, min, max) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        min := nil; max := nil;
    end;
    {
     * Canonize the result, then we're done.
     }
    if 0>= X509v3_asid_canonize(asid) then
        goto _err ;
    Exit(asid);
 _err:
    ASIdentifiers_free(asid);
    ASN1_INTEGER_free(min);
    ASN1_INTEGER_free(max);
    Result := nil;
end;




function ASIdentifiers_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @ASIdentifiers_seq_tt,
                         sizeof(ASIdentifiers_seq_tt) div sizeof(TASN1_TEMPLATE),
            Pointer( 0), sizeof(TASIdentifiers), ' ASIdentifiers');

   Result := @local_it;
end;



initialization
   ossl_v3_asid := get_V3_EXT_METHOD(
      NID_sbgp_autonomousSysNum,  // nid
      0,                          // flags
      ASIdentifiers_it, // template
      nil, nil, nil, nil,                 // old functions, ignored
      nil,                          // i2s
      nil,                          // s2i
      nil,                          // i2v
      v2i_ASIdentifiers,          // v2i
      i2r_ASIdentifiers,          // i2r
      nil,                          // r2i
      nil                       // extension-specific data
  );

  ASIdentifiers_seq_tt := [
    get_ASN1_TEMPLATE ( ( ($2 shl  3) or ($2 shl 6))  or  $1, 0, size_t(@PASIdentifiers(0).asnum), ' asnum' , ASIdentifierChoice_it) ,
    get_ASN1_TEMPLATE ( ( ($2 shl  3) or ($2 shl 6))  or  $1, 1, size_t(@PASIdentifiers(0).rdi), ' rdi' , ASIdentifierChoice_it)
  ] ;

  ASIdentifierChoice_ch_tt := [
    get_ASN1_TEMPLATE ( 0,  0,  size_t(@PASIdentifierChoice(0).u.inherit), ' u.inherit' , ASN1_NULL_it) ,
    get_ASN1_TEMPLATE (($2 shl  1), 0,  size_t(@PASIdentifierChoice(0).u.asIdsOrRanges), ' u.asIdsOrRanges' , ASIdOrRange_it)
  ] ;

  ASIdOrRange_ch_tt := [
    get_ASN1_TEMPLATE ( 0,  0,  size_t(@PASIdOrRange(0).u.id), ' u.id' , ASN1_INTEGER_it) ,
    get_ASN1_TEMPLATE ( 0,  0,  size_t(@PASIdOrRange(0).u.range), ' u.range' , ASRange_it)
  ] ;

  ASRange_seq_tt := [
    get_ASN1_TEMPLATE ( 0,  0,  size_t(@PASRange(0). min), ' min' , ASN1_INTEGER_it) ,
    get_ASN1_TEMPLATE ( 0,  0,  size_t(@PASRange(0). max), ' max' , ASN1_INTEGER_it)
  ] ;

end.
