unit openssl3.crypto.ffc.ffc_params;

interface
uses OpenSSL.Api;

 function ossl_ffc_params_copy(dst : PFFC_PARAMS;const src : PFFC_PARAMS):integer;
 function ffc_bn_cpy(dst : PPBIGNUM;const src : PBIGNUM):integer;
 function ossl_ffc_params_todata(const ffc : PFFC_PARAMS; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
 procedure ossl_ffc_params_set0_pqg( d : PFFC_PARAMS; p, q, g : PBIGNUM);
 function ossl_ffc_params_set_seed(params : PFFC_PARAMS;const seed : PByte; seedlen : size_t):integer;
  procedure ossl_ffc_params_enable_flags( params : PFFC_PARAMS; flags : uint32; enable : integer);
  function ossl_ffc_set_digest(params : PFFC_PARAMS;const alg, props : PUTF8Char):integer;
  procedure ossl_ffc_params_set0_j( d : PFFC_PARAMS; j : PBIGNUM);
  function ossl_ffc_params_cmp(const a, b : PFFC_PARAMS; ignore_q : integer):integer;
  procedure ossl_ffc_params_set_gindex( params : PFFC_PARAMS; index : integer);
  procedure ossl_ffc_params_set_pcounter( params : PFFC_PARAMS; index : integer);
  procedure ossl_ffc_params_set_h( params : PFFC_PARAMS; index : integer);
  function ossl_ffc_params_set_validate_params(params : PFFC_PARAMS;const seed : PByte; seedlen : size_t; counter : integer):integer;
  procedure ossl_ffc_params_cleanup( params : PFFC_PARAMS);
   procedure ossl_ffc_params_init( params : PFFC_PARAMS);
  procedure ossl_ffc_params_get0_pqg(const d : PFFC_PARAMS; p, q, g : PPBIGNUM);
  procedure ossl_ffc_params_get_validate_params(const params : PFFC_PARAMS; seed : PPByte; seedlen : Psize_t; pcounter : PInteger);
   function ossl_ffc_params_print(bp : PBIO;const ffc : PFFC_PARAMS; indent : integer):integer;


implementation
uses
  openssl3.crypto.mem, openssl3.crypto.o_str, openssl3.crypto.param_build_set,
  openssl3.crypto.ffc.ffc_dh, openssl3.crypto.bn.bn_lib,
  openssl3.crypto.bio.bio_print,
  openssl3.crypto.asn1.t_pkey, openssl3.crypto.bio.bio_lib;





function ossl_ffc_params_print(bp : PBIO;const ffc : PFFC_PARAMS; indent : integer):integer;
var
  i : size_t;
  label _err;
begin
    if 0>=ASN1_bn_print(bp, 'prime P:', ffc.p, nil, indent ) then
        goto _err;
    if 0>=ASN1_bn_print(bp, 'generator G:', ffc.g, nil, indent ) then
        goto _err;
    if (ffc.q <> nil)
         and  (0>=ASN1_bn_print(bp, 'subgroup order Q:', ffc.q, nil, indent )) then
        goto _err;
    if (ffc.j <> nil)
         and  (0>=ASN1_bn_print(bp, 'subgroup factor:', ffc.j, nil, indent) ) then
        goto _err;
    if ffc.seed <> nil then
    begin
        if (0>=BIO_indent(bp, indent, 128))
             or  (BIO_puts(bp, 'seed:') <= 0)  then
            goto _err;
        for i := 0 to ffc.seedlen-1 do
        begin
            if i mod 15 = 0 then  begin
                if (BIO_puts(bp, #10)  <= 0)
                     or  (0>=BIO_indent(bp, indent + 4, 128)) then
                    goto _err;
            end;
            if BIO_printf(bp, '%02x%s', [ffc.seed[i],
                           get_result(i + 1 = ffc.seedlen , '' , ':')] ) <= 0 then
                goto _err;
        end;
        if BIO_write(bp, PUTF8Char(#10), 1) <= 0  then
            Exit(0);
    end;
    if ffc.pcounter <> -1 then
    begin
        if (0>=BIO_indent(bp, indent, 128))
             or  (BIO_printf(bp, 'counter: %d'#10, [ffc.pcounter]) <= 0) then
            goto _err;
    end;
    Exit(1);
_err:
    Result := 0;
end;

procedure ossl_ffc_params_get_validate_params(const params : PFFC_PARAMS; seed : PPByte; seedlen : Psize_t; pcounter : PInteger);
begin
    if seed <> nil then seed^ := params.seed;
    if seedlen <> nil then seedlen^ := params.seedlen;
    if pcounter <> nil then pcounter^ := params.pcounter;
end;

procedure ossl_ffc_params_get0_pqg(const d : PFFC_PARAMS; p, q, g : PPBIGNUM);
begin
    if p <> nil then p^ := d.p;
    if q <> nil then q^ := d.q;
    if g <> nil then g^ := d.g;
end;





procedure ossl_ffc_params_init( params : PFFC_PARAMS);
begin
    memset(params, 0, sizeof( params^));
    params.pcounter := -1;
    params.gindex := FFC_UNVERIFIABLE_GINDEX;
    params.flags := FFC_PARAM_FLAG_VALIDATE_PQG;
end;





procedure ossl_ffc_params_cleanup( params : PFFC_PARAMS);
begin
    BN_free(params.p);
    BN_free(params.q);
    BN_free(params.g);
    BN_free(params.j);
    OPENSSL_free(Pointer(params.seed));
    ossl_ffc_params_init(params);
end;

function ossl_ffc_params_set_validate_params(params : PFFC_PARAMS;const seed : PByte; seedlen : size_t; counter : integer):integer;
begin
    if  0>= ossl_ffc_params_set_seed(params, seed, seedlen)  then
        Exit(0);
    params.pcounter := counter;
    Result := 1;
end;

procedure ossl_ffc_params_set_h( params : PFFC_PARAMS; index : integer);
begin
    params.h := index;
end;




procedure ossl_ffc_params_set_pcounter( params : PFFC_PARAMS; index : integer);
begin
    params.pcounter := index;
end;




procedure ossl_ffc_params_set_gindex( params : PFFC_PARAMS; index : integer);
begin
    params.gindex := index;
end;




function ossl_ffc_params_cmp(const a, b : PFFC_PARAMS; ignore_q : integer):integer;
begin
    Result := int( (BN_cmp(a.p, b.p) = 0)
            and  (BN_cmp(a.g, b.g) = 0)
            and  ( (ignore_q>0)  or  (BN_cmp(a.q, b.q) = 0) )); { Note: q may be nil }
end;




procedure ossl_ffc_params_set0_j( d : PFFC_PARAMS; j : PBIGNUM);
begin
    BN_free(d.j);
    d.j := nil;
    if j <> nil then d.j := j;
end;




function ossl_ffc_set_digest(params : PFFC_PARAMS;const alg, props : PUTF8Char):integer;
begin
    params.mdname := alg;
    params.mdprops := props;
    Result := 1;
end;



procedure ossl_ffc_params_enable_flags( params : PFFC_PARAMS; flags : uint32; enable : integer);
begin
    if enable>0 then
       params.flags  := params.flags  or flags
    else
        params.flags := params.flags and (not flags);
end;


function ossl_ffc_params_set_seed(params : PFFC_PARAMS;const seed : PByte; seedlen : size_t):integer;
begin
    if params = nil then Exit(0);
    if params.seed <> nil then
    begin
        if params.seed = seed then
            Exit(1);
        OPENSSL_free(Pointer(params.seed));
    end;
    if (seed <> nil)  and  (seedlen > 0) then
    begin
        params.seed := OPENSSL_memdup(seed, seedlen);
        if params.seed = nil then Exit(0);
        params.seedlen := seedlen;
    end
    else
    begin
        params.seed := nil;
        params.seedlen := 0;
    end;
    Result := 1;
end;

procedure ossl_ffc_params_set0_pqg( d : PFFC_PARAMS; p, q, g : PBIGNUM);
begin
    if (p <> nil)  and  (p <> d.p) then
    begin
        BN_free(d.p);
        d.p := p;
    end;
    if (q <> nil)  and  (q <> d.q) then
    begin
        BN_free(d.q);
        d.q := q;
    end;
    if (g <> nil)  and  (g <> d.g) then
    begin
        BN_free(d.g);
        d.g := g;
    end;
end;

function ossl_ffc_params_todata(const ffc : PFFC_PARAMS; bld : POSSL_PARAM_BLD; params : POSSL_PARAM):integer;
var
    test_flags : integer;

    group      : PDH_NAMED_GROUP;

    name       : PUTF8Char;
begin
    if ffc = nil then Exit(0);
    if (ffc.p <> nil)
         and  (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_P, ffc.p )) then
        Exit(0);
    if (ffc.q <> nil)
         and  (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_Q, ffc.q )) then
        Exit(0);
    if (ffc.g <> nil)
         and  (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_G, ffc.g )) then
        Exit(0);
    if (ffc.j <> nil)
         and  (0>= ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_FFC_COFACTOR, ffc.j )) then
        Exit(0);
    if (0>= ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_GINDEX,
                                  ffc.gindex )) then
        Exit(0);
    if (0>= ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_PCOUNTER,
                                  ffc.pcounter )) then
        Exit(0);
    if (0>= ossl_param_build_set_int(bld, params, OSSL_PKEY_PARAM_FFC_H, ffc.h )) then
        Exit(0);
    if (ffc.seed <> nil)
         and  (0>= ossl_param_build_set_octet_string(bld, params,
                                              OSSL_PKEY_PARAM_FFC_SEED,
                                              ffc.seed, ffc.seedlen )) then
        Exit(0);
    if ffc.nid <> NID_undef then
    begin
         group := ossl_ffc_uid_to_dh_named_group(ffc.nid);
        name := ossl_ffc_named_group_get_name(group);
        if (name = nil)
             or  (0>= ossl_param_build_set_utf8_string(bld, params,
                                                 OSSL_PKEY_PARAM_GROUP_NAME,
                                                 name )) then
            Exit(0);
    end;
    test_flags := int((ffc.flags and FFC_PARAM_FLAG_VALIDATE_PQ) <> 0);
    if 0>= ossl_param_build_set_int(bld, params,
                                  OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, test_flags ) then
        Exit(0);
    test_flags := int((ffc.flags and FFC_PARAM_FLAG_VALIDATE_G) <> 0);
    if 0>= ossl_param_build_set_int(bld, params,
                                  OSSL_PKEY_PARAM_FFC_VALIDATE_G, test_flags ) then
        Exit(0);
    test_flags := int((ffc.flags and FFC_PARAM_FLAG_VALIDATE_LEGACY) <> 0);
    if 0>= ossl_param_build_set_int(bld, params,
                                  OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY,
                                  test_flags ) then
        Exit(0);
    if (ffc.mdname <> nil)
         and  (0>= ossl_param_build_set_utf8_string(bld, params,
                                             OSSL_PKEY_PARAM_FFC_DIGEST,
                                             ffc.mdname )) then
       Exit(0);
    if (ffc.mdprops <> nil)
         and  (0>= ossl_param_build_set_utf8_string(bld, params,
                                             OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
                                             ffc.mdprops )) then
        Exit(0);
    Result := 1;
end;



function ffc_bn_cpy(dst : PPBIGNUM;const src : PBIGNUM):integer;
var
  a : PBIGNUM;
begin
    {
     * If source is read only just copy the pointer, so
     * we don't have to reallocate it.
     }
    if src = nil then
       a := nil
    else
    if (BN_get_flags(src, BN_FLG_STATIC_DATA)>0)
              and   (0>= BN_get_flags(src, BN_FLG_MALLOCED)) then
        a := PBIGNUM (src)
    else
    begin
      a := BN_dup(src);
      if (a = nil) then
         Exit(0);
    end;
    BN_clear_free( dst^);
    dst^ := a;
    Result := 1;
end;

function ossl_ffc_params_copy(dst : PFFC_PARAMS;const src : PFFC_PARAMS):integer;
begin
    if  (0>= ffc_bn_cpy(@dst.p, src.p)) or
        (0>= ffc_bn_cpy(@dst.g, src.g) )
         or  (0>= ffc_bn_cpy(@dst.q, src.q))
         or  (0>= ffc_bn_cpy(@dst.j, src.j))  then
        Exit(0);
    OPENSSL_free(Pointer(dst.seed));
    dst.seedlen := src.seedlen;
    if src.seed <> nil then
    begin
        dst.seed := OPENSSL_memdup(src.seed, src.seedlen);
        if dst.seed = nil then Exit(0);
    end
    else
    begin
        dst.seed := nil;
    end;
    dst.nid := src.nid;
    dst.pcounter := src.pcounter;
    dst.h := src.h;
    dst.gindex := src.gindex;
    dst.flags := src.flags;
    Result := 1;
end;


end.
