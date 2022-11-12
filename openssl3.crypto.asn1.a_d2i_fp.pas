unit openssl3.crypto.asn1.a_d2i_fp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function asn1_d2i_read_bio( _in : PBIO; pb : PPBUF_MEM):integer;

implementation
uses openssl3.crypto.buffer.buffer, OpenSSL3.Err,
     openssl3.crypto.asn1.asn1_lib,
     openssl3.providers.fips.fipsprov, openssl3.crypto.bio.bio_lib;

const
  HEADER_SIZE =  8;
  ASN1_CHUNK_INITIAL_SIZE = (16 * 1024);

function asn1_d2i_read_bio( _in : PBIO; pb : PPBUF_MEM):integer;
var
  b         : PBUF_MEM;
  p         : PByte;
  i         : integer;
  want      : size_t;
  eos       : uint32;
  off,
  len,
  diff      : size_t;
  q         : PByte;
  slen      : long;
  inf,
  tag,
  xclass    : integer;
  e         : Cardinal;
  chunk_max,
  chunk     : size_t;
  label _err;
begin
    want := HEADER_SIZE;
    eos := 0;
    off := 0;
    len := 0;
    b := BUF_MEM_new;
    if b = nil then begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    ERR_set_mark;
    while true do
    begin
        diff := len - off;
        if want >= diff then
        begin
            want  := want - diff;
            if (len + want < len)  or  (0>=BUF_MEM_grow_clean(b, len + want))  then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                goto _err;
            end;
            i := BIO_read(_in, @b.buffer[len], want);
            if (i < 0)  and  (diff = 0) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_NOT_ENOUGH_DATA);
                goto _err;
            end;
            if i > 0 then
            begin
                if len + i < len then  begin
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
                    goto _err;
                end;
                len  := len + i;
            end;
        end;
        { else data already loaded }
        p := PByte(@(b.data[off]));
        q := p;
        diff := len - off;
        if diff = 0 then goto _err;
        inf := ASN1_get_object(@q, @slen, @tag, @xclass, diff);
        if inf and $80 > 0 then
        begin
            e := ERR_GET_REASON(ERR_peek_last_error);
            if e <> ASN1_R_TOO_LONG then goto _err;
            ERR_pop_to_mark;
        end;
        i := q - p;            { header length }
        off  := off + i;
        if inf and 1 > 0 then
        begin
            { no data body so go round again }
            if eos = UINT32_MAX then  begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_HEADER_TOO_LONG);
                goto _err;
            end;
            Inc(eos);
            want := HEADER_SIZE;
        end
        else if (eos > 0)  and  (slen = 0)  and  (tag = V_ASN1_EOC) then
        begin
            { eos value, so go back and read another header }
            PostDec(eos);
            if eos = 0 then
               break
            else
                want := HEADER_SIZE;
        end
        else
        begin
            { suck in slen bytes of data }
            want := slen;
            if want > (len - off) then
            begin
                chunk_max := ASN1_CHUNK_INITIAL_SIZE;
                want  := want - ((len - off));
                if (want > INT_MAX) { BIO_read takes an int length }   or
                   (len + want < len) then
                begin
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
                    goto _err;
                end;
                while want > 0 do  begin
                    {
                     * Read content in chunks of increasing size
                     * so we can return an error for EOF without
                     * having to allocate the entire content length
                     * in one go.
                     }
                    chunk := get_result(want > chunk_max , chunk_max , want);
                    if 0>=BUF_MEM_grow_clean(b, len + chunk) then
                    begin
                        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                        goto _err;
                    end;
                    want  := want - chunk;
                    while chunk > 0 do
                    begin
                        i := BIO_read(_in, @(b.data[len]), chunk);
                        if i <= 0 then begin
                            ERR_raise(ERR_LIB_ASN1, ASN1_R_NOT_ENOUGH_DATA);
                            goto _err;
                        end;
                    {
                     * This can't overflow because |len+want| didn't
                     * overflow.
                     }
                        len  := len + i;
                        chunk  := chunk - i;
                    end;
                    if chunk_max < INT_MAX/2 then chunk_max  := chunk_max  * 2;
                end;
            end;
            if off + slen < off then begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
                goto _err;
            end;
            off  := off + slen;
            if eos = 0 then begin
                break;
            end
            else
                want := HEADER_SIZE;
        end;
    end;
    if off > INT_MAX then begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
        goto _err;
    end;
    pb^ := b;
    Exit(off);
 _err:
    ERR_clear_last_mark;
    BUF_MEM_free(b);
    Result := -1;
end;

end.
