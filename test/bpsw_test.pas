unit bpsw_test;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses openssl.api, SysUtils;

procedure bpsw_tests;

implementation
uses OpenSSL3.Err, openssl3.crypto.bn.bn_lib, openssl3.test.testutil.tests,
     OpenSSL3.crypto.rsa.rsa_sp800_56b_check, openssl3.crypto.bn.bn_shift,
     openssl3.crypto.bn.bn_add,               openssl3.crypto.bn.bn_ctx,
     openssl3.crypto.rsa.rsa_lib,             OpenSSL3.crypto.rsa.rsa_sp800_56b_gen,
     openssl3.crypto.bn.bn_word,              openssl3.crypto.bn.bn_mul,
     openssl3.test.testutil.driver,           openssl3.crypto.bn.bn_sqr,
     openssl3.crypto.bn.bn_mod,               openssl3.crypto.bn.bn_exp,
     openssl3.crypto.bn.bn_conv,              baillie_psw, crypto_utils;

const NUMBER_PRIMES = 669;

procedure bpsw_tests;
var
  ctx : PBN_CTX;
  bn_tmp : PBIGNUM;
  i: int;
  label _done;
begin
	(* Complete BPSW tests *)

  ctx := BN_CTX_new();
	if (ctx = nil) then
		goto _done;
	bn_tmp := BN_new;
	for i := 0 to NUMBER_PRIMES -1 do
	begin
		if (0>=BN_set_word(bn_tmp, primes[i])) then
			goto _done;
		if (bn_is_prime_bpsw(bn_tmp, ctx) = 0) then
			WriteLn('WRONG: %d', primes[i]);
	end;

	if (0>=BN_set_word(bn_tmp, 2297)) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 1) then
		WriteLn('bpsw : 2297 : ERROR\n');

	if (0>=BN_set_word(bn_tmp, 983)) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 1) then
		WriteLn('bpsw : 983 : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp,
        '6471379620836935800182414453957610018160339989398404395248337107199943449721335240352556017335797026155714926'+
        '1464469317297080737722690627775200014918575930145441973136656843904474027376966799110163773563217')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : arnault : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp,
'54941923627933784194618501033252051057466182536496597550629586217435051798988469305088013540932595550290729784274'+
'7589979886135102666157147211855994196065010559627866228837393549736942388413848102819329')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : carmichael : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp,
'16675213704264635359855338582319826599139881187670369606766303648011276513669171437386545724558172168833854673196'+
'99846843349130386187248172347916972119857361121892838129641210517768456878852708559897254136414760769165500614277'+
'84517212206126117991881877507705577212590099553965435675517768023965013254327949763814767752107231345697795547804'+
'43295670451640271953769851816031211776828994779252013021094159247355897769604124730071091196654314171749454933025'+
'02970954487102502435503990716543818462100483812058698052426507250736943813409782289922015342189598897519333130641'+
'3676318626385465709286848580363599123478758994747523'))then
		goto _done;

	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 1) then
		WriteLn('bpsw : prime 2048 : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp,
        '95949120886598825655794496601145753651007381735108316296889541788687974450359369253855936978592684099537844444506'+
        '81085614856019291435100103580696215440036411214783730257525649108984226514139598676163479392135543760901535887266'+
        '37847022636651202378739187353368559972269295289980182299111431639915236001505106822802768759633474923592003419399'+
        '92084328396356538319326258430208666653311128097476571335866985670280131119893815432533650054628964551590201657950'+
        '42942252198586099719005806522237309389896680057966650392489632751535072252906077353054062512010888575718156097516'+
        '81595888705568164910938567846875087593099968524178447965007193035298904760923512762129228271256363692633973298393'+
        '72259995617171672356935654587748881390508358820296337404523326298374995295746301568295995839969623254951195719307'+
        '033570047046373301586561204996962220840898991373203962089956619627002702509687253507762019786509035605120681415'+
        '762028682446058983842445240828497586339714567954637520800497546364891126470246293312632888509816404200944810674'+
        '492898278250190021601338718856005525016110102370557360313230010163057057257273673523309884967480494479522032746'+
        '8365759516613158470220926527181876078187374281123697114208609629101800048460373829711815457106181195590025033'
)) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 1) then
		WriteLn('bpsw : prime 4096 : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp, '190316680009')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : square prime : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp, '119185643267526116681929')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : square number : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp, '0f2ad9'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : square : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp,
'23511795499245521367381353907826033845413959512754234716909319582718218990844601828440516176385782657177820467113'+
'827274259037575120939218127809235097685345744184306999687618362131267693385257558965587881881672116218488010077961'+
'330529677734450715849206424235653730860191030581629676022366528773603917308967322482909944247841367984694950139626'+
'075692739679818833943744599023772829448431021942878456136500100143870231595650256912336403410042784597625682408395'+
'005020774958154743380123078075274149930905621527921858122932548814493773328450246905514372673996670630150057478835'+
'6451693295669354712269552726710363944738481')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : big square prime : ERROR\n');

	if (0>=BN_dec2bn(@bn_tmp, '222222')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : even number 222222\n');

	if (0>=BN_dec2bn(@bn_tmp, '178368728938729712')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('bpsw : another even number (178368728938729712)\n');

	if (0>=BN_hex2bn(@bn_tmp, 'ff')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('small non prime integer\n');

	if (0>=BN_hex2bn(@bn_tmp, '00')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('small non prime integer\n');

	if (0>=BN_hex2bn(@bn_tmp, '01')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('small non prime integer\n');

	if (0>=BN_hex2bn(@bn_tmp, '07ffffffffffffffff')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Non-prime Mersenne number that is pseudoprime to base 2\n');

	if (0>=BN_hex2bn(@bn_tmp, '7fffffffffffffffff')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Non-prime Mersenne number that is pseudoprime to base 2\n');

	if (0>=BN_hex2bn(@bn_tmp, '0100000000000000000000000000000001')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Non-prime Fermat number\n');

	if (0>=BN_hex2bn(@bn_tmp, '010000000000000000000000000000000000000000000000000000000000000001')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Non-prime Fermat number\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'+
'0000000000000001')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Non-prime Fermat number\n');

	if (0>=BN_hex2bn(@bn_tmp, '123a99'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('pseudoprime square derived from Wiefrich prime\n');

	if (0>=BN_hex2bn(@bn_tmp, '00bc18d1'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('pseudoprime square derived from Wiefrich prime\n');

	if (0>=BN_hex2bn(@bn_tmp, '04'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('square\n');

	if (0>=BN_hex2bn(@bn_tmp, '09'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('square\n');

	if (0>=BN_hex2bn(@bn_tmp, '010201'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('square\n');

	if (0>=BN_hex2bn(@bn_tmp, '0f2ad9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('square\n');

	if (0>=BN_hex2bn(@bn_tmp, '01f51f3fee3b'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('G. Jaeschke: On strong pseudoprimes to several bases, Math o. comp. v.61, p 915-926\n');

	if (0>=BN_hex2bn(@bn_tmp, '032907381cdf')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('G. Jaeschke: On strong pseudoprimes to several bases, Math o. comp. v.61, p 915-926\n');

	if (0>=BN_hex2bn(@bn_tmp, '0136a352b2c8c1')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('G. Jaeschke: On strong pseudoprimes to several bases, Math o. comp. v.61, p 915-926\n');

	if (0>=BN_hex2bn(@bn_tmp, '023c3db80e80e53bd1')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('G. Jaeschke: On strong pseudoprimes to several bases, Math o. comp. v.61, p 915-926\n');

	if (0>=BN_hex2bn(@bn_tmp, '0504e8e504fd585e79193ca1'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('G. Jaeschke: On strong pseudoprimes to several bases, Math o. comp. v.61, p 915-926\n');

	if (0>=BN_hex2bn(@bn_tmp, '00b7d84161830e3f6f2231a7a1'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('G. Jaeschke: On strong pseudoprimes to several bases, Math o. comp. v.61, p 915-926\n');

	if (0>=BN_hex2bn(@bn_tmp, '4c6092d9a7a5462b34e5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '22c9a603ee84bb9c4cad')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '437ae92817f9fc85b7e5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '0190e262098f0d746505')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '027a5f7ca7b29ee74d5525')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '008d60a89f3f36cb1fd495')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '02be6951adc5b22410a5fd')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '0292a0068ebb0ed3251f55')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '750b703e68cb957ab415')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '02d0facc78aeeb89f5b299'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprimes to 12 or more bases from https://arxiv.org/pdf/1509.00864v1.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '09bdc1c98b9b'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Some primality testing algorithms a counter example for Maple\n');

	if (0>=BN_hex2bn(@bn_tmp, '0ffb48c934842b'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Some primality testing algorithms a counter example for Maple\n');

	if (0>=BN_hex2bn(@bn_tmp, '18444fdb12afb7'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Some primality testing algorithms a counter example for Maple\n');

	if (0>=BN_hex2bn(@bn_tmp, '08e4f37e51'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Some primality testing algorithms a counter example for Mathematica 2.0\n');

	if (0>=BN_hex2bn(@bn_tmp, '179d55b600e7f1'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Some primality testing algorithms a counter example for Mathematica 2.0\n');

	if (0>=BN_hex2bn(@bn_tmp, '085270bd76a142abc3037d1aab3b'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Some primality testing algorithms a counter example for Axioms primality test\n');

	if (0>=BN_hex2bn(@bn_tmp, '02cb78fe3f36c4f5f05dbe92b82798d5fc18f2bfaaa388ef'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Some primality testing algorithms a counter example for Axioms primality test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'4682f52f0b54308d315b2fbec25065506c77be95912b137bc6eecffad8a299b631c55ce068702b1b3e4ce50958994c289b148fb298a8c603a0959'+
'b0ba5ad4bcba278cf4c87e0ff85a62a25c40849662c53d0f81cf9e4431d8c391586629260e558db473997db20108278b1ae374089140d93bc2c5a'+
'08ad3aaf212f60bfc93cc0c788149dcd82f7ab')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A composite q that was acceptied by Gnu Crypto. http://www.iacr.org/archive/pkc2005/33860010/33860010.pd'+
'\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00f67307e54779cfe9120bf862afc5466c5d6d0783d12df5215c0c981c51e4bfc098e9afd574f51b18c820259b692ec0bf7c9d6e56e9bb99fbd3b7e'+
'c4082146a9d7a5b7bc6519d476c4a9975d9c3e3b12bee45b7accb07a6a68ea583ac2523ef32ee6d01bc766b59c43031f9c6980c9b4317da6825be'+
'f7c5db03283d04c13323')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00c1d00b32d63e3ea4fb69ab6b9dee40a17fada46c122e52a53fecd3fe613303f51c07871dc0b5d8d8c1705b484de6bdb7f442efecd7d9f59dc36'+
'495f72905c7619bc4d3706283774e704a3adad7d6c1be42ddeffc2ca5b1c0e31b58ed606f16dc14676e60ecff42ae33e503621e232ba449e91e3a'+
'909e80a8318610aea3b7cf'))then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01c2faadef91d43c9ab1320020e08e2ec3c34012bd0db94a1175170dc5aec26897e867d0b7a7273119fbe1115f02875b522566016f69f319ad54'+
'5e7458fcf50205d22ba765cc586a6037be987b6832c46227df19cd8ce0641794b60b73fbdd3c104870ae9bdf0194e772c985536e860b90b7fa3eb'+
'05af6b224413f5813836abb')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0109fddd44575367466c67aaa921047b367515c9aa579eb60728034ad2d56f10eb01cfadb3ba0abde99f348bc3c70559bc24551b85937ca4c886'+
'bc0826cc1c310f14393652c1b4994953881bd2d81de0f2a280839829543f429bc41bf3c6db120bb150173e2707f36d1f76318249851f4fedc39e36'+
'aaca48686de03e6d256973')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00ffd0847cdda5a4fdfd2345bc731f1bc77843478950d33b2830ef0caf8deffdbe6309fe61fb67dded6659e433f30363339dbcc7c0832593f33c24a'+
'b8f0e28038cb6edeed58ae765e6884ac0b66b5218cc758e6247269d24be9f91865d33c105219ffbce00c6c2d6391448643bcf5138268f510258f63'+
'b90a6c8b53bfc121759')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0118d077827c6db85bc61d53063edf5676d6ac65b611d836eed07ee7e1d15c02d999a3eb78ce662edaf457f0f7d9c0a0305acc1faec4170400f06'+
'0a797de50ebfb08fd0a5da77144a1e0236e2bc6d8d2a6a719e59df071367cd61275f372e23b1c0187d87d15bda5f71f4705b1c3aaaa8ad951d20c'+
'e93274b151f3f9a55bd693')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01c09377e15f53b1329b6e8a08bf0f94da27dd29c89be74544d705173a0bdd410935e186dd95ac113732674fe08585690ebe9f749a116a8c64e1'+
'4a281ef0cb28bc70b1639bc1352ff5777783bd72e3b8495c1494ae11fb32bdaba8c80870a3de71c0c27f07983e97500c0ec0321b86c679c53ae7f8'+
'76ddbf6a9cc3ff63e45023')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00f35cac3bb3c7cf5e4e50162f4ca889ac7b875f4aac08c5a2433600e9bc64db6c9895aaccf3ee98783ee2cfd8a5e448b265bbc4cda6cb80d487c7'+
'67d5a6724fae1ffd27c70f579e62b49f29819c6221d7659fa9364e8e37795d88611506b552a20533f1f6446a35b41a986d304fdd7a39f484331b4f'+
'f242f95b80788cff39cd')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01e9df6f069f5984c080087127f90437f2d38f19385b3592d17a5f23603ec6315c36a88d2012e85eca62a983de7ef27673c605155b5647311840c'+
'8887be8267fbc01cec3f7e0467d5e9a812e5dca577cc8ac93971c84f8cea94637c60c0bfe5d7f4b4f950e60ad077941190afaa905d6d5d570c9b4d'+
'b98c32c7abc42346f894d')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00c5286502dda772fc22d43b0a2f46823777a91f580f3a1261c47be8e2010a5ad9395e2c036b32813dcdaad33c8f2f4a522593e31ae55ef05c8df'+
'ed58636ac1b9db2b205797d39343e0868ff02bef46d18736bedc6f527730da8594d45d0447e7c7f0e8ca12b285b88aea5e343264874ac22038f58'+
'1bd96519d49caf45184f97')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01c29fe8b7e63795218563774685b9fe85eada73691a6420c38f0e9f2f802e89c77ae78716924e4efb5e4c639ca98ddb0c9e35cbc6313196b3327'+
'72527404b6da8ff7813915702fb7fa254c1cdc167a34170da57606ccff876ca0ce5e920f443e389fc9d0c071b908c6675b6a9f5903d6d22ad490e64'+
'6a7e13adcaf988663b3b')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01e8648f8abce82efb0afa9861c96c428f690c5fe33b9c9d47f97198542c982e607fd9700f876159ea404983f4eecbaf2a73b262085da4b7b5de8f'+
'e8ca0b712f5e89c0e8f024033879f858f814275a3ea5543fd539e74f5e099769d0d726ebd8bc74bda6e2f8ffabbb7d043f7818cd8d531180a82773'+
'fac59f45b2af35d273f9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00cedc5db464312d6f1ecf53a40bde07ae0d5540ef75a4802ff469142270049dbba2b74e4ece7340d8eb99bac1a3d6f0b52ebb41794d3cd4e4a5'+
'8431879ff81818abc50bca5e686a06d48461b425be62d3c064321429e346960163f897d21b362dc72f306a6865cfb9c8c5682cc7fcd7dc6ac4202e'+
'd070729ef9e3b526236c71')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0093ec9e6681f1bc1d6534add99d97e0d907828996bb3d7b481f3ceaefbe8f3fdf15698302ce26feb84c08994079c9f368af8171faf76801fe6dfda'+
'cd587fa0edc751d64ff7e9aa73fb7aa51a8469379bac38e9d7941e0bbdcf658633daea40738e81f5605198b04fe8fd49646da4e98c2282a8041c25'+
'b9894252412472294f9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0129fffd0bf1827f2847f45bd490d5423f67d87eb8254535d57078707e19f2ca5ca10602c5eca552fbdc77e30592b7498254f901cad02e0bf59802'+
'5582cbb3059a1979a5e5311855807b1cbeff86a651dbf3818c3b6cf50092c9b744c4831873d1d0d8c23f23b39517ce435a257e5026cfa0be280672'+
'1bba3074b2cdc6474a37')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'017232b942eedc8a0df14f5c1ad4e099f192b242b7d3dff09c50cecfe636c72c6c8ba1c65dde4396282e1a1c823b6d5d9c0c9068b39e202dcba26a'+
'd35a00b7bb6bede272820fbbba503bc1866c6ae183d8b50e28555a921121929862ce87ea4ddde8f9d6ff2e17a8ee7cf9d306faa0815a4d46e8dfd'+
'b7ea538b7399cc1c06c1f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00d3768b43c242fa7ac1de856dc7bd413b79d544bb8d38677bc9f44aa116ac5525c3e7fcf2fb2c1d3de61844931f47646b4c5f7de226031c925acb'+
'57f1cd292fec7e7d4fd25afa128704ffd8da910ef18961e081e88d40bc37582b087f1b1f39fe4d23a03ec6b869c76fa3aed7a3606c469069c4fa1d4f'+
'1c6112da16ba9dcf97')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'011b5119e5c68a710158c36d414597b4e1ccff332d1b437a4d2da2d2269ad2b626fde79e3ba7ed92128e5feaa87556f18ca6937b5a88f4738608'+
'6bb6aacaf4fb719d67561d66dba9690009bcdbea2db4ee48d575722cbafbf1e487bab1c62ba0cde30a34620c7733b3e13d8b27fa035115680fb81'+
'16d1ca777b8a2bb7c399a47')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'008e9ee596ea83d06e1a9a4c3b75fc67f3c01de737be4dcdc18f1d10e322df48e455546ac8ac810129dbcb0fbf568987033cadef9d051f6032c8dc'+
'2804fc8d8d6e79f5d767963e4b6d72ac29d98d2520c29c8e69ffa59164d6a1e4cb55b7fcc60c7cb274da264203839873ec2f85f4ae377eeb6189e0'+
'1b17e8603a01ef877b3f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00879d1e0bc0538cd9025110cec61a034305c8fdea2b9709ba80b0c45891e7ffc69c05285f4680b95b5882ad04210342314d3ab465ee1209d069'+
'613a09bf7df0d48de18a7200e09e8b7944e748413ad64057fee2daacd099dcbb19920429cf9776d939c27c74c3adc8c41f1001f98d5293e018b1d'+
'e228abc6e79092331804bdb')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00a14d02b57eb643499b92b797687a69aa809fc6c5b56be581de2f8668d38936c9921a16c921a18ae91bff15ab595897416ebbbde977244dbab'+
'779d47bccfec14b1bdb255597bb9bb70e9372fc9afe475b2f73754daf575ef2dd565dfb4216208141fa99df428417d84fff2c54b1fba037a4237bb1'+
'b07ddac0f39209f83f8541')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00d11e471371b5ce0473a80367ce1b0baeb21d8f8ddfebf1116f3b3721247ec85f6e2786467b63743af0885e69c59d674d2b1a4b655ab15d8003'+
'e755fabd56f60ad3a7d2a5edbe942663b882e8c1d9aab7250a45b93feae3f092e8819d5cc2c0eee2cee0c6a098a40331aa12a0efc384e518036d3'+
'2e4e231de3cf644e8aa8b97')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01fe65939e5a1c520be98522b1ebbd40e4c030adf0677c1878b1b0a58b72873eff6f58712e377457ef467bdbb4666e2f8a4733a13a065aa01e3f5'+
'0cc0fbff0e8a2eb2d8d43b9f2a4931d107315943fa7e1d304f98838903897cd42ab948f7c5ce31a9323a35bdc0cae10eebccb5f318a1239f9b9609d'+
'5387805524d67e216477')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00c24248b5f6e52e0ce8c9068ba2b5839489d1a4849feb751b627e12d13722fd5a00cf4597e63c9bfd1a275b68489539f2b0bef36a09504d7539d'+
'e1a346bc0dc5fa2c65c4c23b771a9946ef5bda403dcd27f496dc02233c05d7d7dc73f6438169a0bdc510bad2ca105d84c2c8bbf2a44c4d7d4d0ead'+
'80c13bda71a945d1f3f01')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00ab0ef4c1c3be6b7bb39ab0c8a1ffb2c12f8a2fb6c85ea1a8893f452dae161a8decbbc6a84ddc2068bf9df927c0f68a95fff1af8aa9eddd80b0c37'+
'b7ea750def2f6df54c0a7e50c16bded071b8d1df6687264e496316be5fcf5f9ab73f5c39b61a876441fb3f467205c92a864d97205032660d6eb2ce'+
'3ebfca9649295f6fc95')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01878ec4f236498bbf2320c89679639394b03dda157a9901f2e07486e64f1bb52f6b4823db13786296a71d6e65ad6a17308e46ddbb2608774ea'+
'3df41221eec799fc13ec95b567450abfbae8aa04f3c6361df3a1c01028b83560018b729b5924ee5f03f1306267eea55ab65a95591b105810a5011'+
'c9041d20b3ddd389e8ded20f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01602a125e7578a82e23051dd12ce12be44f2becfccbd13c2ee18ae1e391356786315832fe9fa6dd5488c83b4f560a5a4b9d9daae4faf0b9b2107'+
'fa1b470c7d984b2b43cfca22bc36ec305e52fb4b897445024f2ee536164a5a9a4201db4d9247d4e28e193ad3c62657a91b23727804e8f4bca4069'+
'eb41f17c68ab65bb8dd2a5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0109a25eac262687f28e560e73bd95be9894bf2a0006dc217e97547064d29be5fae521312fcbdd2949520961abd90b5a2ebcf55780f0d14ebda3'+
'17825089183fee844a3ba0d132cf3db13ebb8f42905bf24374ac29a7b68f93f76dbce3942d4b1dbd91c611d24251b374bd29ae153cb9e23177115'+
'c7003894269328d960cbbc9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01962b71c4824f2072f59c73cedfa26a49bd976bba7014005b6feecfc61c90caeeaa05ca8954219165f073bcdb73770846c97383ad1d47f0cf6568'+
'0388fa5847ab9f542e26226d3e9c2a90bdc23819333bd13803f7520272e4cfb80b5c54c92dbc2936ac75f426babec5b49db6a64cd6eee14ecff040'+
'506eabffc8bb11ec6c93')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0102134c13210c561b22c8f2549e0a1786fb85900e3c69c20905cb46a3f633b7128656ba1644cb6bbfa1b5b0c5a5bed69a7802a543cefceb2132e'+
'db7c596e51b88e62185f3815fdd40e7db9d1aed0b0f135b09c4d90e81fcd4ea7a8e7c150147bb2f0fab2d8a0128f25e1e498813f6dc26722a73a44'+
'd6e9ba4f488d96ee6d399')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01ecee4b07f4311afce14524ab060a72a7198499342f099f681dd6b8a366bc9550a7ddd3288273ef59f62c5daa55c9c4726c78f08c20e0d9a7420'+
'db52f732377bbd8ca8f8f1d336bda6bb2defab66506c0db04bf0dd6f7179f52cfe9c5c91179de1c03eab017d7ff867478e45386955c7a5a744e7f8d'+
'cf738c80352a99226777')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'019fd1a5266cb6e8dfcff2b755624ec26413d25cf53a9d4341ff5c7b0b4e06e8246e6e1063e185b05d90f38637ca69c298d6a834e9aeb06e02afd0'+
'1897c1fb097c905445b2e6d27750cef01f40d6030f0328eee55241137afead4f8d358d0be0655782a60265f0b9aa30b275a32b60bdb252c95d8d6'+
'b68e8a1e07c2374029bcd')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'32fa78d5eb67eb14a53de388e9d03ae6ebeb7ae017dbae8f594b95f82f6ec380d5162f6f498d0cb61bb14d7ae54fa1b427c2a1d8191331615768'+
'4a86d039200cb22c5d68716fd0e2b8f021cf25e08506d4ce285536bc6a074edb6d9b4a9dc01fd79eda19efd3b168eac045b6a4edc4c880de430da'+
'c5dd3f32886b88d320505f5f0b064e46be0f1e31c57dd160e89738a4f6897975875564f20f82ecd4cc0db')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'5954649e58b4eea73bf1738957727ed4f356fd14891d95b81c7cd40a9ae4b9f1a807fc859d4d419e9a2178a369ae734cebf3b6b9b7069570515a'+
'4b5609585625a7aab4e2ff05566be39860b1c2e41910a07b46a555299a573c50b82572a8e40d70cd5949c0c5488582cc2ca544265e1e48ec5501f'+
'611ee65de54946f4543ddd94f5d2c100fad681b6390924e3dbee62bf78133bb2ae6d1592fa5c4b0873635')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'282ca88061946bcd2fa15fecd98e61505b4c98079e5ffd08e9797059673150435ed47f6d94311c9df4ceadce2e13679b4eb1e7120f9f19d7ac393c'+
'090d1885c88136ec24d085ace42e92ab049d8cdf963d8ba7b93b25e3c720367fa9d7d3905eb460c6922f53866fe439bb96f6d5213e66ede623951'+
'bf0c2253ae23c3ff9915dbee4eaa576395e2d6986d40151cd8fe4c9b4d990ba17ec4bcdf6660459858d')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'2161895b72aff5d2a865dac7e95cabaf7a28010da0dfb075f9b25c189821c99c1bb599d47d6a688254401511cfad26f1d93f254a3be2752a70f78'+
'9acad5e6f741848bfefe449072365616be7251781063e8f8934b59f1826341ebd0839dcf72b1735e21f35301313c683d28fb637f6f93453f575330f'+
'4e2a0d661ed5fe54816f8cd38b162d5e769c0bf94dfe83e25b6c05b7705a477ebf52ff4deb6bec6aad')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'71f7dff1a6a0fd66d5228398a7ff1707ed9f83b9b8c660ae57ee4dd40de7493cec1540e50b4586fdda98ee538e6264fb72f51682bb7bb5305285c'+
'87f4577023b8350a84fb088005e36121d9d137b16c4528b4a8a3934db88fd27128733b5f9ea78bbaf239c93bd9b6b4b1fb683e2e2ea911eb4da8'+
'4b5650f186a7304031b62fc145a9a20a269079ba598dbd183f29a2f35a46eb05276b8ac99a8dc72d76151')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'55654725a248e323f3d4050b87acae89736b85dc8dd45a9c143b001685c72a70996f3ce99f40be4cdb83b7b420b520e7fa001eecd49cd43c3150'+
'c7c502e8c31e309026c07fcba386f0905da79d34b855861018af444fbd519736483fa79ab2d02182a9f0c0e514528f38cae7ef7668829b25d58b56'+
'027e4f286a71c1da3d9257a72a234ccde58d1604954d99115db265ae13c012125b5f317ab3297e5ca3e7')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'6af6ed1adb0d772536d2e80f9f048b9a94cea70f6e15f37a6b5cac22794826089a11c8fb421b3bf8c108bd41a3cd7f34d09466aadc8b043a51b0b'+
'e9c18e0c96e4c703343fcf68d45d5f023bf781de530a1d7946f4d2bcde9d7ef44374a2ba94ad56777aa113abb19b57d4802c18bedb58157dcd52e'+
'ca7a3837e65aa97d95f3b757e7eec27a5f890f41399aa5c2831f13a724d798aeabfb642a011c52a7c70d')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'344b4e93ddadf36e039a4e97783a18c3a84f3d725d5f496f0b3632fd15b1a0c2ddf8f97a0f47401d0bef33c32ef36b2819f5d0f72046ab8bdd68fa'+
'28397d1906a1923f5ad96483048254e931a6acb5a3d31d4953212aa58c2f96e94dd5393f1e830e76264af68abfed551f3ff4e8d3bfbc6e6cb296be'+
'e2b9d694db4d4dd186cfcd6d697c7aadd92277f9ab85e000dfef3085cd52418d0f9b11605a64719003')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'2947f606c39ded9591b3314918b7fc0586888d42eb0a8d68bfa0890292f83f948280dc92e897c59de2477340c9fb288241737213d63d006a64b5'+
'9c36b010164953fc68b3e4c7d70e4837b707a2b4b3608d878c7e5c122665299c012e2d5b3630b6862b87e4c680cedf13a6fbcc6eea8ce2d1fc394'+
'a2327d6e0f41c4259b00fb8d8922b4a81432a30f7adf6477b5c436102c83bd1896718d8e795cbd5c30b65')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'2d586d8d3e1a38f532ed17011ff9d397084633faf6690129eac51e092c67217fb23e6d08f9cddbc38f7b3fafc308f23375df556f68f8dce22247da7'+
'6e8aded669cb841b6be2fe5a22da4c0d06dcc6d6fd899d294ad0f62de03a7057e56ea6836ce8967d929f4144c9955460bb924fc32f5210919c79e'+
'566e0552caaa130b6ab2e9be086fc97659bb2097adb0ddf82cca17b472ca511735499c448a8301f379')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'4ae1078c81d196eea211f9c4f762a350b4c060b4d3630bf7fb7dddd2739986b9de2422c9902e5870b3760be7b7926d6aaae633cf0ca9c0e78a2e'+
'03fe193675524e0042073d3be737efe994b7bd93382bf8426f454e4a221fc899764f1059fa30b48ba6db9be33c92e312e449d190b3fa2f1c731277'+
'86fa363ac8420668239e0bfc26387ba329720bc4ed0217a772ab214a60d8d2d0889d887960383c420595')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'4acba34e2619592d5cfdbbe195d2aa9eed8762ac0a8336d947c846fc97d1d934c1ff42f1254de674990f76e514be53b2755cfb4ac52edec66a812'+
'685c8e77e84b06bcfeda0684fcbfb20e2ee05c1202f3cb897bfb1c44bcb6301a9843f8e8eed031a1b4eb913bea04f13390ebd2a033ed151ef8b49b'+
'11da558e56cf1e3ac89545219ec026b3938ba9732792a1c89ca6d38c3c5e0e400af528ee477ffcf2ad9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'3d809b8c90e877efa20e031ec99d825afc1c1920d8b94e460848b80c3fa0a093ddff5c608963ab74f505a6da96b8068c2c2b3bc1676170dd0c2e6'+
'adcaf7cfd0c6b0309634961ad0c9b7f75e2f721f1f57fa9cf5d4f41f60b2ad3fc1d213b8e75fedb69ad157e24ad67f2ecc4099943e19ecfa7e1a34ab'+
'9f4bb02cf205906dc159c258973267731ce59d16552d372b9b47f0e630ec677711bc13995e00a41c9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'3de7d0bda6eae8145cc70591c4b78b1dd8d9ecc4a3d7edc1bbb75bf0e98fd3fb8d5cd4e94e4cd3ee246617b22426ceec6981681af9f7e6af08bc0'+
'bde7cbfa13301f7b88f607e1751285c4a861af2ac69f20d2d600e27b0de873b9ec7bf2cd0725b31032932f0f817084b347852613af9977931e2b31'+
'2a523dcd87f545805730b34db29c8c8dac9df8a50f5aa1e36a056ae41b01d04cd9574acaa98203d84a7')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'5e2a15c7d9bee2668dfd689d027bcc37743259309457147ee7785bb3960dae3c8126655cff9e1302086adb3d1c962c3390f50ca3bf5f666e8a004'+
'30536c0bedeef4e8bc3f4dedafc3168692109a239a7d4fbd3aef9e6e0c8665c6379caa6ccb05a6f941782379fb13990f2bc104dc7e0007702c7eea3'+
'b7ee42ffb5d570570b2f5409ebe76d7244b1e8392ccabbfda22515beb0bfad6c006c2a02a5e8526763')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'550fda19f97cdfbd13930911ef6e9e1cb2b7b5215a35c215d51ebffeb435642174cbe998f4451bde2d4bd2ce92ab5b9493b657f1d77d9ad4d3485'+
'0247b903906109c608ecba7f88c239c76f0afc231e7f1ac1cee87b4c34448a16f7979ff4c18e65e05d5a86909615fe56587576962a2cb3ba467d98'+
'6445a0f039907601af77ba7d07578eff612364fbcac11d35e243734aa6d9a6cdcf912a2dd0a12ba7e87')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Worst case for Miller-Rabin test\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00907b5573c3d72ca5afda9df723d24066410e3d2b61f89c5c600f90732d0ad7db06a02e209f6792b609fee2ac6f3d73a5805f2b30642d1e2654f7'+
'fd155153e5fbdcb17c76c27fbcc15010ccbfa7a1737cdf032edd5da7edebc9703e51572ce452c2319f1d91bee276d3e1121f9563b1700448ff37346'+
'5a88098c9a682a59ccab86401aeeb74c8ce45dbf8b5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('A strong pseudoprime for the first 46 primes. F. Arnault, Rabin-Miller primality test: composite numbers which pass it, Math. comp. v.64, n.209, p 355-361.\n');

	if (0>=BN_hex2bn(@bn_tmp, '19bc037ff6b1')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '01933ecb87a0c1')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '021229a85a2f91')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '032d4a135c4d51')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '07277d9f8417a1')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '194f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '0149c3')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '1d7503')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '6c7e23')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '00f1f8bf')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '0ebbb74637')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '127c6e3a4f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Richard G.E. Pinch, Absolute quadratic pseudorprimes http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.210.6783@rep=rep1@type=pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '15179c6582c2a8c42af5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Safety in Numbers: On the Need for Robust Diffie-Hellman Parameter Validation Galbraith, Massimo, Paterson,https://eprint.iacr.org/2019/032.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00800c6ed22988e8353348f28123408551ab4ee482b7961786ea4d90ed7d48bf4cc5bb0d7fbc0346e9ca2dc215540460df3c24bdec561ba766de'+
'd618ce42fedb4fd84a67c5ef94323bfe88d9f55e1b111151edadda5a91cc0056b78c74770ae7f5a1af3741c92af4d87a70f66246fcaac1af0556b0a'+
'bdd511822a01a4b897f0d')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Safety in Numbers: On the Need for Robust Diffie-Hellman Parameter Validation Galbraith, Massimo, Paterson,https://eprint.iacr.org/2019/032.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp,
'44e282e671aa0c4f85ec68b2447bc29caba0ea0228b2fe7b08cd420955280bcf0ad99a0efbb8688b3b71a90a8f6e4b01911c689db474ff3685813'+
'b2c943ce664f32d2dbc3c07387dec550207461270c323ef25c0992449e142ec3d7c36cb876492ee6a8593c4aa8e992c2f4cb394a88fa7aa9c98dd1'+
'9e18bcf280332fa934b')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Safety in Numbers: On the Need for Robust Diffie-Hellman Parameter Validation Galbraith, Massimo, Paterson,https://eprint.iacr.org/2019/032.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00b310aa4e16f59e55df118739db5ac21b65979ff5acd1cd4839716a63eb4ef966afe8a04a877548fa281a252c8a1cd4e62077f2ef5022e855d60'+
'06a24a91cbd042323926aaec1f75fb4cdc4cbaff3a4275903c226d5982c22740e17d3e0bc7bf5bc23e7273b3bf86cad8498e79ffc43054292f38ee0'+
'5fe9f67d6c542631f833')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Safety in Numbers: On the Need for Robust Diffie-Hellman Parameter Validation Galbraith, Massimo, Paterson, https://eprint.iacr.org/2019/032.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '008126e1b6c59a80581221ccb272046804dc8bf7a2893ccbad9e61267f9c56ca5b')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Safety in Numbers: On the Need for Robust Diffie-Hellman Parameter Validation Galbraith, Massimo, Paterson, https://eprint.iacr.org/2019/032.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '008b741e1c47493e2ac2bd5f69f37c01ff0ec6a28e4ff91fea2ff24e2fad1b3369')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Safety in Numbers: On the Need for Robust Diffie-Hellman Parameter Validation Galbraith, Massimo, Paterson, https://eprint.iacr.org/2019/032.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '351591274f9af9fb')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Sorensen and Webster,  Strong Pseudoprimes to Twelve Bases  https://arxiv.org/pdf/1509.00864.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp, '0331ff3562a8d7ff')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Sorensen and Webster,  Strong Pseudoprimes to Twelve Bases  https://arxiv.org/pdf/1509.00864.pdf\n');

	if (0>=BN_hex2bn(@bn_tmp,
'046fe40ff28041a690af557734e885052b879535574af06db2b787f926e85880060199697023504dd9c0d0e23b7e01e922538c586d676c61c972'+
'1356ff053e78fdb481b7e5909c7dcf82155d713e915d8cb694a2f46320cb10868f03b98566022d225a97f1ee3cc26794b1e481abc61458146c48dd'+
'52ba81d06fab826c3ea58585500154d36c9076b0e1fd3d47222d2e8ae28fd5586818db16cc2fb9449a399ec9c22551448bde17c1e752506464424'+
'23af8de6b690f9407aaf52d8d279d11292fca1c32d0d9c3adb061f530fe10eca96e2bb2e4be1f6df1d7130aa21f78d31a312af5bdf56660247d665'+
'168088ba0f1a7e4ec202f8efe5eade78726abf365c735736f578a57')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0b23c53824cc42b6875b787be423bd8c8aef90a1ccd18f041c8d6164b94e33a5c431217f4572779ef6475407474cb7ee0f49781dda2e903f92f5fe'+
'deb0dabee93d47519b8c2633724e2d2f24062dc79c53add5dcf12a90f389ccd242b82323da265c6db54acbda0105dcce948c5450620166cd27815'+
'22d3c1da9748d4b8640a4a0fc8ba0c11d0ae8965d436539e331bfcb712e4942af901f8e5c5a7d860b92afcb2ac7edd96d715d1d5ebd57232fd74c'+
'bc2e18786aae081704a22efe24b4723b8d7227dc10d5c3e9be23bdd5c646d3f5ca53a3a725bf12009ceb98ed6e83f6ac611a0d582116f4d4cacca'+
'af150234a88b81b126ec1452dc747f46214d9c01b3005c2bac5fca9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'2085249c586a279f9474255a00d50a111cbe29b474218524fd3cb75b69e0737b9598905d046ff24235075e6df5a07a56e73cbbe0093e19386fe2'+
'3de96569470a474a843a0211a17013e9132bb8a6f981a18d84b4472985936b72e453401b55c3fe3e7b28398964e2d87788edc03901f95411cb4a'+
'849604caf42a924cf2eb11cc21336efdfce8ec322d27d2744eaff0dddf4ecdf6593485b14d7e7ff50b4d30f4679bbeb9cc0a26cfbaedc0c77c9dde1f5'+
'b21b3957c72f396bd7c7e2ed236a3b0dcd763ff85ec0190c7419496d4769a5329a9e8963ad3c9326e46a14b888a18c063e6afe7f350eff3ccea8c6'+
'0fd4a024c908fa8248fe7cf1c3567f56ee45c1963f4b31225e6c3')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'3dd0b362012faecad5221ed17f9dd0a0b1ea8fc23fa1ebaab3177201f76a8121bcd0310c0bf262bfca1b8f17a5eac72f6eac1102e7d68da9e8374e'+
'7dfed6619f39a1f51fee008288c72ebf3e0d7f4484d5d5b12a74510793c2200e51f8ec89e45a41b8986aad68ffddf864f912ea12fb889d937c237ef'+
'6dddb49ed6ef02e1d1612926c28a2c6f734350d3cfa600f2138dad662f835ecbf166795916c9347a43bac0dc95ebb8b75d9111a1e1efd8f7f6cc8ed'+
'76ad027a21090b41699a1b60f5239e7e7e51ccd9f85d10aea334a95fd09b5467c5f6da9bb10e12f22a577b99625be9c7b8046930cfc16ffae77c37'+
'3f528d0aee48421fb658d62deee4126d235759f00dfeab84d7')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'03263db7214fd0fa5ccb86ed39c03270e0ba52252d80649979ded94b1cd23494533f7d63b47429baaabc9113bf56a785242753301e5a89bd0dc5'+
'6a173ec596a5f4b93def5f9a1af18bcf228d37b8f615e0feade9b26d498946edad3bbb46183d2e69296a8d96ad6c1397f1e3a64d55c98fe2dc0ce7'+
'c3e15672f53e7203d4b658ef17239c4f45b06fc9e30913a8352962e73a47788abc4db223a097ca7f8eb6b404598ca135455758966e6975ef35f07'+
'dfb053007a3b63b42f17dc2f4c251aa07ad4f676b2f3c667ff5640470de7fd353e6e62377b0e272f9704f5d4833a9cd6affcd54b0639c594f5f7f1a6'+
'6c26d6bde51a8590f40201602bb3828225407833a284e618faf89')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0f8451854b84d14366c21be5b7b331d89b1b83c989feaed6430c5e2a85acc3f2b1a09f3c202a99d5b92651d7a38a92059a9fe15ced0358fde59b4'+
'2266f69dde4f8301d3e7808d3b9d023fcebffbad603908029251ed8a017effe2427527461d7e0d768bc3d726f540eea4cc1de1905301f435bb7ac4'+
'175d7bc7a5ed5a8139d5aa7b02d872c982db49b726ae82908ce331dd74c9c8d8056edf8a366e35bb22189d097124588fa9e84f6b8fc2b8708519'+
'5e280f9b5cdf2f8b7c780454a2129ce315e74ff7e46961404304725303f07c148bbf8eb864ab8f89f6ed75ea2d5766250659f1e5a2c11492869ab3'+
'b8d880f73bee69c7ce27702fedc1f672186df29d6c579fbb7368d6f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'02d248d11dfa04ee4f070722df4c1f03467dd32dff2d18d69ae32e6596567c28a3e21dde873bf6f3410b91a70b8a827bbbc1fa88f3d9c192210c1a'+
'548086023d3ad5a340578af38271ee5bef9e0630b37eb56175cb1bc76cec3cb582bb88fdbe15d5190a5e5ebea44550cb0e2ec9e13098e210910c'+
'2c6372d7a24497e80ebf872e492affade18fc4efc5c2cd34bfed582f06f0da6e969122f22057ce7a9a3474e41ad160db119e82f044319d4aa26419'+
'61a1bee786f6003bd6ac854583e7a5489ef1685040162cda798e079a2052fb910f2c36dd9780882738a526a31919420502614542514bf1c4b010e'+
'32cf2e549b0551fb7e0b89cf48cad35ffa29310743d4224fe3ef5b1e5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'04b379213847bad82279fb3dc54d60692e9c128c2e0e5ae46d8388115ee6bf47a922c71e02f2f784e30bd81f56578fe16d901d4ac6060a62932e'+
'dc8d349e1c029c98da5c558ac7da55f07e4422902420fe082018cad6f0d7e024318cb3b8248c87b7baa63d2eb1ecba32bd8051f53c285aad786a8'+
'afc0c05b9d7e365495aa8f1a3afc1301d183be73b689b306c3e1851dfc7c91b88faa3e81b29e23c8c2ae86cfea506168b41eb3ab2a2e19eb4ccf6b'+
'dc73055ce8eae17671110f365e7cf1db7f9a11d66ae816300765868b944d945bedbdd3a275e7faf6ce6b84f2de0a923c7bbec4c6e8f47522eb2fc1'+
'ad0f73a96345eb133b9436c505e8c2b8382e067c08f0bf33d1822a7')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00ce30bb03f146cde0da64125f5d4df15d9b148b73caea0cd30bd06d6c46db3e86646994b6dbf12fe32eb708862c0e88000b2f44cbeb2244ea492'+
'b15d82852b3b83ca6fd9676615b1e5cd2f4153854e48602684be12254b6eda528539c0eba1304bd37f329568636335db835082095ab4319374fb'+
'aa0d61840ae25dae3d22d5f30a368f9130595c6edd667f0e6051bd0abf7512e973d2a7fc95abe4da8bdfb138740925d2ceaaeaf18fe2244e656d3'+
'df46f6c1c40d7dd44eb116d321a33a48d0641294eeda8759ff5bafd3301b7b916a089b82a725b15dc6634db88dbc092d9dbed575676126f0a6027'+
'f24759b24762926a95669148ae8138dee6d84d242a5e9f2b1cb6dfa1633')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01853dddf18e11020af425c8fb280fb606868aacf59fd8365db931779f858d60fe61fa2441591e24aa4e409dbfce513833619710c68e1da623b9a'+
'e5c594f8cb8fcdab698793529d70c4f0079e1ded6e16aa1b42cd820bd72eb719185c61596db069989b88a8cb496f05e6c8b1917db58f145a67946'+
'b6406e15b76b25155402acb4742702e8a5d212e3fbae3d4ff06b91ce6de68e9fda7c5ccf9c591aa0035529fb1c8212a35d74ba5e66cf60ab62c47e'+
'd3a53babac9d4406f3ebab673d2688868b301b7da61e3ab9d8ed91b874a68a3678db9481ee2efb17731c382d232a6303b901054a7b22edc92e3'+
'c497034c824b6f065a008670079e0c4564684c986f141d71d0a288a038f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'02556ed72094c997f884b315d0355be63eacb02a918a75907cd65d8b9f105ecc13412a8b4f7a163fd00f62ba434f42d90ff5b30367e9cc2112285'+
'ad48b498cf72fb0357672ba88e362a52b211b5b317bb6300f745063bc3685a7f4ffaff32018ecc80f44cec94faa3f35babb50de479433a084662009'+
'70ee4258dd6971aa0973002bd507b4a20e8befde99149b4b9036191149399329e39629b0ccccb5b1760c5ab6f50c32a3b2c1d5f85ca2d33a926e'+
'7c7b35dc363d44d5062edbea7051c4aa38064c196394be4b1b16da35131b02c04bbfec11da64538f3922a582f423071893c129def2be77c738cb3'+
'd4ae35623379f6daf129fb44625616ddd886ba1a78c12258f9af7bd')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'078af4b6e56f391741bfbc899f3fefd5e20748e7816657e70318f16445f27366f67b931062a8716e3545024edc4d6bdf151f59770772f45fbee812'+
'3056ef42583f37b6f81add2e0522dc11d23f06814f18b379d139cd3773d3c0bf5aef4c82f1dbf69d34180a7720a029f6b283b46cf045c115aae9e5a'+
'03b830000c42d592ccc42fb2c6233466e86efb440716fbae0e696114b26f73f8c42f90dae82171ddf96e0755da67c788ef523ca0cce19b432200af0'+
'b7314639ac75d26b77d86e08681917ce499f71e8624607217287d0b45898cb69f1323f43abbfbbb758ec3afadf998d27bf30518c613e796bd5f1b7'+
'70dac0decd5ac7ea8bc552dc40e2106ce5f793e32bec01a209')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0b9c27e0c46f3de793c85f2840198e51d3c9550751a2dbd855b364bb4da35fa13871bcff3a049631bf9586c5b261626be4e9ed8865b4d9dd435b'+
'b4731c5c9ee7fdf298e2bd6f7a661e360cbe764a7b7a3723fc8df5181b406bfb787dbc1c2e1586f88261af47c8997e71e79a5ebda4e01d5b862f48'+
'3e919c4b07a3e1a94acf139aac80d490b8af449d88a9ad1344afb05323d7400a53d17d28e8495ce7b17d182872eef67479f99cf2e8b9abc967618'+
'65a4154b4004184db43cfe2476de3f15301708f576712e8bdbf723857eaec4eeccabc8763e5ba2435c184c155909d4ceeb7e34a8fc0acbca6decf8'+
'dd360c63ac4f5bbc307ff2a7ea9901ff48c12cde5b7544ffe9ab55209')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'3c30f69630518ab86d506ccb13f843e64e257e135e68aba14def5c7ca87fb23f606d9a21b43825d46d3249372f6a6734741d9e2a8761c43f151de'+
'b35f22a58223a4ea1b512da6741523247dda566b8ebcc070691541e58293b39b3ac06d4055a652d7e599e443ce5c59067700caf6c5c0a9f75af9a'+
'ea7ff95720485fbdd3eb9e3bc28bf26a7bd1f8afa77c99669254e5b88b056af64002bdcd6e1ae8186033c2ba2a92a2894d6a4c1ff15bbf70b8a577'+
'750b8b96976ac93ef39f50b9cd3c54f81c65953629afe6cb0944249d0ab99bed92e57b79244948d03681762661c308ebfd0cb89d6e7925ad2c687'+
'8f30b4536766fc28bfb8486e3791055604b3ee95085cbbd0b328f7f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'41307dac271321e285ffc17e39f2288c668bccb8c967bcbbf86cf833709c6245ee0d7d9c16a65fc414b94ced362790411f378e2221b8522c57da51'+
'79f50323f2554ca3ea1b79145fea625ccc2df919cb31a06ebbcd636e00e293da1dd5a6b288fc3d5c5e68491beaa8be6fc815c64dcec6e12963c3458'+
'b57090d6c2c2c26b77606c593d711ec498727cf7fcf362e46f86f24ce85df786ffd302e0d927955e691c5bf2a0ebd9eb8c2742fa8648f82b3ec179b1'+
'31749f05cfe67f3559f371bde2627542a7b17262d48fe630fa7c59495cc7edce5489319df977405fd2042ab0a56a62d478115013eab1eac6b37f6d'+
'1ae7591d4cd15fa344b05bdfd996c6a200bd2f588daa779')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'131f432c0f4e8f16b2e068bd41500f4ce67285268d21a1888ed5c13225a2890e17be77444f9c9ebafe284c2d36c6f66fe4e3ea5f64092eec66dec3'+
'6d1b80316517fb0908cb67d6d4d783dc98b113f456fd6fa71f066e2e9ef2d5b665600901e6c4f304b2c230eee34c3516bbd547c45d4af2f41dbb6fc'+
'6fe60c76285bdabb82ae6cbac84119d8783a7341fac7872629830a20c17cf5131d2d5d0474a42ac4972d1ba0cc5a18c0af70b6ec820b7d2dc34b9'+
'281800112ef1b676cb06ff6be14cd023c3c8e366d04d14118d7299d3aa10986dd1c2df41f19df9cc44fd7c2abf22b59693303555b33210c4ff4d120'+
'4b8f8559e3feaab4ff80b0511f296db95f67ad6a4b0e886f7')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0735440b7d3e3aa4be783bb912f644624fb7da694d092d0d3df1d5892dc3d40f96c2e5b5fd3b537a8f6c12b1e1b5931ea92a7ce957f5d08682c68'+
'8e3f864e29dac8c2f3f6a4cc1d3c58eb5513c4bccb9ef9da3ff6db38547563d34f94299c73baf7db8bab5a9ff94edfa55d100bc1c1b1a17f75afa619'+
'577019304887914b70fc72c25c7155085dee797fb824b5cc1d4794c26810662d471acdc625949566d06b734408f47a22ee2f9d3566a200df16ed0'+
'15ba6965a1ce49b91708c9c53f61db16d102a6fd3d8e1de82425b50d0ba726aadc4013ec0aa8fb0d0a86ae9b025c56d99c9351c58987e89865cf0'+
'9e4758aee4b03d2e4962ab1e702a46a95986ea380ae3a5e4d3d8f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'027b903357d9edc25b5d45218e0ac3efa2851ea54d84ec92269fac38e533e41ee68a36f86e96d2582d3bcd16afcb7fdedb0a58fb7ff8c94397dd1'+
'1abdec786a4f94fd3acfe15a50f045c2b7bf614612afc4683e0d39f5b100237f52434dbb44eb264da762557cdac6f4aa651f0fea7a9ca7a04952d6f'+
'b0031f2c2f318325b4b84435433578478cfc215506e9a524a8dfd9c7cbd71c81151bc25681261da8fac3220ab32c5c4cc4d94d0febf6353396c6324'+
'c5ed2fffbe6155a63dc74ec3a67f4a38c6f138d91876783d1b9390743eb1503887b041a1f47d1ff564506543ffef691fa56794ffc4258ac0e7aef7e5'+
'cd0749800c68c8835fc8a3e7118166050bde3e9a4e110df5929')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'74e23abe7fcd90a7c0744204a47059f8fe6f4a9d9fdcd011539c97919129f6f46f310ad14f3866d7e82be737cebbcd72b4f1995941e1ab96db7c56'+
'444158bef8b60de6b98aa76549fa9eeeee8018485bc55f6f9bb8621321072283d9736acebf0c189453033879fd38f141a316a80f6c2d5d2df7c031'+
'5ffae733ac0f060d9d5969446dcb5ab8cad9853486707c1b373f4144a61d1a17a23b3f1171fd06359b98a3b26e4d8f4cb7f83e91bdf9d7a271aec9'+
'6f596ab47a001c07e78758f7c0ba25857260e3f91cd21462594138e6bf84cf1c0cf60a8ece8cd2e53e6ca73305428af507326babdf37e29483bbcc2'+
'6ee7b058c7d9fe0b407ed9b491ee85e001a4dd9175a5047065b')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'010ecf0a6d6fdc6b91c46ed7fba35496708c494b8772bc007bba48958a55e584a40c9a34598c31ace09afc982944c860f6794d5f91f5d07ac3f797'+
'8aba4739b592146dfc4aad9bad99aeabe97960b7245b3e62e04f49cea54b33ab2caaefd84fcc202902da5e35ea446c0057d6015833f4e63d793cf'+
'6192cea8736c0ca4a6c4a7a9cf0d3c8a5820384ff1728ea09900c0b2c3eba1fe588719e7d1ddd750508b28b4c5fed49a03b250a424260ac27ad46d'+
'6b08554c09b75f80505c1f31021fffc5118e40f523fe2ea437025acf3a8e6a23ea6a2863b460ffab45e47a00c5f8a01427e3986cb7520b549db4aaf'+
'c9277fd122787808b519d4d7cad2d225b5c85f253e9b5aa19d7625')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01a097c0a285f02b54ba79a7ddb126b709f41b47bb9d8913fcffab4db0f3ba01766b502e9b3350bbfec70addd52ace387622abc21095eb7a019ac'+
'6873b9d2074edcca2c5eff5998a3e984dbee023a71d62c0bf9c771d84eb16dee06fbeb7babed577e77cab8785951af65086fdbcbb15f2e1c018192'+
'20d6add44db22cbb14edf2a140cc04f4dadf8284fa77fdc780d9ea34eccba9480288b6b776f09f7e7f4b9ea702359c5fd3cbeff5469530413c891d8d'+
'081f9a25d65173b14b313a8c3b75f97b56f053b879f7e31b6d5cd093a47227b2a16afa4af36fd2e91ff1827be9b5d59f537082e535d59788eedcf0'+
'c7a61431bc30c55bc9cb93db60fbc7c747badd057908fc0fa0be9')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'05dd50ba142f4e7f831ff9ac6f4dc4a4582d245cea39319308c2dac8ff1636314b0cda157d0d5ce8dca3dfab608922d9a7071b8478e4e5311f7283'+
'30469be556a5924bcc85338f1f06a4da7e13fa7dfde9fa6db76ddc5e558619d5933a2022d633f1a9ddbb2047c8ae585723f04a69e8c2e01f09e9ee'+
'3d3bab6d7902893d9ad725e08b0ed4a25b778addcd20a9439da8bede1a96cb7fa1efa149d047bb08771b59e22763ebd098ae394ece2912d5b2af'+
'5f2499b44bd4ea2878021a33a3f305ddf9e1860bf670fbf72d1f09ccbf87b00cf996a719d5b5c2728ed3963e13682784f00ca7b6f96eae387992310'+
'e6432fefd20481f72dc6c6d10ca95db052e0c54e294283e68248ce5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'01dab8d833a71ed5abfea060c1a9f2ae09ee0931516fc1f38c14b959cddd92c3aef0574b9f9c9f2991c38fe43a7536c081e14e2b87b7b0d495e83'+
'650ea9e466783d4cf3068382cf8ad00651669959feafbf336f4be62bb4dfc891794e097ea53cd8f800d79818127258f89a7e7d6b3d05e1e3f0da7c'+
'6d1e343d24f82ffa9d96fe2db279d2809f0b6482262d53d32677f57500aa703e5ba9df500367ca255d051d7ff7018fe687c907a2520a2b992cd4f7'+
'10b70b1ba3f1b2e5ab07de0e06de76affc27e6b29aa2730198454a8fe529963c27260729c8fafc6e14594604d8e1046ecb7f88d8ed100280f42feb'+
'9058f17a5c239848d08b85afa976efadd0711c3253410eb8d')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'08f969a48c87087c160937ab35e3a80a04c58eb3620eab93184c7e1e2cff1d958e92faa1c3ff3bc17360c15f221aeeb6af889a95df029dc5c4f9974'+
'b77c86601a4b13f872e57482dfed06c4d0055bd478408c40472d599bdce63c79f91240d448560a554673841ac071518c627fb0f22ea0c56b88a1b'+
'5fdf427d5dc68e8d25d944e0ddb61827aaa1e224f0812acfb1158e37805d84e0957c6895b07913141db56d4b41996e3043977259ab2aae564091'+
'6421da6f89efbcec0c2cd6c173949cece2e402139e9d5c8cc1a0a1832926985811dd052cad509454c51ce4c2ef5b08cb04d6c497431adc86d43a27'+
'd4c7647a12208ca663f5fce246f4045fcfb9ee8ae5d48a4838a9f797')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'3dcf125a77c4a3797dd742d5f4647f22107fcc23597d261d42126ecfd63c979f0069c0a44c9d3bc3eb47f94e83041cf43c90c9d685f61d1784af656'+
'826a7858807fdcc4a62e8fa2e24c060bed22bf5164ea8b193248698a59df6a8ebcf2831a746be18e5a7fff4ecf202ef6f872a773463acc99233dae6'+
'31e20db3b6a1b7d71171754866a9ec6c20fe99a06589b2f940a076068d3cc2e5e199a48804b6361548620877d3b65f2b652ab5029b7e964b465b'+
'fd5725add9461c399db82688b0f2ab510384fe387e8f289c7982d3952bdb61944c37fa1474a67a07008f3cc7115ac907ed22448808842c247d554'+
'3f3e36e6665ba30d489723a08a8342e59dd2f5942a54f0302f3cfd5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00e10f450df7bd6e44aaa5f66994d5e11a57da6947969b8ffa84fc942725d0bdd57fea4cea3907cb5c8200f432453ca855e77b4e89766b1f339f1e'+
'9f1b3bd5a477d7af9c21d97ea2f025ec6810101b103d496141715d61764193ba8bd63b00162161b213da888df612e610c8b3ce100b57ac59d0ea'+
'e65f6ef136d5c42c82104dd37b483d68345216689fca1122fe3e2957d357df3e1bc0a7a23b3f3789103fc8c8bcd6a6a966e2661652e892c0596127'+
'0425b251b8bd02a0955fb5d895ca90a447e560d13b5d065a241777320c3dd839212a9be7ec0dcf792e5d0383ddcc98cb3cdfb85b05d3cfe3c6c81'+
'7c76411d76e5de85b1b117b22521d01728da606bb28491e2dc93b917f')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'034b9c645b94c535846280e92897209efe58970459e1557d61a3a0178a8e6f2e522bb4629291cd32b6357ab7b0fc121a7c62fb7e3de939391847'+
'83b1be7d27ee8394d561d11532159cd3e3ba5e93d49466d1ab5f0196fcb3ca72c4fab0fba4abe918cf22972af7c34168e49a5ffebfb893dd0badba'+
'355ab22daf54422271333b2565d31298f87eb0c9ddb32afa15155c611249f3500045e17aa830dfceee724215a633559f9e65d9603b3b8a848025f'+
'6ec8eed39f9e4d095b08221edad29372c97df63d151f68c3b5b502a12423bb961e51a9626ae8ce0f08b7ac969e1d0ef1e5a04fea3302868c28e02'+
'85eb79ef16c1c7e45d6f68cc32c292205b74ab40bc02cbd5990fc7b92b')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00c1221e5f3877bd767a7c56286fcf77a3a3c96e1c81e15a59933d90cef676f95fa6cde09404c8988f5094edbf5589a01abe9d612b858068ec2c16'+
'0b0b8d49cb3e431982ef99104dbfa95f8008bf5915cc42354a1ee2d8888bfa0d2b964d9f664503be6a1c6a99a121853651a063c33bc96ba1021ba'+
'44151fcf92c8fda6107bcdb4ab61bab8588e94ff38adc65da325b42b1525c635cf096da2da789bb9d97edf07a1d292d9b8dd7169f6292182dd89e2'+
'9cd7169e20b6cce19f951c08d48b3466e134664a6a45ab508e502e3a17271bbd44293b871ae3a61c5168608545be5ffc889ec8f2357b21a628c9a'+
'10c1edb37c8442f8f7676663ad9fae6ba6567115a89f90d1cf05e999')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'1306e7699113ad21f3d91f0b6444a2c65b3261a2a5ff51ef0362866d81305e8f13bc3e112f62005b7853974f9021b4a30b559e699282673c893a7'+
'b91c07969b572b98c460b483ccae8acf42f713da00eb6d65c7123212cfdb538e98b5865f5d9b20ad1f7f9b64887f9efbcb598d7c864a6812bb2f7d9'+
'2cf8ec3d3bbc7004d5316556dc8b663bcd285741ea061dd735b31316160d869b097e44c3042546befbe43e63f24bfc870dbe0f7a20b887c384eae'+
'eea4cac974d3ba610ca6392b75a6fa4646b111a43a6a729835edee935f7019f3cb0929c8858b390d4097d9f6b4cf4665f925bbc8e85da11b99698'+
'556b3e230eb6d59ed8ba337018745f16d7c6f7310db87a615257')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'4eb3ea092cab164f3fd7a73136de87896de4479e92ba918fe1a29797902db20c2ded396a4351b61aaa66a0d142bd2d4f4b44d39ddad927fd38c1'+
'8e773f993f9d49d6aed9af93191408711a0774de82da243279435594c49950929f074b4b95f2e50f7d57a9c523bcf30b8c627dd142529e9679bf4'+
'4ccdf76b2d0077b40a6006ba8721703378b8538064afebfb97c1fa8c49bc704b99675db97de4eb52e9cb78a907909221d492165f074421033428b'+
'ac5c23c508c959d43276ba840d8be98baa38f89dd30f2c67d27dcf60e69af725541538cbbffc2ea804a34f861fd06ed03c682c0bce11cc0c16ad164'+
'846c478a55787f162d2943b577b2cf4483eae13b2fce80f436a15e3')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'020f1c50b3640950fbf9008742b8d993dbd9657026d755691cfb088f0c6f9c4b98bc0be2e0c8e47881e7c9d6ce6f35c08fed549bb40b0f4fd0f7943'+
'df4b5a5f78d2b54df8cd958da785d9ab1c727c1efb0e667bfe216e7d2955dd490e868e783f1409d0ebf2e079f1303f57b50ecc3987a53afea5d824f'+
'dc9a89438fd32f1f4b3a729c5482a3f66cd69e712b1fdd3ed25836dc8157079053bed47f5e500ba698ffa7b6d02100f70993e43bda086dac726e72'+
'9eacc01a1d623edceded81e0a446c0713b06d9224488df1f4239a7d99daf16d5273e0bbbb11360dfef18ce33613441ab6947a0daa61ecf0cf732c4'+
'8141e951b232934b61073455e454e131e442edf39cf62e30b101')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'00811bb71ab010d948e4ab07149e752d4c0b9bb6aa11842a1146011c0da66cd8d597f7dbc48f26b9445a92374684098b2c87db94276481d7995'+
'a8425263ed6ebfd97d4e42a5239b36e079cc14fe923d3312f62800b153c0bb4e4e97396182b6f1ca5eb6f33ec61d4e7c2d822964b679ca0131471'+
'c931a8f430011644ab9d47ff485ba18041a564464c806c0b445a69d4fd4469939dfa304d8aa11fc2e9c98b450441b5658be9ce498f638aaa6076b'+
'ee06c31f66751b440f977543ae6b268da016aadee31ae4866ecbc9f57d077a0cd23f802d27875b524898ad2dcd19e91334b88ff23a7532323984b'+
'40c3d50e6b37044b89d6471f92d03ddb3862530b8a95ec1e10e40b768ebb')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'1a110258b0f5aadf8b223c58bae17d256aa1b66ab381dcb1ec128c4cf8d1d3bde3dbdafb45808865c919babcb5822f5121d6efd80e32496a66acb'+
'c642fa93b9dce7181295085009f2427e1e0dc6bf322b8f6b45219b37640119bf01f468a16def4fdee8ae8bd10829481a918069de36d161dd5a00f4'+
'6fab3267ad043c601a2109e4e40568e76bf97b8c64dbf55b442ad484ac3faba1d654c1e27ff6cc5a215ea6a695b55ad0cd71a14e3288b1c2221c38'+
'b8667e8a37eeafb5703b4f64b13444330cd9a292395f64e26ff8e27ffdb041a7b3d559b187a39df9be773916a4b7ef968892ea923fe79291138a8d'+
'437e4617b9e43e3f4d0a0c3933b6a0babb54cf69756e6457025bf')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0315ac7638fe2dde5f466b9ae990a6b4ca6e4529c86812f1148e65c2268f24569aa0d2fb1a9b4ef4059cb4c93b2c537a63cadbc5de9ed118d4ffe2'+
'e845a57b9fdb1dfaf19e50fc09469beafa470a45baadf99d46d86b23b0f9a7e2211fd5119db7fa220a819bf270ed8cc37df6cdd39413f566158375a'+
'c6ba19d33e59b517f23bfbb7ab72a4253d3b2f25450cbd4dd2795bedbd6267d4bab9c58cf7accf9090e44e932886546d30865fa3675dc31d88c16'+
'223553f4c50e4407ef44c1937b2da3447bc9a9db838e8cb709194b84d155d7dbde917c485a6b95a884dc1776e96c51641445c015bd709b6d1f0b'+
'4349092dc3675b51d15b86b6d73de9e08d61bf3da3e7d3be9d1be689')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'0090fc577b63378b614de9a87438496201917d1d98ee56b34d1220aea2608c9296cc10686b0ae9d554447ed47c5bec9b489f0d4456eb42cd755'+
'bde32a3556a2e7b6b61c868ee49d85b8aec0d5d17993c7165ca2c0accf59499c743cc4c6a50836b0363284b0c7552d8435f2a25257bb6f82d484b'+
'233ddcbb7c8a3f54027d0bbbf935f067dc3579973d1d819d90f4311fd9ff2ae23b3e8d5e049da85d70281cda755de9c57ab09eba0961ff025f3bce'+
'bd3974883836d8d3b9d37af73cde87700a46cb49f424c2264cffeeb0941cd7ffeba9202b6f789d2749860e46b27209e9eba449cf1794944470ece9'+
'b47c092572616ad2f4aa3adf17099dd1dcf434aaadd457f62c18c05d51')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'016ee5c4a1146a72841a52e1add93bfe32ae14ad0ff82b2879ae691f5347cb3866daff3b94cf40fcaf2efbf8be197a1aad8408493becee6f4fcebe5'+
'a43eeab0c444b6ff50cc9661d34b3671effb555ba5f7425d3c99520b29c5fcb937de5c45f0a80f7089fcf6a5e212cae6b68c6811ec22e71706d86dcc'+
'636cca099bf8066336b9da793f86b4780c838145a5f4d079257fd383116cd00b878dd617a984e3694f4ec7d134653946b81b12308457dd4027116'+
'26964099f52f2220778cd954515a705080994d4bfa1327168121ed942f69712d1d8a21cee6a510d38421472179d085908e9993749c2973774b90'+
'0cfde097dddc28d7694d65d28a04684640ff90d5a86a0c037f2bcb')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'09b96de09b3c269edab8cd497efcc8cb84cc2693656dd8b8454423efd8ac844ddad1ffbd5de39f4fbe47db100ee56131691b80c974019ebf31990'+
'068a646a6ac837d69a0d3470f4fdb309481bf1b1df29aa70b1c793094c0a78645216279a4f592ccaf49a39740ec82f2656fc8e343fe58eb4f205afb'+
'97d488843fa3054f9023064cd534823b87f69f808c24690ba57f2307c47c6261d1f240aa35c2c47bb0d89b18f071e7f96359fd91f8a5adf68bf86d4'+
'aff7030c5a106a39ba388b471bad93b49c69aee8d8e2aa12c6ab8ef318507b24603665ced96f8451c5cef5a3340bb4bac1f577cf0be337c1ee8764'+
'a2b48348089ce0d070a0d7e1a5bd735f636baa88f9d282efdfb')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'25ca8e8844298f700c87fdb4156abdfbf2540b4eb16ffdec9d6742a43514e48346040b4ecab2aadb7ac43b59fd113ae2c5636459c964306150e88'+
'e2c688272ab74a9e0fbeeffc29c60df8d8d7e696396ec21e80c2529e12bda83a1e8dcb9858e568afe89a79fdb00f766e5979a0c7b48168ef845ae6'+
'4ca5bafed340cc93d51ca130e72dad8497b2ad8e321e498e169898e6c1491a12f05dbffc31a81c859c27657b510a37914676fdf828c43d4f308e6e'+
'42de80c44cd49b835f6efddeb89df5fe10026c3eb0c6f580bf1a2322468b56ea60e9adef61f06b211b8c072f9a52593ab333dcde7c4109d6c628e4'+
'b20fc0e19476a72956f53fb0c03cafa56d0a3ec0e07fec558fc31')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'4a6e7bc26df7ed0d7c09e82af5b1905f9836705ac7cb854f4be1316dd2ab97505cbf70d090c1feb774e3e11bb4c0bbfa92074b2a59e49d2d6afe3'+
'0de31824d407735b9b7e3b5ac9dc2bfaee3548d8d3ce02e83a275af3933803e301e23d4244a543fd80ff79e1fe751f9540ae7ddd23da5930f01e0'+
'1a095bd5b505ca33868000588a2000938245e75135744dd8a4da04a0288e78fd73ac0160f3cb108f212576418482a581bcc71902f598d9844676'+
'de99fff86be9c10e85036a60925703b80831dbf6bdd75c61b24bfe1ea22b48d5502e5a52036f59ce0332c71836623c22e2dcb9f2958cd4067041d4'+
'4596ff98a88ef53cbb82f011f4346debe204f5389863a0637379888b')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'049a4a9991305451a4c682030ebbffff6a0101f04b9ce286965fa4afe83376fd028134a9e45b3d024bb331e6c80365398649f591ca0f32517171ec'+
'60bb9d9f7b415ce4f4a702aa3cee416a82b51182ce23088beb94d5afcb7d1b0c8b2a2e47e7ff63afaac28aaffe7b2459628d1979a1ccacd028909d'+
'31641a40f3a3f742fc993aa36de8543c19cc05fa3bc6031db33c56a5810c279a0f872ead931e85c5b55f71ba7232f6f0d50e2c7a614f9cd87938b6d'+
'53df6a68e492a0715aee49c235b954aa2fb6ac13c9d64daeafa16ff4addf7605400538ffe6cfb17bd8d694b3a28eb18c2dded3be5167b357a124bc'+
'8376c74c970f394e4acae0b0bdebb5d4479073ebed1829abe37a3')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number with 3 prime factors\n');

	if (0>=BN_hex2bn(@bn_tmp,
'03a48ea2550158e6910298c3a4b6162e9849bb91378d93672c95aaa20c8470ae964d4a11d3edb400dc032f3eabd44d0016255c57379e2765db3'+
'bc00b83a7914b048a28799aef1a74a35abba31755fbcef113c96deb380c86b404e961c28a3fc4bd1beb71f788e98141b1b7ba70365e3063ced78b'+
'14e543405ae80f6135c9f4a9c129bdb8f29a25889a07767339a1de2d5720f491a8394651d6d34fafbd6a63724028809acc69b9c542f107b2368a7'+
'db0cab8f00b4f7006dc619ad1a0b2d10c38cd7d05407b117a6bebd54cefbb552af1b0b81ff21c7bf542140f43cc2e10f270180bfb7b1665f09d36ca'+
'cb86aab4ba9015c9fb6d47b954decdddedb1b81c7faa84671bbd71e9b5')) then
		goto _done;
	if (bn_is_prime_bpsw(bn_tmp, ctx) <> 0) then
		WriteLn('Carmichael number wi');
_done:
	BN_free(bn_tmp);
	BN_CTX_free(ctx);
end;
end.
