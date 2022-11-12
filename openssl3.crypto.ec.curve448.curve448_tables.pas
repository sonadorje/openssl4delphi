unit openssl3.crypto.ec.curve448.curve448_tables;

interface
uses OpenSSL.Api;

function FIELD_LITERAL(a, b, c, d, e, f, g, h: uint64): Tgf;

var
  curve448_precomputed_base_table: curve448_precomputed_s ;
  curve448_wnaf_base_table: array[0..32-1] of niels_t ;

const
  ossl_curve448_precomputed_base: Pcurve448_precomputed_s = @curve448_precomputed_base_table ;
  ossl_curve448_wnaf_base: Pniels_t = @curve448_wnaf_base_table;

implementation

uses openssl3.internal.constant_time, openssl3.crypto.ec.curve448.f_generic,
{$IF ARCH_WORD_BITS = 32}
   openssl3.crypto.ec.curve448.arch_32.f_impl
{$ELSEIF ARCH_WORD_BITS = 64}
   openssl3.crypto.ec.curve448.arch_64.f_impl
{$endif};

function init_curve448_table(a, b ,c: Tgf):niels_t;
begin
  Result[0].a := a;
  Result[0].b := b;
  Result[0].c := c;
end;

function FIELD_LITERAL(a, b, c, d, e, f, g, h: uint64): Tgf;
begin
    Result[0].limb[0] := LIMB1(a);
    Result[0].limb[1] := LIMB2(a);

    Result[0].limb[2] := LIMB1(b);
    Result[0].limb[3] := LIMB2(b);

    Result[0].limb[4] := LIMB1(c);
    Result[0].limb[5] := LIMB2(c);

    Result[0].limb[6] := LIMB1(d);
    Result[0].limb[7] := LIMB2(d);

    Result[0].limb[8] := LIMB1(e);
    Result[0].limb[9] := LIMB2(e);

    Result[0].limb[10] := LIMB1(f);
    Result[0].limb[11] := LIMB2(f);

    Result[0].limb[12] := LIMB1(g);
    Result[0].limb[13] := LIMB2(g);

    Result[0].limb[14] := LIMB1(h);
    Result[0].limb[15] := LIMB2(h);
end;






initialization

      curve448_precomputed_base_table.table[0] := init_curve448_table(
            (FIELD_LITERAL($00cc3b062366f4cc, $003d6e34e314aa3c, $00d51c0a7521774d, $0094e060eec6ab8b, $00d21291b4d80082, $00befed12b55ef1e, $00c3dd2df5c94518, $00e0a7b112b8d4e6)),
            (FIELD_LITERAL($0019eb5608d8723a, $00d1bab52fb3aedb, $00270a7311ebc90c, $0037c12b91be7f13, $005be16cd8b5c704, $003e181acda888e1, $00bc1f00fc3fc6d0, $00d3839bfa319e20)),
            (FIELD_LITERAL($003caeb88611909f, $00ea8b378c4df3d4, $00b3295b95a5a19a, $00a65f97514bdfb5, $00b39efba743cab1, $0016ba98b862fd2d, $0001508812ee71d7, $000a75740eea114a)));
	    curve448_precomputed_base_table.table[1] := init_curve448_table(
            (FIELD_LITERAL($00ebcf0eb649f823, $00166d332e98ea03, $0059ddf64f5cd5f6, $0047763123d9471b, $00a64065c53ef62f, $00978e44c480153d, $000b5b2a0265f194, $0046a24b9f32965a)),
            (FIELD_LITERAL($00b9eef787034df0, $0020bc24de3390cd, $000022160bae99bb, $00ae66e886e97946, $0048d4bbe02cbb8b, $0072ba97b34e38d4, $00eae7ec8f03e85a, $005ba92ecf808b2c)),
            (FIELD_LITERAL($00c9cfbbe74258fd, $00843a979ea9eaa7, $000cbb4371cfbe90, $0059bac8f7f0a628, $004b3dff882ff530, $0011869df4d90733, $00595aa71f4abfc2, $0070e2d38990c2e6)));
	    curve448_precomputed_base_table.table[2] := init_curve448_table(
            (FIELD_LITERAL($00de2010c0a01733, $00c739a612e24297, $00a7212643141d7c, $00f88444f6b67c11, $00484b7b16ec28f2, $009c1b8856af9c68, $00ff4669591fe9d6, $0054974be08a32c8)),
            (FIELD_LITERAL($0010de3fd682ceed, $008c07642d83ca4e, $0013bb064e00a1cc, $009411ae27870e11, $00ea8e5b4d531223, $0032fe7d2aaece2e, $00d989e243e7bb41, $000fe79a508e9b8b)),
            (FIELD_LITERAL($005e0426b9bfc5b1, $0041a5b1d29ee4fa, $0015b0def7774391, $00bc164f1f51af01, $00d543b0942797b9, $003c129b6398099c, $002b114c6e5adf18, $00b4e630e4018a7b)));
	    curve448_precomputed_base_table.table[3] := init_curve448_table(
            (FIELD_LITERAL($00d490afc95f8420, $00b096bf50c1d9b9, $00799fd707679866, $007c74d9334afbea, $00efaa8be80ff4ed, $0075c4943bb81694, $00c21c2fca161f36, $00e77035d492bfee)),
            (FIELD_LITERAL($006658a190dd6661, $00e0e9bab38609a6, $0028895c802237ed, $006a0229c494f587, $002dcde96c9916b7, $00d158822de16218, $00173b917a06856f, $00ca78a79ae07326)),
            (FIELD_LITERAL($00e35bfc79caced4, $0087238a3e1fe3bb, $00bcbf0ff4ceff5b, $00a19c1c94099b91, $0071e102b49db976, $0059e3d004eada1e, $008da78afa58a47e, $00579c8ebf269187)));
	    curve448_precomputed_base_table.table[4] := init_curve448_table(
            (FIELD_LITERAL($00a16c2905eee75f, $009d4bcaea2c7e1d, $00d3bd79bfad19df, $0050da745193342c, $006abdb8f6b29ab1, $00a24fe0a4fef7ef, $0063730da1057dfb, $00a08c312c8eb108)),
            (FIELD_LITERAL($00b583be005375be, $00a40c8f8a4e3df4, $003fac4a8f5bdbf7, $00d4481d872cd718, $004dc8749cdbaefe, $00cce740d5e5c975, $000b1c1f4241fd21, $00a76de1b4e1cd07)),
            (FIELD_LITERAL($007a076500d30b62, $000a6e117b7f090f, $00c8712ae7eebd9a, $000fbd6c1d5f6ff7, $003a7977246ebf11, $00166ed969c6600e, $00aa42e469c98bec, $00dc58f307cf0666)));
	    curve448_precomputed_base_table.table[5] := init_curve448_table(
            (FIELD_LITERAL($004b491f65a9a28b, $006a10309e8a55b7, $00b67210185187ef, $00cf6497b12d9b8f, $0085778c56e2b1ba, $0015b4c07a814d85, $00686479e62da561, $008de5d88f114916)),
            (FIELD_LITERAL($00e37c88d6bba7b1, $003e4577e1b8d433, $0050d8ea5f510ec0, $0042fc9f2da9ef59, $003bd074c1141420, $00561b8b7b68774e, $00232e5e5d1013a3, $006b7f2cb3d7e73f)),
            (FIELD_LITERAL($004bdd0f0b41e6a0, $001773057c405d24, $006029f99915bd97, $006a5ba70a17fe2f, $0046111977df7e08, $004d8124c89fb6b7, $00580983b2bb2724, $00207bf330d6f3fe)));
	    curve448_precomputed_base_table.table[6] := init_curve448_table(
            (FIELD_LITERAL($007efdc93972a48b, $002f5e50e78d5fee, $0080dc11d61c7fe5, $0065aa598707245b, $009abba2300641be, $000c68787656543a, $00ffe0fef2dc0a17, $00007ffbd6cb4f3a)),
            (FIELD_LITERAL($0036012f2b836efc, $00458c126d6b5fbc, $00a34436d719ad1e, $0097be6167117dea, $0009c219c879cff3, $0065564493e60755, $00993ac94a8cdec0, $002d4885a4d0dbaf)),
            (FIELD_LITERAL($00598b60b4c068ba, $00c547a0be7f1afd, $009582164acf12af, $00af4acac4fbbe40, $005f6ca7c539121a, $003b6e752ebf9d66, $00f08a30d5cac5d4, $00e399bb5f97c5a9)));
	    curve448_precomputed_base_table.table[7] := init_curve448_table(
            (FIELD_LITERAL($007445a0409c0a66, $00a65c369f3829c0, $0031d248a4f74826, $006817f34defbe8e, $00649741d95ebf2e, $00d46466ab16b397, $00fdc35703bee414, $00343b43334525f8)),
            (FIELD_LITERAL($001796bea93f6401, $00090c5a42e85269, $00672412ba1252ed, $001201d47b6de7de, $006877bccfe66497, $00b554fd97a4c161, $009753f42dbac3cf, $00e983e3e378270a)),
            (FIELD_LITERAL($00ac3eff18849872, $00f0eea3bff05690, $00a6d72c21dd505d, $001b832642424169, $00a6813017b540e5, $00a744bd71b385cd, $0022a7d089130a7b, $004edeec9a133486)));
	    curve448_precomputed_base_table.table[8] := init_curve448_table(
            (FIELD_LITERAL($00b2d6729196e8a9, $0088a9bb2031cef4, $00579e7787dc1567, $0030f49feb059190, $00a0b1d69c7f7d8f, $0040bdcc6d9d806f, $00d76c4037edd095, $00bbf24376415dd7)),
            (FIELD_LITERAL($00240465ff5a7197, $00bb97e76caf27d0, $004b4edbf8116d39, $001d8586f708cbaa, $000f8ee8ff8e4a50, $00dde5a1945dd622, $00e6fc1c0957e07c, $0041c9cdabfd88a0)),
            (FIELD_LITERAL($005344b0bf5b548c, $002957d0b705cc99, $00f586a70390553d, $0075b3229f583cc3, $00a1aa78227490e4, $001bf09cf7957717, $00cf6bf344325f52, $0065bd1c23ca3ecf)));
	    curve448_precomputed_base_table.table[9] := init_curve448_table(
            (FIELD_LITERAL($009bff3b3239363c, $00e17368796ef7c0, $00528b0fe0971f3a, $0008014fc8d4a095, $00d09f2e8a521ec4, $006713ab5dde5987, $0003015758e0dbb1, $00215999f1ba212d)),
            (FIELD_LITERAL($002c88e93527da0e, $0077c78f3456aad5, $0071087a0a389d1c, $00934dac1fb96dbd, $008470e801162697, $005bc2196cd4ad49, $00e535601d5087c3, $00769888700f497f)),
            (FIELD_LITERAL($00da7a4b557298ad, $0019d2589ea5df76, $00ef3e38be0c6497, $00a9644e1312609a, $004592f61b2558da, $0082c1df510d7e46, $0042809a535c0023, $00215bcb5afd7757)));
	    curve448_precomputed_base_table.table[10] := init_curve448_table(
            (FIELD_LITERAL($002b9df55a1a4213, $00dcfc3b464a26be, $00c4f9e07a8144d5, $00c8e0617a92b602, $008e3c93accafae0, $00bf1bcb95b2ca60, $004ce2426a613bf3, $00266cac58e40921)),
            (FIELD_LITERAL($008456d5db76e8f0, $0032ca9cab2ce163, $0059f2b8bf91abcf, $0063c2a021712788, $00f86155af22f72d, $00db98b2a6c005a0, $00ac6e416a693ac4, $007a93572af53226)),
            (FIELD_LITERAL($0087767520f0de22, $0091f64012279fb5, $001050f1f0644999, $004f097a2477ad3c, $006b37913a9947bd, $001a3d78645af241, $0057832bbb3008a7, $002c1d902b80dc20)));
	    curve448_precomputed_base_table.table[11] := init_curve448_table(
            (FIELD_LITERAL($001a6002bf178877, $009bce168aa5af50, $005fc318ff04a7f5, $0052818f55c36461, $008768f5d4b24afb, $0037ffbae7b69c85, $0018195a4b61edc0, $001e12ea088434b2)),
            (FIELD_LITERAL($0047d3f804e7ab07, $00a809ab5f905260, $00b3ffc7cdaf306d, $00746e8ec2d6e509, $00d0dade8887a645, $00acceeebde0dd37, $009bc2579054686b, $0023804f97f1c2bf)),
            (FIELD_LITERAL($0043e2e2e50b80d7, $00143aafe4427e0f, $005594aaecab855b, $008b12ccaaecbc01, $002deeb091082bc3, $009cca4be2ae7514, $00142b96e696d047, $00ad2a2b1c05256a)));
	    curve448_precomputed_base_table.table[12] := init_curve448_table(
            (FIELD_LITERAL($003914f2f144b78b, $007a95dd8bee6f68, $00c7f4384d61c8e6, $004e51eb60f1bdb2, $00f64be7aa4621d8, $006797bfec2f0ac0, $007d17aab3c75900, $001893e73cac8bc5)),
            (FIELD_LITERAL($00140360b768665b, $00b68aca4967f977, $0001089b66195ae4, $00fe71122185e725, $000bca2618d49637, $00a54f0557d7e98a, $00cdcd2f91d6f417, $00ab8c13741fd793)),
            (FIELD_LITERAL($00725ee6b1e549e0, $007124a0769777fa, $000b68fdad07ae42, $0085b909cd4952df, $0092d2e3c81606f4, $009f22f6cac099a0, $00f59da57f2799a8, $00f06c090122f777)));
	    curve448_precomputed_base_table.table[13] := init_curve448_table(
            (FIELD_LITERAL($00ce0bed0a3532bc, $001a5048a22df16b, $00e31db4cbad8bf1, $00e89292120cf00e, $007d1dd1a9b00034, $00e2a9041ff8f680, $006a4c837ae596e7, $00713af1068070b3)),
            (FIELD_LITERAL($00c4fe64ce66d04b, $00b095d52e09b3d7, $00758bbecb1a3a8e, $00f35cce8d0650c0, $002b878aa5984473, $0062e0a3b7544ddc, $00b25b290ed116fe, $007b0f6abe0bebf2)),
            (FIELD_LITERAL($0081d4e3addae0a8, $003410c836c7ffcc, $00c8129ad89e4314, $000e3d5a23922dcd, $00d91e46f29c31f3, $006c728cde8c5947, $002bc655ba2566c0, $002ca94721533108)));
	    curve448_precomputed_base_table.table[14] := init_curve448_table(
            (FIELD_LITERAL($0051e4b3f764d8a9, $0019792d46e904a0, $00853bc13dbc8227, $000840208179f12d, $0068243474879235, $0013856fbfe374d0, $00bda12fe8676424, $00bbb43635926eb2)),
            (FIELD_LITERAL($0012cdc880a93982, $003c495b21cd1b58, $00b7e5c93f22a26e, $0044aa82dfb99458, $009ba092cdffe9c0, $00a14b3ab2083b73, $000271c2f70e1c4b, $00eea9cac0f66eb8)),
            (FIELD_LITERAL($001a1847c4ac5480, $00b1b412935bb03a, $00f74285983bf2b2, $00624138b5b5d0f1, $008820c0b03d38bf, $00b94e50a18c1572, $0060f6934841798f, $00c52f5d66d6ebe2)));
	    curve448_precomputed_base_table.table[15] := init_curve448_table(
            (FIELD_LITERAL($00da23d59f9bcea6, $00e0f27007a06a4b, $00128b5b43a6758c, $000cf50190fa8b56, $00fc877aba2b2d72, $00623bef52edf53f, $00e6af6b819669e2, $00e314dc34fcaa4f)),
            (FIELD_LITERAL($0066e5eddd164d1e, $00418a7c6fe28238, $0002e2f37e962c25, $00f01f56b5975306, $0048842fa503875c, $0057b0e968078143, $00ff683024f3d134, $0082ae28fcad12e4)),
            (FIELD_LITERAL($0011ddfd21260e42, $00d05b0319a76892, $00183ea4368e9b8f, $00b0815662affc96, $00b466a5e7ce7c88, $00db93b07506e6ee, $0033885f82f62401, $0086f9090ec9b419)));
	    curve448_precomputed_base_table.table[16] := init_curve448_table(
            (FIELD_LITERAL($00d95d1c5fcb435a, $0016d1ed6b5086f9, $00792aa0b7e54d71, $0067b65715f1925d, $00a219755ec6176b, $00bc3f026b12c28f, $00700c897ffeb93e, $0089b83f6ec50b46)),
            (FIELD_LITERAL($003c97e6384da36e, $00423d53eac81a09, $00b70d68f3cdce35, $00ee7959b354b92c, $00f4e9718819c8ca, $009349f12acbffe9, $005aee7b62cb7da6, $00d97764154ffc86)),
            (FIELD_LITERAL($00526324babb46dc, $002ee99b38d7bf9e, $007ea51794706ef4, $00abeb04da6e3c39, $006b457c1d281060, $00fe243e9a66c793, $00378de0fb6c6ee4, $003e4194b9c3cb93)));
	    curve448_precomputed_base_table.table[17] := init_curve448_table(
            (FIELD_LITERAL($00fed3cd80ca2292, $0015b043a73ca613, $000a9fd7bf9be227, $003b5e03de2db983, $005af72d46904ef7, $00c0f1b5c49faa99, $00dc86fc3bd305e1, $00c92f08c1cb1797)),
            (FIELD_LITERAL($0079680ce111ed3b, $001a1ed82806122c, $000c2e7466d15df3, $002c407f6f7150fd, $00c5e7c96b1b0ce3, $009aa44626863ff9, $00887b8b5b80be42, $00b6023cec964825)),
            (FIELD_LITERAL($00e4a8e1048970c8, $0062887b7830a302, $00bcf1c8cd81402b, $0056dbb81a68f5be, $0014eced83f12452, $00139e1a510150df, $00bb81140a82d1a3, $000febcc1aaf1aa7)));
	    curve448_precomputed_base_table.table[18] := init_curve448_table(
            (FIELD_LITERAL($00a7527958238159, $0013ec9537a84cd6, $001d7fee7d562525, $00b9eefa6191d5e5, $00dbc97db70bcb8a, $00481affc7a4d395, $006f73d3e70c31bb, $00183f324ed96a61)),
            (FIELD_LITERAL($0039dd7ce7fc6860, $00d64f6425653da1, $003e037c7f57d0af, $0063477a06e2bcf2, $001727dbb7ac67e6, $0049589f5efafe2e, $00fc0fef2e813d54, $008baa5d087fb50d)),
            (FIELD_LITERAL($0024fb59d9b457c7, $00a7d4e060223e4c, $00c118d1b555fd80, $0082e216c732f22a, $00cd2a2993089504, $003638e836a3e13d, $000d855ee89b4729, $008ec5b7d4810c91)));
	    curve448_precomputed_base_table.table[19] := init_curve448_table(
            (FIELD_LITERAL($001bf51f7d65cdfd, $00d14cdafa16a97d, $002c38e60fcd10e7, $00a27446e393efbd, $000b5d8946a71fdd, $0063df2cde128f2f, $006c8679569b1888, $0059ffc4925d732d)),
            (FIELD_LITERAL($00ece96f95f2b66f, $00ece7952813a27b, $0026fc36592e489e, $007157d1a2de0f66, $00759dc111d86ddf, $0012881e5780bb0f, $00c8ccc83ad29496, $0012b9bd1929eb71)),
            (FIELD_LITERAL($000fa15a20da5df0, $00349ddb1a46cd31, $002c512ad1d8e726, $00047611f669318d, $009e68fba591e17e, $004320dffa803906, $00a640874951a3d3, $00b6353478baa24f)));
	    curve448_precomputed_base_table.table[20] := init_curve448_table(
            (FIELD_LITERAL($009696510000d333, $00ec2f788bc04826, $000e4d02b1f67ba5, $00659aa8dace08b6, $00d7a38a3a3ae533, $008856defa8c746b, $004d7a4402d3da1a, $00ea82e06229260f)),
            (FIELD_LITERAL($006a15bb20f75c0c, $0079a144027a5d0c, $00d19116ce0b4d70, $0059b83bcb0b268e, $005f58f63f16c127, $0079958318ee2c37, $00defbb063d07f82, $00f1f0b931d2d446)),
            (FIELD_LITERAL($00cb5e4c3c35d422, $008df885ca43577f, $00fa50b16ca3e471, $005a0e58e17488c8, $00b2ceccd6d34d19, $00f01d5d235e36e9, $00db2e7e4be6ca44, $00260ab77f35fccd)));
	    curve448_precomputed_base_table.table[21] := init_curve448_table(
            (FIELD_LITERAL($006f6fd9baac61d5, $002a7710a020a895, $009de0db7fc03d4d, $00cdedcb1875f40b, $00050caf9b6b1e22, $005e3a6654456ab0, $00775fdf8c4423d4, $0028701ea5738b5d)),
            (FIELD_LITERAL($009ffd90abfeae96, $00cba3c2b624a516, $005ef08bcee46c91, $00e6fde30afb6185, $00f0b4db4f818ce4, $006c54f45d2127f5, $00040125035854c7, $00372658a3287e13)),
            (FIELD_LITERAL($00d7070fb1beb2ab, $0078fc845a93896b, $006894a4b2f224a6, $005bdd8192b9dbde, $00b38839874b3a9e, $00f93618b04b7a57, $003e3ec75fd2c67e, $00bf5e6bfc29494a)));
	    curve448_precomputed_base_table.table[22] := init_curve448_table(
            (FIELD_LITERAL($00f19224ebba2aa5, $0074f89d358e694d, $00eea486597135ad, $0081579a4555c7e1, $0010b9b872930a9d, $00f002e87a30ecc0, $009b9d66b6de56e2, $00a3c4f45e8004eb)),
            (FIELD_LITERAL($0045e8dda9400888, $002ff12e5fc05db7, $00a7098d54afe69c, $00cdbe846a500585, $00879c1593ca1882, $003f7a7fea76c8b0, $002cd73dd0c8e0a1, $00645d6ce96f51fe)),
            (FIELD_LITERAL($002b7e83e123d6d6, $00398346f7419c80, $0042922e55940163, $005e7fc5601886a3, $00e88f2cee1d3103, $00e7fab135f2e377, $00b059984dbf0ded, $0009ce080faa5bb8)));
	    curve448_precomputed_base_table.table[23] := init_curve448_table(
            (FIELD_LITERAL($0085e78af7758979, $00275a4ee1631a3a, $00d26bc0ed78b683, $004f8355ea21064f, $00d618e1a32696e5, $008d8d7b150e5680, $00a74cd854b278d2, $001dd62702203ea0)),
            (FIELD_LITERAL($00f89335c2a59286, $00a0f5c905d55141, $00b41fb836ee9382, $00e235d51730ca43, $00a5cb37b5c0a69a, $009b966ffe136c45, $00cb2ea10bf80ed1, $00fb2b370b40dc35)),
            (FIELD_LITERAL($00d687d16d4ee8ba, $0071520bdd069dff, $00de85c60d32355d, $0087d2e3565102f4, $00cde391b8dfc9aa, $00e18d69efdfefe5, $004a9d0591954e91, $00fa36dd8b50eee5)));
	    curve448_precomputed_base_table.table[24] := init_curve448_table(
            (FIELD_LITERAL($002e788749a865f7, $006e4dc3116861ea, $009f1428c37276e6, $00e7d2e0fc1e1226, $003aeebc6b6c45f6, $0071a8073bf500c9, $004b22ad986b530c, $00f439e63c0d79d4)),
            (FIELD_LITERAL($006bc3d53011f470, $00032d6e692b83e8, $00059722f497cd0b, $0009b4e6f0c497cc, $0058a804b7cce6c0, $002b71d3302bbd5d, $00e2f82a36765fce, $008dded99524c703)),
            (FIELD_LITERAL($004d058953747d64, $00701940fe79aa6f, $00a620ac71c760bf, $009532b611158b75, $00547ed7f466f300, $003cb5ab53a8401a, $00c7763168ce3120, $007e48e33e4b9ab2)));
	    curve448_precomputed_base_table.table[25] := init_curve448_table(
            (FIELD_LITERAL($001b2fc57bf3c738, $006a3f918993fb80, $0026f7a14fdec288, $0075a2cdccef08db, $00d3ecbc9eecdbf1, $0048c40f06e5bf7f, $00d63e423009896b, $000598bc99c056a8)),
            (FIELD_LITERAL($002f194eaafa46dc, $008e38f57fe87613, $00dc8e5ae25f4ab2, $000a17809575e6bd, $00d3ec7923ba366a, $003a7e72e0ad75e3, $0010024b88436e0a, $00ed3c5444b64051)),
            (FIELD_LITERAL($00831fc1340af342, $00c9645669466d35, $007692b4cc5a080f, $009fd4a47ac9259f, $001eeddf7d45928b, $003c0446fc45f28b, $002c0713aa3e2507, $0095706935f0f41e)));
	    curve448_precomputed_base_table.table[26] := init_curve448_table(
            (FIELD_LITERAL($00766ae4190ec6d8, $0065768cabc71380, $00b902598416cdc2, $00380021ad38df52, $008f0b89d6551134, $004254d4cc62c5a5, $000d79f4484b9b94, $00b516732ae3c50e)),
            (FIELD_LITERAL($001fb73475c45509, $00d2b2e5ea43345a, $00cb3c3842077bd1, $0029f90ad820946e, $007c11b2380778aa, $009e54ece62c1704, $004bc60c41ca01c3, $004525679a5a0b03)),
            (FIELD_LITERAL($00c64fbddbed87b3, $0040601d11731faa, $009c22475b6f9d67, $0024b79dae875f15, $00616fed3f02c3b0, $0000cf39f6af2d3b, $00c46bac0aa9a688, $00ab23e2800da204)));
	    curve448_precomputed_base_table.table[27] := init_curve448_table(
            (FIELD_LITERAL($000b3a37617632b0, $00597199fe1cfb6c, $0042a7ccdfeafdd6, $004cc9f15ebcea17, $00f436e596a6b4a4, $00168861142df0d8, $000753edfec26af5, $000c495d7e388116)),
            (FIELD_LITERAL($0017085f4a346148, $00c7cf7a37f62272, $001776e129bc5c30, $009955134c9eef2a, $001ba5bdf1df07be, $00ec39497103a55c, $006578354fda6cfb, $005f02719d4f15ee)),
            (FIELD_LITERAL($0052b9d9b5d9655d, $00d4ec7ba1b461c3, $00f95df4974f280b, $003d8e5ca11aeb51, $00d4981eb5a70b26, $000af9a4f6659f29, $004598c846faeb43, $0049d9a183a47670)));
	    curve448_precomputed_base_table.table[28] := init_curve448_table(
            (FIELD_LITERAL($000a72d23dcb3f1f, $00a3737f84011727, $00f870c0fbbf4a47, $00a7aadd04b5c9ca, $000c7715c67bd072, $00015a136afcd74e, $0080d5caea499634, $0026b448ec7514b7)),
            (FIELD_LITERAL($00b60167d9e7d065, $00e60ba0d07381e8, $003a4f17b725c2d4, $006c19fe176b64fa, $003b57b31af86ccb, $0021047c286180fd, $00bdc8fb00c6dbb6, $00fe4a9f4bab4f3f)),
            (FIELD_LITERAL($0088ffc3a16111f7, $009155e4245d0bc8, $00851d68220572d5, $00557ace1e514d29, $0031d7c339d91022, $00101d0ae2eaceea, $00246ab3f837b66a, $00d5216d381ff530)));
	    curve448_precomputed_base_table.table[29] := init_curve448_table(
            (FIELD_LITERAL($0057e7ea35f36dae, $00f47d7ad15de22e, $00d757ea4b105115, $008311457d579d7e, $00b49b75b1edd4eb, $0081c7ff742fd63a, $00ddda3187433df6, $00475727d55f9c66)),
            (FIELD_LITERAL($00a6295218dc136a, $00563b3af0e9c012, $00d3753b0145db1b, $004550389c043dc1, $00ea94ae27401bdf, $002b0b949f2b7956, $00c63f780ad8e23c, $00e591c47d6bab15)),
            (FIELD_LITERAL($00416c582b058eb6, $004107da5b2cc695, $00b3cd2556aeec64, $00c0b418267e57a1, $001799293579bd2e, $0046ed44590e4d07, $001d7459b3630a1e, $00c6afba8b6696aa)));
	    curve448_precomputed_base_table.table[30] := init_curve448_table(
            (FIELD_LITERAL($008d6009b26da3f8, $00898e88ca06b1ca, $00edb22b2ed7fe62, $00fbc93516aabe80, $008b4b470c42ce0d, $00e0032ba7d0dcbb, $00d76da3a956ecc8, $007f20fe74e3852a)),
            (FIELD_LITERAL($002419222c607674, $00a7f23af89188b3, $00ad127284e73d1c, $008bba582fae1c51, $00fc6aa7ca9ecab1, $003df5319eb6c2ba, $002a05af8a8b199a, $004bf8354558407c)),
            (FIELD_LITERAL($00ce7d4a30f0fcbf, $00d02c272629f03d, $0048c001f7400bc2, $002c21368011958d, $0098a550391e96b5, $002d80b66390f379, $001fa878760cc785, $001adfce54b613d5)));
	    curve448_precomputed_base_table.table[31] := init_curve448_table(
            (FIELD_LITERAL($001ed4dc71fa2523, $005d0bff19bf9b5c, $00c3801cee065a64, $001ed0b504323fbf, $0003ab9fdcbbc593, $00df82070178b8d2, $00a2bcaa9c251f85, $00c628a3674bd02e)),
            (FIELD_LITERAL($006b7a0674f9f8de, $00a742414e5c7cff, $0041cbf3c6e13221, $00e3a64fd207af24, $0087c05f15fbe8d1, $004c50936d9e8a33, $001306ec21042b6d, $00a4f4137d1141c2)),
            (FIELD_LITERAL($0009e6fb921568b0, $00b3c60120219118, $002a6c3460dd503a, $009db1ef11654b54, $0063e4bf0be79601, $00670d34bb2592b9, $00dcee2f6c4130ce, $00b2682e88e77f54)));
	    curve448_precomputed_base_table.table[32] := init_curve448_table(
            (FIELD_LITERAL($000d5b4b3da135ab, $00838f3e5064d81d, $00d44eb50f6d94ed, $0008931ab502ac6d, $00debe01ca3d3586, $0025c206775f0641, $005ad4b6ae912763, $007e2c318ad8f247)),
            (FIELD_LITERAL($00ddbe0750dd1add, $004b3c7b885844b8, $00363e7ecf12f1ae, $0062e953e6438f9d, $0023cc73b076afe9, $00b09fa083b4da32, $00c7c3d2456c541d, $005b591ec6b694d4)),
            (FIELD_LITERAL($0028656e19d62fcf, $0052a4af03df148d, $00122765ddd14e42, $00f2252904f67157, $004741965b636f3a, $006441d296132cb9, $005e2106f956a5b7, $00247029592d335c)));
	    curve448_precomputed_base_table.table[33] := init_curve448_table(
            (FIELD_LITERAL($003fe038eb92f894, $000e6da1b72e8e32, $003a1411bfcbe0fa, $00b55d473164a9e4, $00b9a775ac2df48d, $0002ddf350659e21, $00a279a69eb19cb3, $00f844eab25cba44)),
            (FIELD_LITERAL($00c41d1f9c1f1ac1, $007b2df4e9f19146, $00b469355fd5ba7a, $00b5e1965afc852a, $00388d5f1e2d8217, $0022079e4c09ae93, $0014268acd4ef518, $00c1dd8d9640464c)),
            (FIELD_LITERAL($0038526adeed0c55, $00dd68c607e3fe85, $00f746ddd48a5d57, $0042f2952b963b7c, $001cbbd6876d5ec2, $005e341470bca5c2, $00871d41e085f413, $00e53ab098f45732)));
	    curve448_precomputed_base_table.table[34] := init_curve448_table(
            (FIELD_LITERAL($004d51124797c831, $008f5ae3750347ad, $0070ced94c1a0c8e, $00f6db2043898e64, $000d00c9a5750cd0, $000741ec59bad712, $003c9d11aab37b7f, $00a67ba169807714)),
            (FIELD_LITERAL($00adb2c1566e8b8f, $0096c68a35771a9a, $00869933356f334a, $00ba9c93459f5962, $009ec73fb6e8ca4b, $003c3802c27202e1, $0031f5b733e0c008, $00f9058c19611fa9)),
            (FIELD_LITERAL($00238f01814a3421, $00c325a44b6cce28, $002136f97aeb0e73, $000cac8268a4afe2, $0022fd218da471b3, $009dcd8dfff8def9, $00cb9f8181d999bb, $00143ae56edea349)));
	    curve448_precomputed_base_table.table[35] := init_curve448_table(
            (FIELD_LITERAL($0000623bf87622c5, $00a1966fdd069496, $00c315b7b812f9fc, $00bdf5efcd128b97, $001d464f532e3e16, $003cd94f081bfd7e, $00ed9dae12ce4009, $002756f5736eee70)),
            (FIELD_LITERAL($00a5187e6ee7341b, $00e6d52e82d83b6e, $00df3c41323094a7, $00b3324f444e9de9, $00689eb21a35bfe5, $00f16363becd548d, $00e187cc98e7f60f, $00127d9062f0ccab)),
            (FIELD_LITERAL($004ad71b31c29e40, $00a5fcace12fae29, $004425b5597280ed, $00e7ef5d716c3346, $0010b53ada410ac8, $0092310226060c9b, $0091c26128729c7e, $0088b42900f8ec3b)));
	    curve448_precomputed_base_table.table[36] := init_curve448_table(
            (FIELD_LITERAL($00f1e26e9762d4a8, $00d9d74082183414, $00ffec9bd57a0282, $000919e128fd497a, $00ab7ae7d00fe5f8, $0054dc442851ff68, $00c9ebeb3b861687, $00507f7cab8b698f)),
            (FIELD_LITERAL($00c13c5aae3ae341, $009c6c9ed98373e7, $00098f26864577a8, $0015b886e9488b45, $0037692c42aadba5, $00b83170b8e7791c, $001670952ece1b44, $00fd932a39276da2)),
            (FIELD_LITERAL($0081a3259bef3398, $005480fff416107b, $00ce4f607d21be98, $003ffc084b41df9b, $0043d0bb100502d1, $00ec35f575ba3261, $00ca18f677300ef3, $00e8bb0a827d8548)));
	    curve448_precomputed_base_table.table[37] := init_curve448_table(
            (FIELD_LITERAL($00df76b3328ada72, $002e20621604a7c2, $00f910638a105b09, $00ef4724d96ef2cd, $00377d83d6b8a2f7, $00b4f48805ade324, $001cd5da8b152018, $0045af671a20ca7f)),
            (FIELD_LITERAL($009ae3b93a56c404, $004a410b7a456699, $00023a619355e6b2, $009cdc7297387257, $0055b94d4ae70d04, $002cbd607f65b005, $003208b489697166, $00ea2aa058867370)),
            (FIELD_LITERAL($00f29d2598ee3f32, $00b4ac5385d82adc, $007633eaf04df19b, $00aa2d3d77ceab01, $004a2302fcbb778a, $00927f225d5afa34, $004a8e9d5047f237, $008224ae9dbce530)));
	    curve448_precomputed_base_table.table[38] := init_curve448_table(
            (FIELD_LITERAL($001cf640859b02f8, $00758d1d5d5ce427, $00763c784ef4604c, $005fa81aee205270, $00ac537bfdfc44cb, $004b919bd342d670, $00238508d9bf4b7a, $00154888795644f3)),
            (FIELD_LITERAL($00c845923c084294, $00072419a201bc25, $0045f408b5f8e669, $00e9d6a186b74dfe, $00e19108c68fa075, $0017b91d874177b7, $002f0ca2c7912c5a, $009400aa385a90a2)),
            (FIELD_LITERAL($0071110b01482184, $00cfed0044f2bef8, $0034f2901cf4662e, $003b4ae2a67f9834, $00cca9b96fe94810, $00522507ae77abd0, $00bac7422721e73e, $0066622b0f3a62b0)));
	    curve448_precomputed_base_table.table[39] := init_curve448_table(
            (FIELD_LITERAL($00f8ac5cf4705b6a, $00867d82dcb457e3, $007e13ab2ccc2ce9, $009ee9a018d3930e, $008370f8ecb42df8, $002d9f019add263e, $003302385b92d196, $00a15654536e2c0c)),
            (FIELD_LITERAL($0026ef1614e160af, $00c023f9edfc9c76, $00cff090da5f57ba, $0076db7a66643ae9, $0019462f8c646999, $008fec00b3854b22, $00d55041692a0a1c, $0065db894215ca00)),
            (FIELD_LITERAL($00a925036e0a451c, $002a0390c36b6cc1, $00f27020d90894f4, $008d90d52cbd3d7f, $00e1d0137392f3b8, $00f017c158b51a8f, $00cac313d3ed7dbc, $00b99a81e3eb42d3)));
	    curve448_precomputed_base_table.table[40] := init_curve448_table(
            (FIELD_LITERAL($00b54850275fe626, $0053a3fd1ec71140, $00e3d2d7dbe096fa, $00e4ac7b595cce4c, $0077bad449c0a494, $00b7c98814afd5b3, $0057226f58486cf9, $00b1557154f0cc57)),
            (FIELD_LITERAL($008cc9cd236315c0, $0031d9c5b39fda54, $00a5713ef37e1171, $00293d5ae2886325, $00c4aba3e05015e1, $0003f35ef78e4fc6, $0039d6bd3ac1527b, $0019d7c3afb77106)),
            (FIELD_LITERAL($007b162931a985af, $00ad40a2e0daa713, $006df27c4009f118, $00503e9f4e2e8bec, $00751a77c82c182d, $000298937769245b, $00ffb1e8fabf9ee5, $0008334706e09abe)));
	    curve448_precomputed_base_table.table[41] := init_curve448_table(
            (FIELD_LITERAL($00dbca4e98a7dcd9, $00ee29cfc78bde99, $00e4a3b6995f52e9, $0045d70189ae8096, $00fd2a8a3b9b0d1b, $00af1793b107d8e1, $00dbf92cbe4afa20, $00da60f798e3681d)),
            (FIELD_LITERAL($004246bfcecc627a, $004ba431246c03a4, $00bd1d101872d497, $003b73d3f185ee16, $001feb2e2678c0e3, $00ff13c5a89dec76, $00ed06042e771d8f, $00a4fd2a897a83dd)),
            (FIELD_LITERAL($009a4a3be50d6597, $00de3165fc5a1096, $004f3f56e345b0c7, $00f7bf721d5ab8bc, $004313e47b098c50, $00e4c7d5c0e1adbb, $002e3e3db365051e, $00a480c2cd6a96fb)));
	    curve448_precomputed_base_table.table[42] := init_curve448_table(
            (FIELD_LITERAL($00417fa30a7119ed, $00af257758419751, $00d358a487b463d4, $0089703cc720b00d, $00ce56314ff7f271, $0064db171ade62c1, $00640b36d4a22fed, $00424eb88696d23f)),
            (FIELD_LITERAL($004ede34af2813f3, $00d4a8e11c9e8216, $004796d5041de8a5, $00c4c6b4d21cc987, $00e8a433ee07fa1e, $0055720b5abcc5a1, $008873ea9c74b080, $005b3fec1ab65d48)),
            (FIELD_LITERAL($0047e5277db70ec5, $000a096c66db7d6b, $00b4164cc1730159, $004a9f783fe720fe, $00a8177b94449dbc, $0095a24ff49a599f, $0069c1c578250cbc, $00452019213debf4)));
	    curve448_precomputed_base_table.table[43] := init_curve448_table(
            (FIELD_LITERAL($0021ce99e09ebda3, $00fcbd9f91875ad0, $009bbf6b7b7a0b5f, $00388886a69b1940, $00926a56d0f81f12, $00e12903c3358d46, $005dfce4e8e1ce9d, $0044cfa94e2f7e23)),
            (FIELD_LITERAL($001bd59c09e982ea, $00f72daeb937b289, $0018b76dca908e0e, $00edb498512384ad, $00ce0243b6cc9538, $00f96ff690cb4e70, $007c77bf9f673c8d, $005bf704c088a528)),
            (FIELD_LITERAL($0093d4628dcb33be, $0095263d51d42582, $0049b3222458fe06, $00e7fce73b653a7f, $003ca2ebce60b369, $00c5de239a32bea4, $0063b8b3d71fb6bf, $0039aeeb78a1a839)));
	    curve448_precomputed_base_table.table[44] := init_curve448_table(
            (FIELD_LITERAL($007dc52da400336c, $001fded1e15b9457, $00902e00f5568e3a, $00219bef40456d2d, $005684161fb3dbc9, $004a4e9be49a76ea, $006e685ae88b78ff, $0021c42f13042d3c)),
            (FIELD_LITERAL($00fb22bb5fd3ce50, $0017b48aada7ae54, $00fd5c44ad19a536, $000ccc4e4e55e45c, $00fd637d45b4c3f5, $0038914e023c37cf, $00ac1881d6a8d898, $00611ed8d3d943a8)),
            (FIELD_LITERAL($0056e2259d113d2b, $00594819b284ec16, $00c7bf794bb36696, $00721ee75097cdc6, $00f71be9047a2892, $00df6ba142564edf, $0069580b7a184e8d, $00f056e38fca0fee)));
	    curve448_precomputed_base_table.table[45] := init_curve448_table(
            (FIELD_LITERAL($009df98566a18c6d, $00cf3a200968f219, $0044ba60da6d9086, $00dbc9c0e344da03, $000f9401c4466855, $00d46a57c5b0a8d1, $00875a635d7ac7c6, $00ef4a933b7e0ae6)),
            (FIELD_LITERAL($005e8694077a1535, $008bef75f71c8f1d, $000a7c1316423511, $00906e1d70604320, $003fc46c1a2ffbd6, $00d1d5022e68f360, $002515fba37bbf46, $00ca16234e023b44)),
            (FIELD_LITERAL($00787c99561f4690, $00a857a8c1561f27, $00a10df9223c09fe, $00b98a9562e3b154, $004330b8744c3ed2, $00e06812807ec5c4, $00e4cf6a7db9f1e3, $00d95b089f132a34)));
	    curve448_precomputed_base_table.table[46] := init_curve448_table(
            (FIELD_LITERAL($002922b39ca33eec, $0090d12a5f3ab194, $00ab60c02fb5f8ed, $00188d292abba1cf, $00e10edec9698f6e, $0069a4d9934133c8, $0024aac40e6d3d06, $001702c2177661b0)),
            (FIELD_LITERAL($00139078397030bd, $000e3c447e859a00, $0064a5b334c82393, $00b8aabeb7358093, $00020778bb9ae73b, $0032ee94c7892a18, $008215253cb41bda, $005e2797593517ae)),
            (FIELD_LITERAL($0083765a5f855d4a, $0051b6d1351b8ee2, $00116de548b0f7bb, $0087bd88703affa0, $0095b2cc34d7fdd2, $0084cd81b53f0bc8, $008562fc995350ed, $00a39abb193651e3)));
	    curve448_precomputed_base_table.table[47] := init_curve448_table(
            (FIELD_LITERAL($0019e23f0474b114, $00eb94c2ad3b437e, $006ddb34683b75ac, $00391f9209b564c6, $00083b3bb3bff7aa, $00eedcd0f6dceefc, $00b50817f794fe01, $0036474deaaa75c9)),
            (FIELD_LITERAL($0091868594265aa2, $00797accae98ca6d, $0008d8c5f0f8a184, $00d1f4f1c2b2fe6e, $0036783dfb48a006, $008c165120503527, $0025fd780058ce9b, $0068beb007be7d27)),
            (FIELD_LITERAL($00d0ff88aa7c90c2, $00b2c60dacf53394, $0094a7284d9666d6, $00bed9022ce7a19d, $00c51553f0cd7682, $00c3fb870b124992, $008d0bc539956c9b, $00fc8cf258bb8885)));
	    curve448_precomputed_base_table.table[48] := init_curve448_table(
            (FIELD_LITERAL($003667bf998406f8, $0000115c43a12975, $001e662f3b20e8fd, $0019ffa534cb24eb, $00016be0dc8efb45, $00ff76a8b26243f5, $00ae20d241a541e3, $0069bd6af13cd430)),
            (FIELD_LITERAL($0045fdc16487cda3, $00b2d8e844cf2ed7, $00612c50e88c1607, $00a08aabc66c1672, $006031fdcbb24d97, $001b639525744b93, $004409d62639ab17, $00a1853d0347ab1d)),
            (FIELD_LITERAL($0075a1a56ebf5c21, $00a3e72be9ac53ed, $00efcde1629170c2, $0004225fe91ef535, $0088049fc73dfda7, $004abc74857e1288, $0024e2434657317c, $00d98cb3d3e5543c)));
	    curve448_precomputed_base_table.table[49] := init_curve448_table(
            (FIELD_LITERAL($00b4b53eab6bdb19, $009b22d8b43711d0, $00d948b9d961785d, $00cb167b6f279ead, $00191de3a678e1c9, $00d9dd9511095c2e, $00f284324cd43067, $00ed74fa535151dd)),
            (FIELD_LITERAL($007e32c049b5c477, $009d2bfdbd9bcfd8, $00636e93045938c6, $007fde4af7687298, $0046a5184fafa5d3, $0079b1e7f13a359b, $00875adf1fb927d6, $00333e21c61bcad2)),
            (FIELD_LITERAL($00048014f73d8b8d, $0075684aa0966388, $0092be7df06dc47c, $0097cebcd0f5568a, $005a7004d9c4c6a9, $00b0ecbb659924c7, $00d90332dd492a7c, $0057fc14df11493d)));
	    curve448_precomputed_base_table.table[50] := init_curve448_table(
            (FIELD_LITERAL($0008ed8ea0ad95be, $0041d324b9709645, $00e25412257a19b4, $0058df9f3423d8d2, $00a9ab20def71304, $009ae0dbf8ac4a81, $00c9565977e4392a, $003c9269444baf55)),
            (FIELD_LITERAL($007df6cbb926830b, $00d336058ae37865, $007af47dac696423, $0048d3011ec64ac8, $006b87666e40049f, $0036a2e0e51303d7, $00ba319bd79dbc55, $003e2737ecc94f53)),
            (FIELD_LITERAL($00d296ff726272d9, $00f6d097928fcf57, $00e0e616a55d7013, $00deaf454ed9eac7, $0073a56bedef4d92, $006ccfdf6fc92e19, $009d1ee1371a7218, $00ee3c2ee4462d80)));
	    curve448_precomputed_base_table.table[51] := init_curve448_table(
            (FIELD_LITERAL($00437bce9bccdf9d, $00e0c8e2f85dc0a3, $00c91a7073995a19, $00856ec9fe294559, $009e4b33394b156e, $00e245b0dc497e5c, $006a54e687eeaeff, $00f1cd1cd00fdb7c)),
            (FIELD_LITERAL($008132ae5c5d8cd1, $00121d68324a1d9f, $00d6be9dafcb8c76, $00684d9070edf745, $00519fbc96d7448e, $00388182fdc1f27e, $000235baed41f158, $00bf6cf6f1a1796a)),
            (FIELD_LITERAL($002adc4b4d148219, $003084ada0d3a90a, $0046de8aab0f2e4e, $00452d342a67b5fd, $00d4b50f01d4de21, $00db6d9fc0cefb79, $008c184c86a462cd, $00e17c83764d42da)));
	    curve448_precomputed_base_table.table[52] := init_curve448_table(
            (FIELD_LITERAL($007b2743b9a1e01a, $007847ffd42688c4, $006c7844d610a316, $00f0cb8b250aa4b0, $00a19060143b3ae6, $0014eb10b77cfd80, $000170905729dd06, $00063b5b9cd72477)),
            (FIELD_LITERAL($00ce382dc7993d92, $00021153e938b4c8, $00096f7567f48f51, $0058f81ddfe4b0d5, $00cc379a56b355c7, $002c760770d3e819, $00ee22d1d26e5a40, $00de6d93d5b082d7)),
            (FIELD_LITERAL($000a91a42c52e056, $00185f6b77fce7ea, $000803c51962f6b5, $0022528582ba563d, $0043f8040e9856d6, $0085a29ec81fb860, $005f9a611549f5ff, $00c1f974ecbd4b06)));
	    curve448_precomputed_base_table.table[53] := init_curve448_table(
            (FIELD_LITERAL($005b64c6fd65ec97, $00c1fdd7f877bc7f, $000d9cc6c89f841c, $005c97b7f1aff9ad, $0075e3c61475d47e, $001ecb1ba8153011, $00fe7f1c8d71d40d, $003fa9757a229832)),
            (FIELD_LITERAL($00ffc5c89d2b0cba, $00d363d42e3e6fc3, $0019a1a0118e2e8a, $00f7baeff48882e1, $001bd5af28c6b514, $0055476ca2253cb2, $00d8eb1977e2ddf3, $00b173b1adb228a1)),
            (FIELD_LITERAL($00f2cb99dd0ad707, $00e1e08b6859ddd8, $000008f2d0650bcc, $00d7ed392f8615c3, $00976750a94da27f, $003e83bb0ecb69ba, $00df8e8d15c14ac6, $00f9f7174295d9c2)));
	    curve448_precomputed_base_table.table[54] := init_curve448_table(
            (FIELD_LITERAL($00f11cc8e0e70bcb, $00e5dc689974e7dd, $0014e409f9ee5870, $00826e6689acbd63, $008a6f4e3d895d88, $00b26a8da41fd4ad, $000fb7723f83efd7, $009c749db0a5f6c3)),
            (FIELD_LITERAL($002389319450f9ba, $003677f31aa1250a, $0092c3db642f38cb, $00f8b64c0dfc9773, $00cd49fe3505b795, $0068105a4090a510, $00df0ba2072a8bb6, $00eb396143afd8be)),
            (FIELD_LITERAL($00a0d4ecfb24cdff, $00ddaf8008ba6479, $00f0b3e36d4b0f44, $003734bd3af1f146, $00b87e2efc75527e, $00d230df55ddab50, $002613257ae56c1d, $00bc0946d135934d)));
	    curve448_precomputed_base_table.table[55] := init_curve448_table(
            (FIELD_LITERAL($00468711bd994651, $0033108fa67561bf, $0089d760192a54b4, $00adc433de9f1871, $000467d05f36e050, $007847e0f0579f7f, $00a2314ad320052d, $00b3a93649f0b243)),
            (FIELD_LITERAL($0067f8f0c4fe26c9, $0079c4a3cc8f67b9, $0082b1e62f23550d, $00f2d409caefd7f5, $0080e67dcdb26e81, $0087ae993ea1f98a, $00aa108becf61d03, $001acf11efb608a3)),
            (FIELD_LITERAL($008225febbab50d9, $00f3b605e4dd2083, $00a32b28189e23d2, $00d507e5e5eb4c97, $005a1a84e302821f, $0006f54c1c5f08c7, $00a347c8cb2843f0, $0009f73e9544bfa5)));
	    curve448_precomputed_base_table.table[56] := init_curve448_table(
            (FIELD_LITERAL($006c59c9ae744185, $009fc32f1b4282cd, $004d6348ca59b1ac, $00105376881be067, $00af4096013147dc, $004abfb5a5cb3124, $000d2a7f8626c354, $009c6ed568e07431)),
            (FIELD_LITERAL($00e828333c297f8b, $009ef3cf8c3f7e1f, $00ab45f8fff31cb9, $00c8b4178cb0b013, $00d0c50dd3260a3f, $0097126ac257f5bc, $0042376cc90c705a, $001d96fdb4a1071e)),
            (FIELD_LITERAL($00542d44d89ee1a8, $00306642e0442d98, $0090853872b87338, $002362cbf22dc044, $002c222adff663b8, $0067c924495fcb79, $000e621d983c977c, $00df77a9eccb66fb)));
	    curve448_precomputed_base_table.table[57] := init_curve448_table(
            (FIELD_LITERAL($002809e4bbf1814a, $00b9e854f9fafb32, $00d35e67c10f7a67, $008f1bcb76e748cf, $004224d9515687d2, $005ba0b774e620c4, $00b5e57db5d54119, $00e15babe5683282)),
            (FIELD_LITERAL($00832d02369b482c, $00cba52ff0d93450, $003fa9c908d554db, $008d1e357b54122f, $00abd91c2dc950c6, $007eff1df4c0ec69, $003f6aeb13fb2d31, $00002d6179fc5b2c)),
            (FIELD_LITERAL($0046c9eda81c9c89, $00b60cb71c8f62fc, $0022f5a683baa558, $00f87319fccdf997, $009ca09b51ce6a22, $005b12baf4af7d77, $008a46524a1e33e2, $00035a77e988be0d)));
	    curve448_precomputed_base_table.table[58] := init_curve448_table(
            (FIELD_LITERAL($00a7efe46a7dbe2f, $002f66fd55014fe7, $006a428afa1ff026, $0056caaa9604ab72, $0033f3bcd7fac8ae, $00ccb1aa01c86764, $00158d1edf13bf40, $009848ee76fcf3b4)),
            (FIELD_LITERAL($00a9e7730a819691, $00d9cc73c4992b70, $00e299bde067de5a, $008c314eb705192a, $00e7226f17e8a3cc, $0029dfd956e65a47, $0053a8e839073b12, $006f942b2ab1597e)),
            (FIELD_LITERAL($001c3d780ecd5e39, $0094f247fbdcc5fe, $00d5c786fd527764, $00b6f4da74f0db2a, $0080f1f8badcd5fc, $00f36a373ad2e23b, $00f804f9f4343bf2, $00d1af40ec623982)));
	    curve448_precomputed_base_table.table[59] := init_curve448_table(
            (FIELD_LITERAL($0082aeace5f1b144, $00f68b3108cf4dd3, $00634af01dde3020, $000beab5df5c2355, $00e8b790d1b49b0b, $00e48d15854e36f4, $0040ab2d95f3db9f, $002711c4ed9e899a)),
            (FIELD_LITERAL($0039343746531ebe, $00c8509d835d429d, $00e79eceff6b0018, $004abfd31e8efce5, $007bbfaaa1e20210, $00e3be89c193e179, $001c420f4c31d585, $00f414a315bef5ae)),
            (FIELD_LITERAL($007c296a24990df8, $00d5d07525a75588, $00dd8e113e94b7e7, $007bbc58febe0cc8, $0029f51af9bfcad3, $007e9311ec7ab6f3, $009a884de1676343, $0050d5f2dce84be9)));
	    curve448_precomputed_base_table.table[60] := init_curve448_table(
            (FIELD_LITERAL($005fa020cca2450a, $00491c29db6416d8, $0037cefe3f9f9a85, $003d405230647066, $0049e835f0fdbe89, $00feb78ac1a0815c, $00828e4b32dc9724, $00db84f2dc8d6fd4)),
            (FIELD_LITERAL($0098cddc8b39549a, $006da37e3b05d22c, $00ce633cfd4eb3cb, $00fda288ef526acd, $0025338878c5d30a, $00f34438c4e5a1b4, $00584efea7c310f1, $0041a551f1b660ad)),
            (FIELD_LITERAL($00d7f7a8fbd6437a, $0062872413bf3753, $00ad4bbcb43c584b, $007fe49be601d7e3, $0077c659789babf4, $00eb45fcb06a741b, $005ce244913f9708, $0088426401736326)));
	    curve448_precomputed_base_table.table[61] := init_curve448_table(
            (FIELD_LITERAL($007bf562ca768d7c, $006c1f3a174e387c, $00f024b447fee939, $007e7af75f01143f, $003adb70b4eed89d, $00e43544021ad79a, $0091f7f7042011f6, $0093c1a1ee3a0ddc)),
            (FIELD_LITERAL($00a0b68ec1eb72d2, $002c03235c0d45a0, $00553627323fe8c5, $006186e94b17af94, $00a9906196e29f14, $0025b3aee6567733, $007e0dd840080517, $0018eb5801a4ba93)),
            (FIELD_LITERAL($00d7fe7017bf6a40, $006e3f0624be0c42, $00ffbba205358245, $00f9fc2cf8194239, $008d93b37bf15b4e, $006ddf2e38be8e95, $002b6e79bf5fcff9, $00ab355da425e2de)));
	    curve448_precomputed_base_table.table[62] := init_curve448_table(
            (FIELD_LITERAL($00938f97e20be973, $0099141a36aaf306, $0057b0ca29e545a1, $0085db571f9fbc13, $008b333c554b4693, $0043ab6ef3e241cb, $0054fb20aa1e5c70, $00be0ff852760adf)),
            (FIELD_LITERAL($003973d8938971d6, $002aca26fa80c1f5, $00108af1faa6b513, $00daae275d7924e6, $0053634ced721308, $00d2355fe0bbd443, $00357612b2d22095, $00f9bb9dd4136cf3)),
            (FIELD_LITERAL($002bff12cf5e03a5, $001bdb1fa8a19cf8, $00c91c6793f84d39, $00f869f1b2eba9af, $0059bc547dc3236b, $00d91611d6d38689, $00e062daaa2c0214, $00ed3c047cc2bc82)));
	    curve448_precomputed_base_table.table[63] := init_curve448_table(
            (FIELD_LITERAL($000050d70c32b31a, $001939d576d437b3, $00d709e598bf9fe6, $00a885b34bd2ee9e, $00dd4b5c08ab1a50, $0091bebd50b55639, $00cf79ff64acdbc6, $006067a39d826336)),
            (FIELD_LITERAL($0062dd0fb31be374, $00fcc96b84c8e727, $003f64f1375e6ae3, $0057d9b6dd1af004, $00d6a167b1103c7b, $00dd28f3180fb537, $004ff27ad7167128, $008934c33461f2ac)),
            (FIELD_LITERAL($0065b472b7900043, $00ba7efd2ff1064b, $000b67d6c4c3020f, $0012d28469f4e46d, $0031c32939703ec7, $00b49f0bce133066, $00f7e10416181d47, $005c90f51867eecc)));
	    curve448_precomputed_base_table.table[64] := init_curve448_table(
            (FIELD_LITERAL($0051207abd179101, $00fc2a5c20d9c5da, $00fb9d5f2701b6df, $002dd040fdea82b8, $00f163b0738442ff, $00d9736bd68855b8, $00e0d8e93005e61c, $00df5a40b3988570)),
            (FIELD_LITERAL($0006918f5dfce6dc, $00d4bf1c793c57fb, $0069a3f649435364, $00e89a50e5b0cd6e, $00b9f6a237e973af, $006d4ed8b104e41d, $00498946a3924cd2, $00c136ec5ac9d4f7)),
            (FIELD_LITERAL($0011a9c290ac5336, $002b9a2d4a6a6533, $009a8a68c445d937, $00361b27b07e5e5c, $003c043b1755b974, $00b7eb66cf1155ee, $0077af5909eefff2, $0098f609877cc806)));
	    curve448_precomputed_base_table.table[65] := init_curve448_table(
            (FIELD_LITERAL($00ab13af436bf8f4, $000bcf0a0dac8574, $00d50c864f705045, $00c40e611debc842, $0085010489bd5caa, $007c5050acec026f, $00f67d943c8da6d1, $00de1da0278074c6)),
            (FIELD_LITERAL($00b373076597455f, $00e83f1af53ac0f5, $0041f63c01dc6840, $0097dea19b0c6f4b, $007f9d63b4c1572c, $00e692d492d0f5f0, $00cbcb392e83b4ad, $0069c0f39ed9b1a8)),
            (FIELD_LITERAL($00861030012707c9, $009fbbdc7fd4aafb, $008f591d6b554822, $00df08a41ea18ade, $009d7d83e642abea, $0098c71bda3b78ff, $0022c89e7021f005, $0044d29a3fe1e3c4)));
	    curve448_precomputed_base_table.table[66] := init_curve448_table(
            (FIELD_LITERAL($00e748cd7b5c52f2, $00ea9df883f89cc3, $0018970df156b6c7, $00c5a46c2a33a847, $00cbde395e32aa09, $0072474ebb423140, $00fb00053086a23d, $001dafcfe22d4e1f)),
            (FIELD_LITERAL($00c903ee6d825540, $00add6c4cf98473e, $007636efed4227f1, $00905124ae55e772, $00e6b38fab12ed53, $0045e132b863fe55, $003974662edb366a, $00b1787052be8208)),
            (FIELD_LITERAL($00a614b00d775c7c, $00d7c78941cc7754, $00422dd68b5dabc4, $00a6110f0167d28b, $00685a309c252886, $00b439ffd5143660, $003656e29ee7396f, $00c7c9b9ed5ad854)));
	    curve448_precomputed_base_table.table[67] := init_curve448_table(
            (FIELD_LITERAL($0040f7e7c5b37bf2, $0064e4dc81181bba, $00a8767ae2a366b6, $001496b4f90546f2, $002a28493f860441, $0021f59513049a3a, $00852d369a8b7ee3, $00dd2e7d8b7d30a9)),
            (FIELD_LITERAL($00006e34a35d9fbc, $00eee4e48b2f019a, $006b344743003a5f, $00541d514f04a7e3, $00e81f9ee7647455, $005e2b916c438f81, $00116f8137b7eff0, $009bd3decc7039d1)),
            (FIELD_LITERAL($0005d226f434110d, $00af8288b8ef21d5, $004a7a52ef181c8c, $00be0b781b4b06de, $00e6e3627ded07e1, $00e43aa342272b8b, $00e86ab424577d84, $00fb292c566e35bb)));
	    curve448_precomputed_base_table.table[68] := init_curve448_table(
            (FIELD_LITERAL($00334f5303ea1222, $00dfb3dbeb0a5d3e, $002940d9592335c1, $00706a7a63e8938a, $005a533558bc4caf, $00558e33192022a9, $00970d9faf74c133, $002979fcb63493ca)),
            (FIELD_LITERAL($00e38abece3c82ab, $005a51f18a2c7a86, $009dafa2e86d592e, $00495a62eb688678, $00b79df74c0eb212, $0023e8cc78b75982, $005998cb91075e13, $00735aa9ba61bc76)),
            (FIELD_LITERAL($00d9f7a82ddbe628, $00a1fc782889ae0f, $0071ffda12d14b66, $0037cf4eca7fb3d5, $00c80bc242c58808, $0075bf8c2d08c863, $008d41f31afc52a7, $00197962ecf38741)));
	    curve448_precomputed_base_table.table[69] := init_curve448_table(
            (FIELD_LITERAL($006e9f475cccf2ee, $00454b9cd506430c, $00224a4fb79ee479, $0062e3347ef0b5e2, $0034fd2a3512232a, $00b8b3cb0f457046, $00eb20165daa38ec, $00128eebc2d9c0f7)),
            (FIELD_LITERAL($00bfc5fa1e4ea21f, $00c21d7b6bb892e6, $00cf043f3acf0291, $00c13f2f849b3c90, $00d1a97ebef10891, $0061e130a445e7fe, $0019513fdedbf22b, $001d60c813bff841)),
            (FIELD_LITERAL($0019561c7fcf0213, $00e3dca6843ebd77, $0068ea95b9ca920e, $009bdfb70f253595, $00c68f59186aa02a, $005aee1cca1c3039, $00ab79a8a937a1ce, $00b9a0e549959e6f)));
	    curve448_precomputed_base_table.table[70] := init_curve448_table(
            (FIELD_LITERAL($00c79e0b6d97dfbd, $00917c71fd2bc6e8, $00db7529ccfb63d8, $00be5be957f17866, $00a9e11fdc2cdac1, $007b91a8e1f44443, $00a3065e4057d80f, $004825f5b8d5f6d4)),
            (FIELD_LITERAL($003e4964fa8a8fc8, $00f6a1cdbcf41689, $00943cb18fe7fda7, $00606dafbf34440a, $005d37a86399c789, $00e79a2a69417403, $00fe34f7e68b8866, $0011f448ed2df10e)),
            (FIELD_LITERAL($00f1f57efcc1fcc4, $00513679117de154, $002e5b5b7c86d8c3, $009f6486561f9cfb, $00169e74b0170cf7, $00900205af4af696, $006acfddb77853f3, $00df184c90f31068)));
	    curve448_precomputed_base_table.table[71] := init_curve448_table(
            (FIELD_LITERAL($00b37396c3320791, $00fc7b67175c5783, $00c36d2cd73ecc38, $0080ebcc0b328fc5, $0043a5b22b35d35d, $00466c9f1713c9da, $0026ad346dcaa8da, $007c684e701183a6)),
            (FIELD_LITERAL($00fd579ffb691713, $00b76af4f81c412d, $00f239de96110f82, $00e965fb437f0306, $00ca7e9436900921, $00e487f1325fa24a, $00633907de476380, $00721c62ac5b8ea0)),
            (FIELD_LITERAL($00c0d54e542eb4f9, $004ed657171c8dcf, $00b743a4f7c2a39b, $00fd9f93ed6cc567, $00307fae3113e58b, $0058aa577c93c319, $00d254556f35b346, $00491aada2203f0d)));
	    curve448_precomputed_base_table.table[72] := init_curve448_table(
            (FIELD_LITERAL($00dff3103786ff34, $000144553b1f20c3, $0095613baeb930e4, $00098058275ea5d4, $007cd1402b046756, $0074d74e4d58aee3, $005f93fc343ff69b, $00873df17296b3b0)),
            (FIELD_LITERAL($00c4a1fb48635413, $00b5dd54423ad59f, $009ff5d53fd24a88, $003c98d267fc06a7, $002db7cb20013641, $00bd1d6716e191f2, $006dbc8b29094241, $0044bbf233dafa2c)),
            (FIELD_LITERAL($0055838d41f531e6, $00bf6a2dd03c81b2, $005827a061c4839e, $0000de2cbb36aac3, $002efa29d9717478, $00f9e928cc8a77ba, $00c134b458def9ef, $00958a182223fc48)));
	    curve448_precomputed_base_table.table[73] := init_curve448_table(
            (FIELD_LITERAL($000a9ee23c06881f, $002c727d3d871945, $00f47d971512d24a, $00671e816f9ef31a, $00883af2cfaad673, $00601f98583d6c9a, $00b435f5adc79655, $00ad87b71c04bff2)),
            (FIELD_LITERAL($007860d99db787cf, $00fda8983018f4a8, $008c8866bac4743c, $00ef471f84c82a3f, $00abea5976d3b8e7, $00714882896cd015, $00b49fae584ddac5, $008e33a1a0b69c81)),
            (FIELD_LITERAL($007b6ee2c9e8a9ec, $002455dbbd89d622, $006490cf4eaab038, $00d925f6c3081561, $00153b3047de7382, $003b421f8bdceb6f, $00761a4a5049da78, $00980348c5202433)));
	    curve448_precomputed_base_table.table[74] := init_curve448_table(
            (FIELD_LITERAL($007f8a43da97dd5c, $00058539c800fc7b, $0040f3cf5a28414a, $00d68dd0d95283d6, $004adce9da90146e, $00befa41c7d4f908, $007603bc2e3c3060, $00bdf360ab3545db)),
            (FIELD_LITERAL($00eebfd4e2312cc3, $00474b2564e4fc8c, $003303ef14b1da9b, $003c93e0e66beb1d, $0013619b0566925a, $008817c24d901bf3, $00b62bd8898d218b, $0075a7716f1e88a2)),
            (FIELD_LITERAL($0009218da1e6890f, $0026907f5fd02575, $004dabed5f19d605, $003abf181870249d, $00b52fd048cc92c4, $00b6dd51e415a5c5, $00d9eb82bd2b4014, $002c865a43b46b43)));
	    curve448_precomputed_base_table.table[75] := init_curve448_table(
            (FIELD_LITERAL($0070047189452f4c, $00f7ad12e1ce78d5, $00af1ba51ec44a8b, $005f39f63e667cd6, $00058eac4648425e, $00d7fdab42bea03b, $0028576a5688de15, $00af973209e77c10)),
            (FIELD_LITERAL($00c338b915d8fef0, $00a893292045c39a, $0028ab4f2eba6887, $0060743cb519fd61, $0006213964093ac0, $007c0b7a43f6266d, $008e3557c4fa5bda, $002da976de7b8d9d)),
            (FIELD_LITERAL($0048729f8a8b6dcd, $00fe23b85cc4d323, $00e7384d16e4db0e, $004a423970678942, $00ec0b763345d4ba, $00c477b9f99ed721, $00c29dad3777b230, $001c517b466f7df6)));
	    curve448_precomputed_base_table.table[76] := init_curve448_table(
            (FIELD_LITERAL($006366c380f7b574, $001c7d1f09ff0438, $003e20a7301f5b22, $00d3efb1916d28f6, $0049f4f81060ce83, $00c69d91ea43ced1, $002b6f3e5cd269ed, $005b0fb22ce9ec65)),
            (FIELD_LITERAL($00aa2261022d883f, $00ebcca4548010ac, $002528512e28a437, $0070ca7676b66082, $0084bda170f7c6d3, $00581b4747c9b8bb, $005c96a01061c7e2, $00fb7c4a362b5273)),
            (FIELD_LITERAL($00c30020eb512d02, $0060f288283a4d26, $00b7ed13becde260, $0075ebb74220f6e9, $00701079fcfe8a1f, $001c28fcdff58938, $002e4544b8f4df6b, $0060c5bc4f1a7d73)));
	    curve448_precomputed_base_table.table[77] := init_curve448_table(
            (FIELD_LITERAL($00ae307cf069f701, $005859f222dd618b, $00212d6c46ec0b0d, $00a0fe4642afb62d, $00420d8e4a0a8903, $00a80ff639bdf7b0, $0019bee1490b5d8e, $007439e4b9c27a86)),
            (FIELD_LITERAL($00a94700032a093f, $0076e96c225216e7, $00a63a4316e45f91, $007d8bbb4645d3b2, $00340a6ff22793eb, $006f935d4572aeb7, $00b1fb69f00afa28, $009e8f3423161ed3)),
            (FIELD_LITERAL($009ef49c6b5ced17, $00a555e6269e9f0a, $007e6f1d79ec73b5, $009ac78695a32ac4, $0001d77fbbcd5682, $008cea1fee0aaeed, $00f42bea82a53462, $002e46ab96cafcc9)));
	    curve448_precomputed_base_table.table[78] := init_curve448_table(
            (FIELD_LITERAL($0051cfcc5885377a, $00dce566cb1803ca, $00430c7643f2c7d4, $00dce1a1337bdcc0, $0010d5bd7283c128, $003b1b547f9b46fe, $000f245e37e770ab, $007b72511f022b37)),
            (FIELD_LITERAL($0060db815bc4786c, $006fab25beedc434, $00c610d06084797c, $000c48f08537bec0, $0031aba51c5b93da, $007968fa6e01f347, $0030070da52840c6, $00c043c225a4837f)),
            (FIELD_LITERAL($001bcfd00649ee93, $006dceb47e2a0fd5, $00f2cebda0cf8fd0, $00b6b9d9d1fbdec3, $00815262e6490611, $00ef7f5ce3176760, $00e49cd0c998d58b, $005fc6cc269ba57c)));
	    curve448_precomputed_base_table.table[79] := init_curve448_table(
            (FIELD_LITERAL($008940211aa0d633, $00addae28136571d, $00d68fdbba20d673, $003bc6129bc9e21a, $000346cf184ebe9a, $0068774d741ebc7f, $0019d5e9e6966557, $0003cbd7f981b651)),
            (FIELD_LITERAL($004a2902926f8d3f, $00ad79b42637ab75, $0088f60b90f2d4e8, $0030f54ef0e398c4, $00021dc9bf99681e, $007ebf66fde74ee3, $004ade654386e9a4, $00e7485066be4c27)),
            (FIELD_LITERAL($00445f1263983be0, $004cf371dda45e6a, $00744a89d5a310e7, $001f20ce4f904833, $00e746edebe66e29, $000912ab1f6c153d, $00f61d77d9b2444c, $0001499cd6647610)));

     curve448_wnaf_base_table[0] := init_curve448_table(
        FIELD_LITERAL($00303cda6feea532, $00860f1d5a3850e4, $00226b9fa4728ccd, $00e822938a0a0c0c, $00263a61c9ea9216, $001204029321b828, $006a468360983c65, $0002846f0a782143),
        FIELD_LITERAL($00303cda6feea532, $00860f1d5a3850e4, $00226b9fa4728ccd, $006822938a0a0c0c, $00263a61c9ea9215, $001204029321b828, $006a468360983c65, $0082846f0a782143),
        FIELD_LITERAL($00ef8e22b275198d, $00b0eb141a0b0e8b, $001f6789da3cb38c, $006d2ff8ed39073e, $00610bdb69a167f3, $00571f306c9689b4, $00f557e6f84b2df8, $002affd38b2c86db));
     curve448_wnaf_base_table[1] := init_curve448_table(
        FIELD_LITERAL($00cea0fc8d2e88b5, $00821612d69f1862, $0074c283b3e67522, $005a195ba05a876d, $000cddfe557feea4, $008046c795bcc5e5, $00540969f4d6e119, $00d27f96d6b143d5),
        FIELD_LITERAL($000c3b1019d474e8, $00e19533e4952284, $00cc9810ba7c920a, $00f103d2785945ac, $00bfa5696cc69b34, $00a8d3d51e9ca839, $005623cb459586b9, $00eae7ce1cd52e9e),
        FIELD_LITERAL($0005a178751dd7d8, $002cc3844c69c42f, $00acbfe5efe10539, $009c20f43431a65a, $008435d96374a7b3, $009ee57566877bd3, $0044691725ed4757, $001e87bb2fe2c6b2));
     curve448_wnaf_base_table[2] := init_curve448_table(
        FIELD_LITERAL($000cedc4debf7a04, $002ffa45000470ac, $002e9f9678201915, $0017da1208c4fe72, $007d558cc7d656cb, $0037a827287cf289, $00142472d3441819, $009c21f166cf8dd1),
        FIELD_LITERAL($003ef83af164b2f2, $000949a5a0525d0d, $00f4498186cac051, $00e77ac09ef126d2, $0073ae0b2c9296e9, $001c163f6922e3ed, $0062946159321bea, $00cfb79b22990b39),
        FIELD_LITERAL($00b001431ca9e654, $002d7e5eabcc9a3a, $0052e8114c2f6747, $0079ac4f94487f92, $00bffd919b5d749c, $00261f92ad15e620, $00718397b7a97895, $00c1443e6ebbc0c4));
     curve448_wnaf_base_table[3] := init_curve448_table(
        FIELD_LITERAL($00eacd90c1e0a049, $008977935b149fbe, $0004cb9ba11c93dc, $009fbd5b3470844d, $004bc18c9bfc22cf, $0057679a991839f3, $00ef15b76fb4092e, $0074a5173a225041),
        FIELD_LITERAL($003f5f9d7ec4777b, $00ab2e733c919c94, $001bb6c035245ae5, $00a325a49a883630, $0033e9a9ea3cea2f, $00e442a1eaa0e844, $00b2116d5b0e71b8, $00c16abed6d64047),
        FIELD_LITERAL($00c560b5ed051165, $001945adc5d65094, $00e221865710f910, $00cc12bc9e9b8ceb, $004faa9518914e35, $0017476d89d42f6d, $00b8f637c8fa1c8b, $0088c7d2790864b8));
     curve448_wnaf_base_table[4] := init_curve448_table(
        FIELD_LITERAL($00ef7eafc1c69be6, $0085d3855778fbea, $002c8d5b450cb6f5, $004e77de5e1e7fec, $0047c057893abded, $001b430b85d51e16, $00965c7b45640c3c, $00487b2bb1162b97),
        FIELD_LITERAL($0099c73a311beec2, $00a3eff38d8912ad, $002efa9d1d7e8972, $00f717ae1e14d126, $002833f795850c8b, $0066c12ad71486bd, $00ae9889da4820eb, $00d6044309555c08),
        FIELD_LITERAL($004b1c5283d15e41, $00669d8ea308ff75, $0004390233f762a1, $00e1d67b83cb6cec, $003eebaa964c78b1, $006b0aff965eb664, $00b313d4470bdc37, $008814ffcb3cb9d8));
     curve448_wnaf_base_table[5] := init_curve448_table(
        FIELD_LITERAL($009724b8ce68db70, $007678b5ed006f3d, $00bdf4b89c0abd73, $00299748e04c7c6d, $00ddd86492c3c977, $00c5a7febfa30a99, $00ed84715b4b02bb, $00319568adf70486),
        FIELD_LITERAL($0070ff2d864de5bb, $005a37eeb637ee95, $0033741c258de160, $00e6ca5cb1988f46, $001ceabd92a24661, $0030957bd500fe40, $001c3362afe912c5, $005187889f678bd2),
        FIELD_LITERAL($0086835fc62bbdc7, $009c3516ca4910a1, $00956c71f8d00783, $0095c78fcf63235f, $00fc7ff6ba05c222, $00cdd8b3f8d74a52, $00ac5ae16de8256e, $00e9d4be8ed48624));
     curve448_wnaf_base_table[6] := init_curve448_table(
        FIELD_LITERAL($00c0ce11405df2d8, $004e3f37b293d7b6, $002410172e1ac6db, $00b8dbff4bf8143d, $003a7b409d56eb66, $003e0f6a0dfef9af, $0081c4e4d3645be1, $00ce76076b127623),
        FIELD_LITERAL($00f6ee0f98974239, $0042d89af07d3a4f, $00846b7fe84346b5, $006a21fc6a8d39a1, $00ac8bc2541ff2d9, $006d4e2a77732732, $009a39b694cc3f2f, $0085c0aa2a404c8f),
        FIELD_LITERAL($00b261101a218548, $00c1cae96424277b, $00869da0a77dd268, $00bc0b09f8ec83ea, $00d61027f8e82ba9, $00aa4c85999dce67, $00eac3132b9f3fe1, $00fb9b0cf1c695d2));
     curve448_wnaf_base_table[7] := init_curve448_table(
        FIELD_LITERAL($0043079295512f0d, $0046a009861758e0, $003ee2842a807378, $0034cc9d1298e4fa, $009744eb4d31b3ee, $00afacec96650cd0, $00ac891b313761ae, $00e864d6d26e708a),
        FIELD_LITERAL($00a84d7c8a23b491, $0088e19aa868b27f, $0005986d43e78ce9, $00f28012f0606d28, $0017ded7e10249b3, $005ed4084b23af9b, $00b9b0a940564472, $00ad9056cceeb1f4),
        FIELD_LITERAL($00db91b357fe755e, $00a1aa544b15359c, $00af4931a0195574, $007686124fe11aef, $00d1ead3c7b9ef7e, $00aaf5fc580f8c15, $00e727be147ee1ec, $003c61c1e1577b86));
     curve448_wnaf_base_table[8] := init_curve448_table(
        FIELD_LITERAL($009d3fca983220cf, $00cd11acbc853dc4, $0017590409d27f1d, $00d2176698082802, $00fa01251b2838c8, $00dd297a0d9b51c6, $00d76c92c045820a, $00534bc7c46c9033),
        FIELD_LITERAL($0080ed9bc9b07338, $00fceac7745d2652, $008a9d55f5f2cc69, $0096ce72df301ac5, $00f53232e7974d87, $0071728c7ae73947, $0090507602570778, $00cb81cfd883b1b2),
        FIELD_LITERAL($005011aadea373da, $003a8578ec896034, $00f20a6535fa6d71, $005152d31e5a87cf, $002bac1c8e68ca31, $00b0e323db4c1381, $00f1d596b7d5ae25, $00eae458097cb4e0));
     curve448_wnaf_base_table[9] := init_curve448_table(
        FIELD_LITERAL($00920ac80f9b0d21, $00f80f7f73401246, $0086d37849b557d6, $0002bd4b317b752e, $00b26463993a42bb, $002070422a73b129, $00341acaa0380cb3, $00541914dd66a1b2),
        FIELD_LITERAL($00c1513cd66abe8c, $000139e01118944d, $0064abbcb8080bbb, $00b3b08202473142, $00c629ef25da2403, $00f0aec3310d9b7f, $0050b2227472d8cd, $00f6c8a922d41fb4),
        FIELD_LITERAL($001075ccf26b7b1f, $00bb6bb213170433, $00e9491ad262da79, $009ef4f48d2d384c, $008992770766f09d, $001584396b6b1101, $00af3f8676c9feef, $0024603c40269118));
     curve448_wnaf_base_table[10] := init_curve448_table(
        FIELD_LITERAL($009dd7b31319527c, $001e7ac948d873a9, $00fa54b46ef9673a, $0066efb8d5b02fe6, $00754b1d3928aeae, $0004262ac72a6f6b, $0079b7d49a6eb026, $003126a753540102),
        FIELD_LITERAL($009666e24f693947, $00f714311269d45f, $0010ffac1d0c851c, $0066e80c37363497, $00f1f4ad010c60b0, $0015c87408470ff7, $00651d5e9c7766a4, $008138819d7116de),
        FIELD_LITERAL($003934b11c57253b, $00ef308edf21f46e, $00e54e99c7a16198, $0080d57135764e63, $00751c27b946bc24, $00dd389ce4e9e129, $00a1a2bfd1cd84dc, $002fae73e5149b32));
     curve448_wnaf_base_table[11] := init_curve448_table(
        FIELD_LITERAL($00911657dffb4cdd, $00c100b7cc553d06, $00449d075ec467cc, $007062100bc64e70, $0043cf86f7bd21e7, $00f401dc4b797dea, $005224afb2f62e65, $00d1ede3fb5a42be),
        FIELD_LITERAL($00f2ba36a41aa144, $00a0c22d946ee18f, $008aae8ef9a14f99, $00eef4d79b19bb36, $008e75ce3d27b1fc, $00a65daa03b29a27, $00d9cc83684eb145, $009e1ed80cc2ed74),
        FIELD_LITERAL($00bed953d1997988, $00b93ed175a24128, $00871c5963fb6365, $00ca2df20014a787, $00f5d9c1d0b34322, $00f6f5942818db0a, $004cc091f49c9906, $00e8a188a60bff9f));
     curve448_wnaf_base_table[12] := init_curve448_table(
        FIELD_LITERAL($0032c7762032fae8, $00e4087232e0bc21, $00f767344b6e8d85, $00bbf369b76c2aa2, $008a1f46c6e1570c, $001368cd9780369f, $007359a39d079430, $0003646512921434),
        FIELD_LITERAL($007c4b47ca7c73e7, $005396221039734b, $008b64ddf0e45d7e, $00bfad5af285e6c2, $008ec711c5b1a1a8, $00cf663301237f98, $00917ee3f1655126, $004152f337efedd8),
        FIELD_LITERAL($0007c7edc9305daa, $000a6664f273701c, $00f6e78795e200b1, $005d05b9ecd2473e, $0014f5f17c865786, $00c7fd2d166fa995, $004939a2d8eb80e0, $002244ba0942c199));
     curve448_wnaf_base_table[13] := init_curve448_table(
        FIELD_LITERAL($00321e767f0262cf, $002e57d776caf68e, $00bf2c94814f0437, $00c339196acd622f, $001db4cce71e2770, $001ded5ddba6eee2, $0078608ab1554c8d, $00067fe0ab76365b),
        FIELD_LITERAL($00f09758e11e3985, $00169efdbd64fad3, $00e8889b7d6dacd6, $0035cdd58ea88209, $00bcda47586d7f49, $003cdddcb2879088, $0016da70187e954b, $009556ea2e92aacd),
        FIELD_LITERAL($008cab16bd1ff897, $00b389972cdf753f, $00ea8ed1e46dfdc0, $004fe7ef94c589f4, $002b8ae9b805ecf3, $0025c08d892874a5, $0023938e98d44c4c, $00f759134cabf69c));
     curve448_wnaf_base_table[14] := init_curve448_table(
        FIELD_LITERAL($006c2a84678e4b3b, $007a194aacd1868f, $00ed0225af424761, $00da0a6f293c64b8, $001062ac5c6a7a18, $0030f5775a8aeef4, $0002acaad76b7af0, $00410b8fd63a579f),
        FIELD_LITERAL($001ec59db3d9590e, $001e9e3f1c3f182d, $0045a9c3ec2cab14, $0008198572aeb673, $00773b74068bd167, $0012535eaa395434, $0044dba9e3bbb74a, $002fba4d3c74bd0e),
        FIELD_LITERAL($0042bf08fe66922c, $003318b8fbb49e8c, $00d75946004aa14c, $00f601586b42bf1c, $00c74cf1d912fe66, $00abcb36974b30ad, $007eb78720c9d2b8, $009f54ab7bd4df85));
     curve448_wnaf_base_table[15] := init_curve448_table(
        FIELD_LITERAL($00db9fc948f73826, $00fa8b3746ed8ee9, $00132cb65aafbeb2, $00c36ff3fe7925b8, $00837daed353d2fe, $00ec661be0667cf4, $005beb8ed2e90204, $00d77dd69e564967),
        FIELD_LITERAL($0042e6268b861751, $0008dd0469500c16, $00b51b57c338a3fd, $00cc4497d85cff6b, $002f13d6b57c34a4, $0083652eaf301105, $00cc344294cc93a8, $0060f4d02810e270),
        FIELD_LITERAL($00a8954363cd518b, $00ad171124bccb7b, $0065f46a4adaae00, $001b1a5b2a96e500, $0043fe24f8233285, $0066996d8ae1f2c3, $00c530f3264169f9, $00c0f92d07cf6a57));
     curve448_wnaf_base_table[16] := init_curve448_table(
        FIELD_LITERAL($0036a55c6815d943, $008c8d1def993db3, $002e0e1e8ff7318f, $00d883a4b92db00a, $002f5e781ae33906, $001a72adb235c06d, $00f2e59e736e9caa, $001a4b58e3031914),
        FIELD_LITERAL($00d73bfae5e00844, $00bf459766fb5f52, $0061b4f5a5313cde, $004392d4c3b95514, $000d3551b1077523, $0000998840ee5d71, $006de6e340448b7b, $00251aa504875d6e),
        FIELD_LITERAL($003bf343427ac342, $00adc0a78642b8c5, $0003b893175a8314, $0061a34ade5703bc, $00ea3ea8bb71d632, $00be0df9a1f198c2, $0046dd8e7c1635fb, $00f1523fdd25d5e5));
     curve448_wnaf_base_table[17] := init_curve448_table(
        FIELD_LITERAL($00633f63fc9dd406, $00e713ff80e04a43, $0060c6e970f2d621, $00a57cd7f0df1891, $00f2406a550650bb, $00b064290efdc684, $001eab0144d17916, $00cd15f863c293ab),
        FIELD_LITERAL($0029cec55273f70d, $007044ee275c6340, $0040f637a93015e2, $00338bb78db5aae9, $001491b2a6132147, $00a125d6cfe6bde3, $005f7ac561ba8669, $001d5eaea3fbaacf),
        FIELD_LITERAL($00054e9635e3be31, $000e43f31e2872be, $00d05b1c9e339841, $006fac50bd81fd98, $00cdc7852eaebb09, $004ff519b061991b, $009099e8107d4c85, $00273e24c36a4a61));
     curve448_wnaf_base_table[18] := init_curve448_table(
        FIELD_LITERAL($00070b4441ef2c46, $00efa5b02801a109, $00bf0b8c3ee64adf, $008a67e0b3452e98, $001916b1f2fa7a74, $00d781a78ff6cdc3, $008682ce57e5c919, $00cc1109dd210da3),
        FIELD_LITERAL($00cae8aaff388663, $005e983a35dda1c7, $007ab1030d8e37f4, $00e48940f5d032fe, $006a36f9ef30b331, $009be6f03958c757, $0086231ceba91400, $008bd0f7b823e7aa),
        FIELD_LITERAL($00cf881ebef5a45a, $004ebea78e7c6f2c, $0090da9209cf26a0, $00de2b2e4c775b84, $0071d6031c3c15ae, $00d9e927ef177d70, $00894ee8c23896fd, $00e3b3b401e41aad));
     curve448_wnaf_base_table[19] := init_curve448_table(
        FIELD_LITERAL($00204fef26864170, $00819269c5dee0f8, $00bfb4713ec97966, $0026339a6f34df78, $001f26e64c761dc2, $00effe3af313cb60, $00e17b70138f601b, $00f16e1ccd9ede5e),
        FIELD_LITERAL($005d9a8353fdb2db, $0055cc2048c698f0, $00f6c4ac89657218, $00525034d73faeb2, $00435776fbda3c7d, $0070ea5312323cbc, $007a105d44d069fb, $006dbc8d6dc786aa),
        FIELD_LITERAL($0017cff19cd394ec, $00fef7b810922587, $00e6483970dff548, $00ddf36ad6874264, $00e61778523fcce2, $0093a66c0c93b24a, $00fd367114db7f86, $007652d7ddce26dd));
     curve448_wnaf_base_table[20] := init_curve448_table(
        FIELD_LITERAL($00d92ced7ba12843, $00aea9c7771e86e7, $0046639693354f7b, $00a628dbb6a80c47, $003a0b0507372953, $00421113ab45c0d9, $00e545f08362ab7a, $0028ce087b4d6d96),
        FIELD_LITERAL($00a67ee7cf9f99eb, $005713b275f2ff68, $00f1d536a841513d, $00823b59b024712e, $009c46b9d0d38cec, $00cdb1595aa2d7d4, $008375b3423d9af8, $000ab0b516d978f7),
        FIELD_LITERAL($00428dcb3c510b0f, $00585607ea24bb4e, $003736bf1603687a, $00c47e568c4fe3c7, $003cd00282848605, $0043a487c3b91939, $004ffc04e1095a06, $00a4c989a3d4b918));
     curve448_wnaf_base_table[21] := init_curve448_table(
        FIELD_LITERAL($00a8778d0e429f7a, $004c02b059105a68, $0016653b609da3ff, $00d5107bd1a12d27, $00b4708f9a771cab, $00bb63b662033f69, $0072f322240e7215, $0019445b59c69222),
        FIELD_LITERAL($00cf4f6069a658e6, $0053ca52859436a6, $0064b994d7e3e117, $00cb469b9a07f534, $00cfb68f399e9d47, $00f0dcb8dac1c6e7, $00f2ab67f538b3a5, $0055544f178ab975),
        FIELD_LITERAL($0099b7a2685d538c, $00e2f1897b7c0018, $003adac8ce48dae3, $00089276d5c50c0c, $00172fca07ad6717, $00cb1a72f54069e5, $004ee42f133545b3, $00785f8651362f16));
     curve448_wnaf_base_table[22] := init_curve448_table(
        FIELD_LITERAL($0049cbac38509e11, $0015234505d42cdf, $00794fb0b5840f1c, $00496437344045a5, $0031b6d944e4f9b0, $00b207318ac1f5d8, $0000c840da7f5c5d, $00526f373a5c8814),
        FIELD_LITERAL($002c7b7742d1dfd9, $002cabeb18623c01, $00055f5e3e044446, $006c20f3b4ef54ba, $00c600141ec6b35f, $00354f437f1a32a3, $00bac4624a3520f9, $00c483f734a90691),
        FIELD_LITERAL($0053a737d422918d, $00f7fca1d8758625, $00c360336dadb04c, $00f38e3d9158a1b8, $0069ce3b418e84c6, $005d1697eca16ead, $00f8bd6a35ece13d, $007885dfc2b5afea));
     curve448_wnaf_base_table[23] := init_curve448_table(
        FIELD_LITERAL($00c3617ae260776c, $00b20dc3e96922d7, $00a1a7802246706a, $00ca6505a5240244, $002246b62d919782, $001439102d7aa9b3, $00e8af1139e6422c, $00c888d1b52f2b05),
        FIELD_LITERAL($005b67690ffd41d9, $005294f28df516f9, $00a879272412fcb9, $00098b629a6d1c8d, $00fabd3c8050865a, $00cd7e5b0a3879c5, $00153238210f3423, $00357cac101e9f42),
        FIELD_LITERAL($008917b454444fb7, $00f59247c97e441b, $00a6200a6815152d, $0009a4228601d254, $001c0360559bd374, $007563362039cb36, $00bd75b48d74e32b, $0017f515ac3499e8));
     curve448_wnaf_base_table[24] := init_curve448_table(
        FIELD_LITERAL($001532a7ffe41c5a, $00eb1edce358d6bf, $00ddbacc7b678a7b, $008a7b70f3c841a3, $00f1923bf27d3f4c, $000b2713ed8f7873, $00aaf67e29047902, $0044994a70b3976d),
        FIELD_LITERAL($00d54e802082d42c, $00a55aa0dce7cc6c, $006477b96073f146, $0082efe4ceb43594, $00a922bcba026845, $0077f19d1ab75182, $00c2bb2737846e59, $0004d7eec791dd33),
        FIELD_LITERAL($0044588d1a81d680, $00b0a9097208e4f8, $00212605350dc57e, $0028717cd2871123, $00fb083c100fd979, $0045a056ce063fdf, $00a5d604b4dd6a41, $001dabc08ba4e236));
     curve448_wnaf_base_table[25] := init_curve448_table(
        FIELD_LITERAL($00c4887198d7a7fa, $00244f98fb45784a, $0045911e15a15d01, $001d323d374c0966, $00967c3915196562, $0039373abd2f3c67, $000d2c5614312423, $0041cf2215442ce3),
        FIELD_LITERAL($008ede889ada7f06, $001611e91de2e135, $00fdb9a458a471b9, $00563484e03710d1, $0031cc81925e3070, $0062c97b3af80005, $00fa733eea28edeb, $00e82457e1ebbc88),
        FIELD_LITERAL($006a0df5fe9b6f59, $00a0d4ff46040d92, $004a7cedb6f93250, $00d1df8855b8c357, $00e73a46086fd058, $0048fb0add6dfe59, $001e03a28f1b4e3d, $00a871c993308d76));
     curve448_wnaf_base_table[26] := init_curve448_table(
        FIELD_LITERAL($0030dbb2d1766ec8, $00586c0ad138555e, $00d1a34f9e91c77c, $0063408ad0e89014, $00d61231b05f6f5b, $0009abf569f5fd8a, $00aec67a110f1c43, $0031d1a790938dd7),
        FIELD_LITERAL($006cded841e2a862, $00198d60af0ab6fb, $0018f09db809e750, $004e6ac676016263, $00eafcd1620969cb, $002c9784ca34917d, $0054f00079796de7, $00d9fab5c5972204),
        FIELD_LITERAL($004bd0fee2438a83, $00b571e62b0f83bd, $0059287d7ce74800, $00fb3631b645c3f0, $00a018e977f78494, $0091e27065c27b12, $007696c1817165e0, $008c40be7c45ba3a));
     curve448_wnaf_base_table[27] := init_curve448_table(
        FIELD_LITERAL($00a0f326327cb684, $001c7d0f672680ff, $008c1c81ffb112d1, $00f8f801674eddc8, $00e926d5d48c2a9d, $005bd6d954c6fe9a, $004c6b24b4e33703, $00d05eb5c09105cc),
        FIELD_LITERAL($00d61731caacf2cf, $002df0c7609e01c5, $00306172208b1e2b, $00b413fe4fb2b686, $00826d360902a221, $003f8d056e67e7f7, $0065025b0175e989, $00369add117865eb),
        FIELD_LITERAL($00aaf895aec2fa11, $000f892bc313eb52, $005b1c794dad050b, $003f8ec4864cec14, $00af81058d0b90e5, $00ebe43e183997bb, $00a9d610f9f3e615, $007acd8eec2e88d3));
     curve448_wnaf_base_table[28] := init_curve448_table(
        FIELD_LITERAL($0049b2fab13812a3, $00846db32cd60431, $000177fa578c8d6c, $00047d0e2ad4bc51, $00b158ba38d1e588, $006a45daad79e3f3, $000997b93cab887b, $00c47ea42fa23dc3),
        FIELD_LITERAL($0012b6fef7aeb1ca, $009412768194b6a7, $00ff0d351f23ab93, $007e8a14c1aff71b, $006c1c0170c512bc, $0016243ea02ab2e5, $007bb6865b303f3e, $0015ce6b29b159f4),
        FIELD_LITERAL($009961cd02e68108, $00e2035d3a1d0836, $005d51f69b5e1a1d, $004bccb4ea36edcd, $0069be6a7aeef268, $0063f4dd9de8d5a7, $006283783092ca35, $0075a31af2c35409));
     curve448_wnaf_base_table[29] := init_curve448_table(
        FIELD_LITERAL($00c412365162e8cf, $00012283fb34388a, $003e6543babf39e2, $00eead6b3a804978, $0099c0314e8b326f, $00e98e0a8d477a4f, $00d2eb96b127a687, $00ed8d7df87571bb),
        FIELD_LITERAL($00777463e308cacf, $00c8acb93950132d, $00ebddbf4ca48b2c, $0026ad7ca0795a0a, $00f99a3d9a715064, $000d60bcf9d4dfcc, $005e65a73a437a06, $0019d536a8db56c8),
        FIELD_LITERAL($00192d7dd558d135, $0027cd6a8323ffa7, $00239f1a412dc1e7, $0046b4b3be74fc5c, $0020c47a2bef5bce, $00aa17e48f43862b, $00f7e26c96342e5f, $0008011c530f39a9));
     curve448_wnaf_base_table[30] := init_curve448_table(
        FIELD_LITERAL($00aad4ac569bf0f1, $00a67adc90b27740, $0048551369a5751a, $0031252584a3306a, $0084e15df770e6fc, $00d7bba1c74b5805, $00a80ef223af1012, $0089c85ceb843a34),
        FIELD_LITERAL($00c4545be4a54004, $0099e11f60357e6c, $001f3936d19515a6, $007793df84341a6e, $0051061886717ffa, $00e9b0a660b28f85, $0044ea685892de0d, $000257d2a1fda9d9),
        FIELD_LITERAL($007e8b01b24ac8a8, $006cf3b0b5ca1337, $00f1607d3e36a570, $0039b7fab82991a1, $00231777065840c5, $00998e5afdd346f9, $00b7dc3e64acc85f, $00baacc748013ad6));
     curve448_wnaf_base_table[31] := init_curve448_table(
        FIELD_LITERAL($008ea6a4177580bf, $005fa1953e3f0378, $005fe409ac74d614, $00452327f477e047, $00a4018507fb6073, $007b6e71951caac8, $0012b42ab8a6ce91, $0080eca677294ab7),
        FIELD_LITERAL($00a53edc023ba69b, $00c6afa83ddde2e8, $00c3f638b307b14e, $004a357a64414062, $00e4d94d8b582dc9, $001739caf71695b7, $0012431b2ae28de1, $003b6bc98682907c),
        FIELD_LITERAL($008a9a93be1f99d6, $0079fa627cc699c8, $00b0cfb134ba84c8, $001c4b778249419a, $00df4ab3d9c44f40, $009f596e6c1a9e3c, $001979c0df237316, $00501e953a919b87));

end.

