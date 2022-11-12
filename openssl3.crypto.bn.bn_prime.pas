unit openssl3.crypto.bn.bn_prime;

interface
uses OpenSSL.Api;

type prime_t = uint16 ;
     Pprime_t = ^prime_t;

//function BN_DEF(lo, hi: Uint64): BN_ULONG;
const // 1d arrays
    NUMPRIMES = 2048;
    primes : array[0..2047] of prime_t = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137,
    139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
    223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
    293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
    383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461,
    463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563,
    569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643,
    647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
    743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
    839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937,
    941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021,
    1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093,
    1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181,
    1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259,
    1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
    1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433,
    1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
    1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579,
    1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657,
    1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831,
    1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913,
    1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003,
    2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087,
    2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
    2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269,
    2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347,
    2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417,
    2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531,
    2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621,
    2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
    2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767,
    2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
    2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953,
    2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023, 3037, 3041,
    3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163,
    3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251,
    3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329,
    3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
    3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517,
    3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
    3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673,
    3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767,
    3769, 3779, 3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853,
    3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919, 3923, 3929, 3931,
    3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027,
    4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129,
    4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219, 4229,
    4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
    4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421,
    4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513,
    4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603,
    4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691,
    4703, 4721, 4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793,
    4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909,
    4919, 4931, 4933, 4937, 4943, 4951, 4957, 4967, 4969, 4973, 4987,
    4993, 4999, 5003, 5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077,
    5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171,
    5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
    5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387, 5393,
    5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471,
    5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557,
    5563, 5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653,
    5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741,
    5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839,
    5843, 5849, 5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903,
    5923, 5927, 5939, 5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043,
    6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131,
    6133, 6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
    6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301, 6311,
    6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379,
    6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521,
    6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607,
    6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703,
    6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803,
    6823, 6827, 6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899,
    6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983,
    6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079,
    7103, 7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
    7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297, 7307,
    7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433,
    7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523,
    7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577, 7583, 7589,
    7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687,
    7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789,
    7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883,
    7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009,
    8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101,
    8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219,
    8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291, 8293,
    8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419,
    8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501, 8513, 8521, 8527,
    8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609, 8623, 8627,
    8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707,
    8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803,
    8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867, 8887,
    8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001,
    9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103,
    9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199,
    9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293,
    9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397,
    9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439, 9461, 9463, 9467,
    9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587,
    9601, 9613, 9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679,
    9689, 9697, 9719, 9721, 9733, 9739, 9743, 9749, 9767, 9769, 9781,
    9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859,
    9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967,
    9973, 10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091,
    10093, 10099, 10103, 10111, 10133, 10139, 10141, 10151, 10159, 10163,
    10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247, 10253, 10259,
    10267, 10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331, 10333,
    10337, 10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433, 10453,
    10457, 10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531,
    10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631, 10639,
    10651, 10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723, 10729,
    10733, 10739, 10753, 10771, 10781, 10789, 10799, 10831, 10837, 10847,
    10853, 10859, 10861, 10867, 10883, 10889, 10891, 10903, 10909, 10937,
    10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003, 11027, 11047,
    11057, 11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117, 11119,
    11131, 11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213, 11239,
    11243, 11251, 11257, 11261, 11273, 11279, 11287, 11299, 11311, 11317,
    11321, 11329, 11351, 11353, 11369, 11383, 11393, 11399, 11411, 11423,
    11437, 11443, 11447, 11467, 11471, 11483, 11489, 11491, 11497, 11503,
    11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617, 11621,
    11633, 11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731,
    11743, 11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821, 11827,
    11831, 11833, 11839, 11863, 11867, 11887, 11897, 11903, 11909, 11923,
    11927, 11933, 11939, 11941, 11953, 11959, 11969, 11971, 11981, 11987,
    12007, 12011, 12037, 12041, 12043, 12049, 12071, 12073, 12097, 12101,
    12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161, 12163, 12197,
    12203, 12211, 12227, 12239, 12241, 12251, 12253, 12263, 12269, 12277,
    12281, 12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377, 12379,
    12391, 12401, 12409, 12413, 12421, 12433, 12437, 12451, 12457, 12473,
    12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527, 12539, 12541,
    12547, 12553, 12569, 12577, 12583, 12589, 12601, 12611, 12613, 12619,
    12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703, 12713,
    12721, 12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821,
    12823, 12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917,
    12919, 12923, 12941, 12953, 12959, 12967, 12973, 12979, 12983, 13001,
    13003, 13007, 13009, 13033, 13037, 13043, 13049, 13063, 13093, 13099,
    13103, 13109, 13121, 13127, 13147, 13151, 13159, 13163, 13171, 13177,
    13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267, 13291,
    13297, 13309, 13313, 13327, 13331, 13337, 13339, 13367, 13381, 13397,
    13399, 13411, 13417, 13421, 13441, 13451, 13457, 13463, 13469, 13477,
    13487, 13499, 13513, 13523, 13537, 13553, 13567, 13577, 13591, 13597,
    13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687, 13691,
    13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751, 13757, 13759,
    13763, 13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859, 13873,
    13877, 13879, 13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933,
    13963, 13967, 13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057,
    14071, 14081, 14083, 14087, 14107, 14143, 14149, 14153, 14159, 14173,
    14177, 14197, 14207, 14221, 14243, 14249, 14251, 14281, 14293, 14303,
    14321, 14323, 14327, 14341, 14347, 14369, 14387, 14389, 14401, 14407,
    14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479, 14489,
    14503, 14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561, 14563,
    14591, 14593, 14621, 14627, 14629, 14633, 14639, 14653, 14657, 14669,
    14683, 14699, 14713, 14717, 14723, 14731, 14737, 14741, 14747, 14753,
    14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821, 14827, 14831,
    14843, 14851, 14867, 14869, 14879, 14887, 14891, 14897, 14923, 14929,
    14939, 14947, 14951, 14957, 14969, 14983, 15013, 15017, 15031, 15053,
    15061, 15073, 15077, 15083, 15091, 15101, 15107, 15121, 15131, 15137,
    15139, 15149, 15161, 15173, 15187, 15193, 15199, 15217, 15227, 15233,
    15241, 15259, 15263, 15269, 15271, 15277, 15287, 15289, 15299, 15307,
    15313, 15319, 15329, 15331, 15349, 15359, 15361, 15373, 15377, 15383,
    15391, 15401, 15413, 15427, 15439, 15443, 15451, 15461, 15467, 15473,
    15493, 15497, 15511, 15527, 15541, 15551, 15559, 15569, 15581, 15583,
    15601, 15607, 15619, 15629, 15641, 15643, 15647, 15649, 15661, 15667,
    15671, 15679, 15683, 15727, 15731, 15733, 15737, 15739, 15749, 15761,
    15767, 15773, 15787, 15791, 15797, 15803, 15809, 15817, 15823, 15859,
    15877, 15881, 15887, 15889, 15901, 15907, 15913, 15919, 15923, 15937,
    15959, 15971, 15973, 15991, 16001, 16007, 16033, 16057, 16061, 16063,
    16067, 16069, 16073, 16087, 16091, 16097, 16103, 16111, 16127, 16139,
    16141, 16183, 16187, 16189, 16193, 16217, 16223, 16229, 16231, 16249,
    16253, 16267, 16273, 16301, 16319, 16333, 16339, 16349, 16361, 16363,
    16369, 16381, 16411, 16417, 16421, 16427, 16433, 16447, 16451, 16453,
    16477, 16481, 16487, 16493, 16519, 16529, 16547, 16553, 16561, 16567,
    16573, 16603, 16607, 16619, 16631, 16633, 16649, 16651, 16657, 16661,
    16673, 16691, 16693, 16699, 16703, 16729, 16741, 16747, 16759, 16763,
    16787, 16811, 16823, 16829, 16831, 16843, 16871, 16879, 16883, 16889,
    16901, 16903, 16921, 16927, 16931, 16937, 16943, 16963, 16979, 16981,
    16987, 16993, 17011, 17021, 17027, 17029, 17033, 17041, 17047, 17053,
    17077, 17093, 17099, 17107, 17117, 17123, 17137, 17159, 17167, 17183,
    17189, 17191, 17203, 17207, 17209, 17231, 17239, 17257, 17291, 17293,
    17299, 17317, 17321, 17327, 17333, 17341, 17351, 17359, 17377, 17383,
    17387, 17389, 17393, 17401, 17417, 17419, 17431, 17443, 17449, 17467,
    17471, 17477, 17483, 17489, 17491, 17497, 17509, 17519, 17539, 17551,
    17569, 17573, 17579, 17581, 17597, 17599, 17609, 17623, 17627, 17657,
    17659, 17669, 17681, 17683, 17707, 17713, 17729, 17737, 17747, 17749,
    17761, 17783, 17789, 17791, 17807, 17827, 17837, 17839, 17851, 17863 );


var
   small_prime_factors: array[0..16] of BN_ULONG;
   BN_SMALL_PRIME_FACTORS_TOP: Integer;
   _bignum_small_prime_factors :TBIGNUM;

function BN_check_prime(const p : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
function ossl_bn_check_prime(const w : PBIGNUM; checks : integer; ctx : PBN_CTX; do_trial_division : integer; cb : PBN_GENCB):integer;
function bn_mr_min_checks( bits : integer):integer;
function bn_is_prime_int(const w : PBIGNUM; checks : integer; ctx : PBN_CTX; do_trial_division : integer; cb : PBN_GENCB):integer;
function calc_trial_divisions( bits : integer):integer;
function ossl_bn_miller_rabin_is_prime(const w : PBIGNUM; iterations : integer; ctx : PBN_CTX; cb : PBN_GENCB; enhanced : integer;var status : Integer):integer;
function ossl_bn_get0_small_factors:PBIGNUM;
function BN_GENCB_call(cb : PBN_GENCB; a, b : integer):integer;
function BN_generate_prime_ex2(ret : PBIGNUM; bits, safe : integer;const add, rem : PBIGNUM; cb : PBN_GENCB; ctx : PBN_CTX):integer;
function probable_prime(rnd : PBIGNUM; bits, safe : integer; mods : Pprime_t; ctx : PBN_CTX):integer;
function probable_prime_dh(rnd : PBIGNUM; bits, safe : integer; mods : Pprime_t;const add, rem : PBIGNUM; ctx : PBN_CTX):integer;
function BN_generate_prime_ex(ret : PBIGNUM; bits, safe : integer;const add, rem : PBIGNUM; cb : PBN_GENCB):integer;

implementation
uses  openssl3.crypto.mem,        OpenSSL3.Err,
      openssl3.crypto.bn.bn_lib,  openssl3.crypto.bn.bn_word,
      openssl3.crypto.bn.bn_mont, openssl3.crypto.bn.bn_gcd,
      openssl3.crypto.bn.bn_exp,  openssl3.crypto.bn.bn_mod,
      openssl3.crypto.bn.bn_add,  openssl3.crypto.bn.bn_rand,
      openssl3.crypto.bn.bn_ctx,  openssl3.crypto.bn.bn_shift;

function square(x: BN_ULONG): BN_ULONG;
begin
  Result := (BN_ULONG(x) * BN_ULONG(x))
end;


function BN_generate_prime_ex(ret : PBIGNUM; bits, safe : integer;const add, rem : PBIGNUM; cb : PBN_GENCB):integer;
var
  ctx : PBN_CTX;
  retval : integer;
begin
    ctx := BN_CTX_new();
    if ctx = nil then
       Exit(0);
    retval := BN_generate_prime_ex2(ret, bits, safe, add, rem, cb, ctx);
    BN_CTX_free(ctx);
    Result := retval;
end;

function probable_prime_dh(rnd : PBIGNUM; bits, safe : integer; mods : Pprime_t;const add, rem : PBIGNUM; ctx : PBN_CTX):integer;
var
  i,  ret         : integer;
  t1              : PBIGNUM;
  delta           : BN_ULONG;
  trial_divisions : integer;
  maxdelta,
  _mod            : BN_ULONG;
  label _again, _err, _loop;
begin
{$POINTERMATH ON}
    ret := 0;
    trial_divisions := calc_trial_divisions(bits);
    maxdelta := BN_MASK2 - primes[trial_divisions - 1];
    BN_CTX_start(ctx);
    t1 := BN_CTX_get(ctx);
    if t1 = nil then
        goto _err ;
    if maxdelta > BN_MASK2 - BN_get_word(add) then
        maxdelta := BN_MASK2 - BN_get_word(add);
 _again:
    if 0>= BN_rand_ex(rnd, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD, 0, ctx) then
        goto _err ;
    { we need ((rnd-rem) % add) = 0 }
    if 0>= BN_mod(t1, rnd, add, ctx) then
        goto _err ;
    if 0>= BN_sub(rnd, rnd, t1 ) then
        goto _err ;
    if rem = nil then
    begin
        if 0>= BN_add_word(rnd, get_result(safe > 0, 3 , 1)) then
            goto _err ;
    end
    else
    begin
        if 0>= BN_add(rnd, rnd, rem) then
            goto _err ;
    end;
    if (BN_num_bits(rnd) < bits)  or
       (BN_get_word(rnd) < get_result (safe > 0, 5 , 3)) then
     begin
        if 0>= BN_add(rnd, rnd, add) then
            goto _err ;
    end;
    { we now have a random number 'rnd' to test. }
    for i := 1 to trial_divisions-1 do
    begin
        _mod := BN_mod_word(rnd, BN_ULONG(primes[i]));
        if _mod = BN_ULONG(-1)  then
            goto _err ;
        mods[i] := prime_t(_mod);
    end;
    delta := 0;

 _loop:
    for i := 1 to trial_divisions-1 do
    begin
        { check that rnd is a prime }
        if (bits <= 31)  and  (delta <= $7fffffff) and
           (square(primes[i]) > BN_get_word(rnd) + delta)  then
            break;
        { rnd mod p = 1 implies q = (rnd-1)/2 is divisible by p }
        if safe > 0 then
        begin
          if (mods[i] + delta ) mod primes[i] <= 1 then
          begin
            delta  := delta + (BN_get_word(add));
            if delta > maxdelta then
               goto _again ;
            goto _loop ;
          end;
        end
        else
        begin
           if (mods[i] + delta) mod primes[i] = 0 then
           begin
              delta  := delta + (BN_get_word(add));
              if delta > maxdelta then
                 goto _again ;
              goto _loop ;
           end;
        end;
    end;
    if 0>= BN_add_word(rnd, delta) then
        goto _err ;
    ret := 1;

 _err:
    BN_CTX_end(ctx);
    bn_check_top(rnd);
    Result := ret;
 {$POINTERMATH OFF}
end;


function probable_prime(rnd : PBIGNUM; bits, safe : integer; mods : Pprime_t; ctx : PBN_CTX):integer;
var
    i               : integer;
    delta           : BN_ULONG;
    trial_divisions : integer;
    maxdelta,
    _mod            : BN_ULONG;
    label _again, _loop;
begin
{$POINTERMATH ON}
    trial_divisions := calc_trial_divisions(bits);
    maxdelta := BN_MASK2 - primes[trial_divisions - 1];

 _again:
    if 0>= BN_priv_rand_ex(rnd, bits, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ODD, 0, ctx) then
        Exit(0);
    if (safe>0)  and  (0>= BN_set_bit(rnd, 1)) then
        Exit(0);
    { we now have a random number 'rnd' to test. }
    for i := 1 to trial_divisions-1 do
    begin
        _mod := BN_mod_word(rnd, BN_ULONG(primes[i]));
        if _mod = BN_ULONG(-1)  then
            Exit(0);
        mods[i] := prime_t(_mod);
    end;
    delta := 0;
 _loop:
    for i := 1 to trial_divisions-1 do
    begin
        {
         * check that rnd is a prime and also that
         * gcd(rnd-1,primes) = 1 (except for 2)
         * do the second check only if we are interested in safe primes
         * in the case that the candidate prime is a single word then
         * we check only the primes up to sqrt(rnd)
         }
        if (bits <= 31)  and  (delta <= $7fffffff) and
           (square(primes[i]) > BN_get_word(rnd) + delta) then
            break;
        if safe > 0 then
        begin
           if (mods[i] + delta ) mod primes[i] <= 1 then
           begin
              delta  := delta + get_result(safe > 0 , 4 , 2);
              if delta > maxdelta then
                 goto _again ;
              goto _loop ;
           end;

        end
        else
        begin
            if  (mods[i] + delta) mod primes[i] = 0 then
            begin
              delta  := delta + get_result(safe > 0, 4 , 2);
              if delta > maxdelta then
                 goto _again ;
              goto _loop
            end;
        end;

    end;
    if 0>= BN_add_word(rnd, delta) then
        Exit(0);
    if BN_num_bits(rnd)  <> bits then
        goto _again ;
    bn_check_top(rnd);
    Result := 1;
 {$POINTERMATH OFF}
end;

function BN_generate_prime_ex2(ret : PBIGNUM; bits, safe : integer;const add, rem : PBIGNUM; cb : PBN_GENCB; ctx : PBN_CTX):integer;
var
  t : PBIGNUM;
  found, i, j, c1 : integer;
  mods : Pprime_t;
  checks : integer;
  label _err,_loop;
begin
    found := 0;
    c1 := 0;
    mods := nil;
    checks := bn_mr_min_checks(bits);
    if bits < 2 then
    begin
        { There are no prime numbers this small. }
        ERR_raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL);
        Exit(0);
    end
    else
    if (add = nil)  and  (safe>0)  and ( bits < 6)  and  (bits <> 3) then
    begin
        {
         * The smallest safe prime (7) is three bits.
         * But the following two safe primes with less than 6 bits (11, 23)
         * are unreachable for BN_rand with BN_RAND_TOP_TWO.
         }
        ERR_raise(ERR_LIB_BN, BN_R_BITS_TOO_SMALL);
        Exit(0);
    end;
    mods := OPENSSL_zalloc(sizeof( mods^) * NUMPRIMES);
    if mods = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    BN_CTX_start(ctx);
    t := BN_CTX_get(ctx);
    if t = nil then
       goto _err ;

 _loop:
    { make a random number and set the top and bottom bits }
    if add = nil then
    begin
        if 0>= probable_prime(ret, bits, safe, mods, ctx) then
            goto _err ;
    end
    else
    begin
        if 0>= probable_prime_dh(ret, bits, safe, mods, add, rem, ctx) then
            goto _err ;
    end;
    if 0>= BN_GENCB_call(cb, 0, PostInc(c1))  then
        { aborted }
        goto _err ;
    if 0>= safe then
    begin
        i := bn_is_prime_int(ret, checks, ctx, 0, cb);
        if i = -1 then goto _err ;
        if i = 0 then goto _loop ;
    end
    else
    begin
        {
         * for 'safe prime' generation, check that (p-1)/2 is prime. Since a
         * prime is odd, We just need to divide by 2
         }
        if 0>= BN_rshift1(t, ret) then
            goto _err ;
        for i := 0 to checks-1 do
        begin
            j := bn_is_prime_int(ret, 1, ctx, 0, cb);
            if j = -1 then goto _err ;
            if j = 0 then goto _loop ;
            j := bn_is_prime_int(t, 1, ctx, 0, cb);
            if j = -1 then goto _err ;
            if j = 0 then goto _loop ;
            if 0>= BN_GENCB_call(cb, 2, c1 - 1 ) then
                goto _err ;
            { We have a safe prime test pass }
        end;
    end;
    { we have a prime :-) }
    found := 1;
 _err:
    OPENSSL_free(Pointer(mods));
    BN_CTX_end(ctx);
    bn_check_top(ret);
    Result := found;
end;



function BN_GENCB_call( cb : PBN_GENCB; a, b : integer):integer;
begin
    { No callback means continue }
    if  nil = cb then Exit(1);
    case cb.ver of
      1:
      begin
          { Deprecated-style callbacks }
          if  not Assigned(cb.cb.cb_1) then
             Exit(1);
          cb.cb.cb_1(a, b, cb.arg);
          Exit(1);
      end;
      2:
          { New-style callbacks }
          Exit(cb.cb.cb_2(a, b, cb));
      else
      begin
      end;

    end;
    { Unrecognised callback type }
    Result := 0;
end;

{$if BN_BITS2 = 64}
function BN_DEF(lo, hi: Uint64): BN_ULONG;
begin
  Result := (BN_ULONG(hi) shl 32) or lo;
end;
{$ELSE}

{$IFEND}
function ossl_bn_get0_small_factors:PBIGNUM;
begin
    Result := @_bignum_small_prime_factors;
end;


function ossl_bn_miller_rabin_is_prime(const w : PBIGNUM; iterations : integer;
                                       ctx : PBN_CTX; cb : PBN_GENCB;
                                       enhanced : integer;var status : Integer):integer;
var
  i, j, a, ret : integer;
  g, w1, w3, m, z, b, x : PBIGNUM;
  mont : PBN_MONT_CTX;
  label _err, _outer_loop, _composite;
begin
{$POINTERMATH ON}
    ret := 0;
    mont := nil;
    { w must be odd }
    if  not BN_is_odd(w) then
        Exit(0);
    BN_CTX_start(ctx);
    g := BN_CTX_get(ctx);
    w1 := BN_CTX_get(ctx);
    w3 := BN_CTX_get(ctx);
    x := BN_CTX_get(ctx);
    m := BN_CTX_get(ctx);
    z := BN_CTX_get(ctx);
    b := BN_CTX_get(ctx);
    if  not ( (b <> nil)
            { w1 := w - 1 }
             and  (BN_copy(w1, w) <> nil )  and  (BN_sub_word(w1, 1) > 0)
            { w3 := w - 3 }
             and  (BN_copy(w3, w) <> nil)
             and  (BN_sub_word(w3, 3)>0))   then
        goto _err ;
    { check w is larger than 3, otherwise the random b will be too small }
    if (BN_is_zero(w3)) or ( BN_is_negative(w3)>0)  then
        goto _err ;
    { (Step 1) Calculate largest integer 'a' such that 2^a divides w-1 }
    a := 1;
    while 0 >= BN_is_bit_set(w1, a) do
        Inc(a);
    { (Step 2) m = (w-1) / 2^a }
    if  0 >= BN_rshift(m, w1, a) then
        goto _err ;
    { Montgomery setup for computations mod a }
    mont := BN_MONT_CTX_new();
    if (mont = nil)  or (0>= BN_MONT_CTX_set(mont, w, ctx) )then
        goto _err ;
    if iterations = 0 then
       iterations := bn_mr_min_checks(BN_num_bits(w));
    { (Step 4) }
    for i := 0 to iterations - 1 do
    begin
        { (Step 4.1) obtain a Random string of bits b where 1 < b < w-1 }
        if  (0>= BN_priv_rand_range_ex(b, w3, 0, ctx) )   or
            (0>= BN_add_word(b, 2)) then { 1 < b < w-1 }
            goto _err ;

        if enhanced > 0 then
        begin
            { (Step 4.3) }
            if  0>= BN_gcd(g, b, w, ctx) then
                goto _err ;
            { (Step 4.4) }
            if  not BN_is_one(g) then
            begin
                status := BN_PRIMETEST_COMPOSITE_WITH_FACTOR;
                ret := 1;
                goto _err ;
            end;
        end;
        { (Step 4.5) z = b^m mod w }

        if  0>= BN_mod_exp_mont(z, b, m, w, ctx, mont) then
            goto _err ;

        { (Step 4.6) if (z = 1 or z = w-1) }
        if BN_is_one(z)  or  (BN_cmp(z, w1) = 0)  then
           goto _outer_loop;
        { (Step 4.7) for j = 1 to a-1 }

        for j := 1 to a - 1 do
        begin
            { (Step 4.7.1 - 4.7.2) x = z. z = x^2 mod w }
            if (nil = BN_copy(x, z))  or (0>= BN_mod_mul(z, x, x, w, ctx)) then
                goto _err ;
            { (Step 4.7.3) }
            if BN_cmp(z, w1) = 0  then
               goto _outer_loop;
            { (Step 4.7.4) }

            if BN_is_one(z) then
               goto _composite ;

        end;
        { At this point z = b^((w-1)/2) mod w }
        { (Steps 4.8 - 4.9) x = z, z = x^2 mod w }
        if  (nil = BN_copy(x, z)) or   (0>= BN_mod_mul(z, x, x, w, ctx)) then
            goto _err ;
        { (Step 4.10) }
        if BN_is_one(z)  then
            goto _composite ;
        { (Step 4.11) x = b^(w-1) mod w }
        if nil = BN_copy(x, z) then
            goto _err ;

_composite:
        if enhanced > 0 then
        begin
            { (Step 4.1.2) g = GCD(x-1, w) }
            if  (0>= BN_sub_word(x, 1))  or   (0>= BN_gcd(g, x, w, ctx)) then
                goto _err ;
            { (Steps 4.1.3 - 4.1.4) }
            if BN_is_one(g)  then
                status := BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME
            else
                status := BN_PRIMETEST_COMPOSITE_WITH_FACTOR;
        end
        else
        begin
            status := BN_PRIMETEST_COMPOSITE;
        end;
        ret := 1;
        goto _err;

_outer_loop:
        { (Step 4.1.5) }
        if  0>= BN_GENCB_call(cb, 1, i)  then
            goto _err ;
    end; //-->for i := 0 to iterations - 1

    { (Step 5) }
    status := BN_PRIMETEST_PROBABLY_PRIME;
    ret := 1;

_err:
    BN_clear(g);
    BN_clear(w1);
    BN_clear(w3);
    BN_clear(x);
    BN_clear(m);
    BN_clear(z);
    BN_clear(b);
    BN_CTX_end(ctx);
    BN_MONT_CTX_free(mont);
    Result := ret;
{$POINTERMATH OFF}
end;

function calc_trial_divisions( bits : integer):integer;
begin
    if bits <= 512 then
       Exit(64)
    else
    if (bits <= 1024) then
        Exit(128)
    else
    if (bits <= 2048) then
        Exit(384)
    else
    if (bits <= 4096) then
        Exit(1024);
    Result := NUMPRIMES;
end;

function bn_is_prime_int(const w : PBIGNUM; checks : integer; ctx : PBN_CTX; do_trial_division : integer; cb : PBN_GENCB):integer;
var
  i, status,
  ret             : integer;
  ctxlocal        : PBN_CTX;
  trial_divisions : integer;
  _mod            : BN_ULONG;
  label _err;
begin
    ret := -1;
{$IFNDEF FIPS_MODULE}
    ctxlocal := nil;
{$ELSE}
    if ctx = nil then Exit(-1);
{$ENDIF}
    { w must be bigger than 1 }
    if BN_cmp(w, BN_value_one())<= 0  then
        Exit(0);
    { w must be odd }
    if BN_is_odd(w) then
    begin
        { Take care of the really small prime 3 }
        if BN_is_word(w, 3) then
           Exit(1);
    end
    else
    begin
        { 2 is the only even prime }
        Exit(Int(BN_is_word(w, 2)));
    end;
    { first look for small factors }
    if do_trial_division >0 then
    begin
        trial_divisions := calc_trial_divisions(BN_num_bits(w));
        for i := 1 to trial_divisions-1 do
        begin
            _mod := BN_mod_word(w, primes[i]);
            if _mod = BN_ULONG(-1)  then
                Exit(-1);
            if _mod = 0 then
               Exit(Int(BN_is_word(w, primes[i])));
        end;
        if  0>= BN_GENCB_call(cb, 1, -1) then
            Exit(-1);
    end;
{$IFNDEF FIPS_MODULE}

    if (ctx = nil) then
    begin
        ctx := BN_CTX_new();
        ctxlocal := ctx;
        if ctxlocal = nil  then
            goto _err ;
    end;
{$ENDIF}
    ret := ossl_bn_miller_rabin_is_prime(w, checks, ctx, cb, 0, status);
    if 0>= ret then
       goto _err ;
    ret := int(status = BN_PRIMETEST_PROBABLY_PRIME);

_err:
{$IFNDEF FIPS_MODULE}
    BN_CTX_free(ctxlocal);
{$ENDIF}
    Result := ret;
end;

function bn_mr_min_checks( bits : integer):integer;
begin
    if bits > 2048 then Exit(128);
    Result := 64;
end;

function ossl_bn_check_prime(const w : PBIGNUM; checks : integer; ctx : PBN_CTX; do_trial_division : integer; cb : PBN_GENCB):integer;
var
  min_checks : integer;
begin
    min_checks := bn_mr_min_checks(BN_num_bits(w));
    if checks < min_checks then
       checks := min_checks;
    Result := bn_is_prime_int(w, checks, ctx, do_trial_division, cb);
end;

function BN_check_prime(const p : PBIGNUM; ctx : PBN_CTX; cb : PBN_GENCB):integer;
begin
    Result := ossl_bn_check_prime(p, 0, ctx, 1, cb);
end;

initialization
    small_prime_factors[0] := BN_DEF($3ef4e3e1, $c4309333);
    small_prime_factors[1] := BN_DEF($cd2d655f, $71161eb6);
    small_prime_factors[2] := BN_DEF($0bf94862, $95e2238c);
    small_prime_factors[3] := BN_DEF($24f7912b, $3eb233d3);
    small_prime_factors[4] := BN_DEF($bf26c483, $6b55514b);
    small_prime_factors[5] := BN_DEF($5a144871, $0a84d817);
    small_prime_factors[6] := BN_DEF($9b82210a, $77d12fee);
    small_prime_factors[7] := BN_DEF($97f050b3, $db5b93c2);
    small_prime_factors[8] := BN_DEF($4d6c026b, $4acad6b9);
    small_prime_factors[9] := BN_DEF($54aec893, $eb7751f3);
    small_prime_factors[10] := BN_DEF($36bc85c4, $dba53368);
    small_prime_factors[11] := BN_DEF($7f5ec78e, $d85a1b28);
    small_prime_factors[12] := BN_DEF($6b322244, $2eb072d8);
    small_prime_factors[13] := BN_DEF($5e2b3aea, $bba51112);
    small_prime_factors[14] := BN_DEF($0e2486bf, $36ed1a6c);
    small_prime_factors[15] := BN_DEF($ec0c5727, $5f270460);
    small_prime_factors[16] := BN_ULONG($000017b1);

    BN_SMALL_PRIME_FACTORS_TOP := Length(small_prime_factors);
    _bignum_small_prime_factors.d := @small_prime_factors;
    _bignum_small_prime_factors.top := BN_SMALL_PRIME_FACTORS_TOP;
    _bignum_small_prime_factors.dmax := BN_SMALL_PRIME_FACTORS_TOP;
    _bignum_small_prime_factors.neg := 0;
    _bignum_small_prime_factors.flags := BN_FLG_STATIC_DATA;

end.
