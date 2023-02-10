from .common import run_backward_slicing_on_binary

def test_add32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_arm') == [937846598, 1947212994, 151287565, 4257145192, 1198076261, 3923515204, 1909765456, 2968465022, 2217036800, 3005960734, 545941882, 588478191, 1401398195, 903888944, 398148311, 119857788, 278414808, 957208950, 1022579359, 3951180242, 1764152885, 3922034229, 2804370634, 2157464411, 2660170198, 1431871100, 1228317392, 3394396195, 1569534144, 2644614330, 1918049295, 2195048109, 3832918434, 687197152, 1100870747, 2629730194, 2678512910, 4008688948, 3962148724, 2454319413, 2672894164, 131429578, 2992786784, 3488436108, 1999085519, 1721290233, 2578940537, 3351185471, 3792350976, 2445501183]

def test_add32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_mips') == [937846598, 1947212994, 151287565, 4257145192, 1198076261, 3923515204, 1909765456, 2968465022, 2217036800, 3005960734, 545941882, 588478191, 1401398195, 903888944, 398148311, 119857788, 278414808, 957208950, 1022579359, 3951180242, 1764152885, 3922034229, 2804370634, 2157464411, 2660170198, 1431871100, 1228317392, 3394396195, 1569534144, 2644614330, 1918049295, 2195048109, 3832918434, 687197152, 1100870747, 2629730194, 2678512910, 4008688948, 3962148724, 2454319413, 2672894164, 131429578, 2992786784, 3488436108, 1999085519, 1721290233, 2578940537, 3351185471, 3792350976, 2445501183]

def test_sub32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_arm') == [2015666661, 4054515733, 3900201846, 1647042257, 1578900997, 873973817, 4124400920, 2082432493, 2636582349, 533889821, 375309047, 1906530552, 3764905307, 1116616386, 2970873196, 2582275417, 2281651153, 112931931, 3187165205, 1272519155, 1398776217, 3599257544, 2337394488, 2242943687, 2195279827, 4253276880, 2345904490, 3068569049, 2216914034, 1593759227, 2261309913, 4267100179, 3477168557, 274691866, 426082873, 399460946, 1686868464, 1469443004, 3808405816, 1466190451, 1938820685, 1562777631, 1455725656, 2556547574, 3724008146, 3156710772, 1705717676, 3189648297, 2735797702, 2328110954]

def test_sub32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_mips') == [2015666661, 4054515733, 3900201846, 1647042257, 1578900997, 873973817, 4124400920, 2082432493, 2636582349, 533889821, 375309047, 1906530552, 3764905307, 1116616386, 2970873196, 2582275417, 2281651153, 112931931, 3187165205, 1272519155, 1398776217, 3599257544, 2337394488, 2242943687, 2195279827, 4253276880, 2345904490, 3068569049, 2216914034, 1593759227, 2261309913, 4267100179, 3477168557, 274691866, 426082873, 399460946, 1686868464, 1469443004, 3808405816, 1466190451, 1938820685, 1562777631, 1455725656, 2556547574, 3724008146, 3156710772, 1705717676, 3189648297, 2735797702, 2328110954]

def test_mul32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_arm') == [1601690255, 1870744438, 3169515440, 1708639919, 1179166690, 1900646760, 4260273920, 3230981554, 4204460189, 2111453602, 3231389994, 2144393977, 779448234, 3128483064, 4126429328, 4099936774, 1683173216, 2709962778, 2639682769, 1348850826, 625852617, 2323451380, 3674318688, 1474452960, 3561671637, 3985225241, 1864704793, 560169961, 1137540731, 2258970916, 3816553923, 1579028200, 3600679522, 1416588328, 1893661982, 4097051872, 139772340, 4167235380, 2034125694, 579177550, 2633993192, 1287823881, 661939572, 2163694288, 2704745308, 3192370514, 1725611558, 1584128576, 3376717968, 2614156754]

def test_mul32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_mips') == [1601690255, 1870744438, 3169515440, 1708639919, 1179166690, 1900646760, 4260273920, 3230981554, 4204460189, 2111453602, 3231389994, 2144393977, 779448234, 3128483064, 4126429328, 4099936774, 1683173216, 2709962778, 2639682769, 1348850826, 625852617, 2323451380, 3674318688, 1474452960, 3561671637, 3985225241, 1864704793, 560169961, 1137540731, 2258970916, 3816553923, 1579028200, 3600679522, 1416588328, 1893661982, 4097051872, 139772340, 4167235380, 2034125694, 579177550, 2633993192, 1287823881, 661939572, 2163694288, 2704745308, 3192370514, 1725611558, 1584128576, 3376717968, 2614156754]

def test_shr32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_arm') == [212, 470106, 0, 773, 133115, 0, 669015427, 2, 11940, 2657225, 3751424702, 2, 13, 97698665, 8173, 17771370, 8199121, 1130612226, 14381, 51716, 30, 90, 7132691, 99, 716097, 0, 3, 2, 962539843, 6, 29, 130263, 429, 2296897, 4002098, 4320, 80748, 82, 0, 13, 378, 1884538, 59543979, 19, 6738359, 69843, 4667, 0, 189, 1706287885]

def test_shr32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_mips') == [212, 470106, 0, 773, 133115, 0, 669015427, 2, 11940, 2657225, 3751424702, 2, 13, 97698665, 8173, 17771370, 8199121, 1130612226, 14381, 51716, 30, 90, 7132691, 99, 716097, 0, 3, 2, 962539843, 6, 29, 130263, 429, 2296897, 4002098, 4320, 80748, 82, 0, 13, 378, 1884538, 59543979, 19, 6738359, 69843, 4667, 0, 189, 1706287885]

def test_sar32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_arm') == [4294957855, 902915, 4294967292, 4293097404, 6358, 4267483291, 150530886, 1, 4294459307, 4294092531, 4294941938, 4294965346, 4289331110, 4294966128, 1919122, 4279360947, 4294965924, 18325, 4201616932, 25033130, 4292385575, 0, 120696, 4294227525, 14672, 1, 0, 226, 4291399533, 844, 10, 7926595, 4294967291, 4294967292, 1, 11814, 5408257, 865841, 3877, 4294967288, 1981, 10103521, 4294966486, 379390155, 3, 138, 3962109080, 983133, 4100305437, 14]

def test_sar32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_mips') == [4294957855, 902915, 4294967292, 4293097404, 6358, 4267483291, 150530886, 1, 4294459307, 4294092531, 4294941938, 4294965346, 4289331110, 4294966128, 1919122, 4279360947, 4294965924, 18325, 4201616932, 25033130, 4292385575, 0, 120696, 4294227525, 14672, 1, 0, 226, 4291399533, 844, 10, 7926595, 4294967291, 4294967292, 1, 11814, 5408257, 865841, 3877, 4294967288, 1981, 10103521, 4294966486, 379390155, 3, 138, 3962109080, 983133, 4100305437, 14]

def test_shl32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_arm') == [837025792, 1373424810, 2308708448, 4268994560, 0, 1466873287, 2684354560, 1644167168, 3489660928, 3096473576, 268435456, 4151133952, 0, 3978693760, 1979711488, 3061841920, 1559756800, 1275068416, 1306675384, 4212129792, 3758096384, 246756096, 908064768, 0, 2645843968, 324276224, 1644343841, 0, 0, 2388639744, 1610612736, 2147483648, 2147483648, 3024064128, 578813952, 805306368, 3296722944, 1073741824, 1409286144, 2975143296, 3098316913, 2157706240, 3170893824, 2952790016, 1912602624, 205520896, 3151003952, 1827778496, 704643072, 411664384]

def test_shl32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_mips') == [837025792, 1373424810, 2308708448, 4268994560, 0, 1466873287, 2684354560, 1644167168, 3489660928, 3096473576, 268435456, 4151133952, 0, 3978693760, 1979711488, 3061841920, 1559756800, 1275068416, 1306675384, 4212129792, 3758096384, 246756096, 908064768, 0, 2645843968, 324276224, 1644343841, 0, 0, 2388639744, 1610612736, 2147483648, 2147483648, 3024064128, 578813952, 805306368, 3296722944, 1073741824, 1409286144, 2975143296, 3098316913, 2157706240, 3170893824, 2952790016, 1912602624, 205520896, 3151003952, 1827778496, 704643072, 411664384]

def test_and32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_arm') == [474089512, 879888401, 4331648, 138543176, 1409288441, 159974402, 4150067744, 551182336, 1347455320, 8259110, 358719768, 1800487520, 1124164144, 11611524, 827001034, 67127297, 319818072, 436226200, 70160548, 218234880, 3224375554, 2689617920, 2179080, 3024388676, 3389260844, 277415425, 269877952, 1080122136, 274207138, 269091632, 553655456, 1074004097, 805445893, 269287624, 272630036, 1076115456, 143944036, 2434812161, 136316420, 2684375216, 3660612352, 2785542144, 2567508039, 338211329, 8655397, 2147500032, 1233275440, 3358605744, 2151682210, 3222307937]

def test_and32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_mips') == [474089512, 879888401, 4331648, 138543176, 1409288441, 159974402, 4150067744, 551182336, 1347455320, 8259110, 358719768, 1800487520, 1124164144, 11611524, 827001034, 67127297, 319818072, 436226200, 70160548, 218234880, 3224375554, 2689617920, 2179080, 3024388676, 3389260844, 277415425, 269877952, 1080122136, 274207138, 269091632, 553655456, 1074004097, 805445893, 269287624, 272630036, 1076115456, 143944036, 2434812161, 136316420, 2684375216, 3660612352, 2785542144, 2567508039, 338211329, 8655397, 2147500032, 1233275440, 3358605744, 2151682210, 3222307937]

def test_or32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_arm') == [3196846069, 4290239422, 2378956735, 3219863419, 2573662683, 4025215903, 2906586853, 930873215, 4286054143, 4006870895, 1475049150, 2683944567, 3757915610, 1055759719, 226469051, 3889167325, 2063312891, 3967799039, 1870659546, 2544796467, 2146900755, 804763511, 2684090751, 3184638941, 4219444215, 2146672379, 3452304639, 4110118138, 4294930223, 3955089278, 1543499519, 4289724287, 3619682238, 3598405604, 4294699738, 3204147135, 4290248444, 4268228599, 4223327198, 3221213039, 1837039615, 2797006747, 3892182783, 4194287582, 4226678203, 4248281084, 1509873151, 3215182591, 4294698963, 2672733073]

def test_or32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_mips') == [3196846069, 4290239422, 2378956735, 3219863419, 2573662683, 4025215903, 2906586853, 930873215, 4286054143, 4006870895, 1475049150, 2683944567, 3757915610, 1055759719, 226469051, 3889167325, 2063312891, 3967799039, 1870659546, 2544796467, 2146900755, 804763511, 2684090751, 3184638941, 4219444215, 2146672379, 3452304639, 4110118138, 4294930223, 3955089278, 1543499519, 4289724287, 3619682238, 3598405604, 4294699738, 3204147135, 4290248444, 4268228599, 4223327198, 3221213039, 1837039615, 2797006747, 3892182783, 4194287582, 4226678203, 4248281084, 1509873151, 3215182591, 4294698963, 2672733073]

def test_xor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_arm') == [2792736775, 1963835386, 3041572286, 3850882537, 2455639688, 855732756, 189155784, 2784226517, 4179852388, 2070240082, 3467410060, 2068044051, 3501318480, 744907643, 1556262927, 3120317936, 3945831433, 909164796, 138236833, 2623349600, 1189887953, 2544551231, 194945214, 1433474770, 3820784842, 3326340070, 3020309434, 2221126350, 1991630881, 1708181445, 1910838410, 2136078200, 2067889750, 2747658761, 1504050096, 4113805772, 325918392, 2192370263, 1336297177, 367947342, 616235293, 4134647233, 2008255781, 3310747988, 2579055985, 1458130930, 1853981684, 3660874957, 1980647325, 1193719809]

def test_xor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_mips') == [2792736775, 1963835386, 3041572286, 3850882537, 2455639688, 855732756, 189155784, 2784226517, 4179852388, 2070240082, 3467410060, 2068044051, 3501318480, 744907643, 1556262927, 3120317936, 3945831433, 909164796, 138236833, 2623349600, 1189887953, 2544551231, 194945214, 1433474770, 3820784842, 3326340070, 3020309434, 2221126350, 1991630881, 1708181445, 1910838410, 2136078200, 2067889750, 2747658761, 1504050096, 4113805772, 325918392, 2192370263, 1336297177, 367947342, 616235293, 4134647233, 2008255781, 3310747988, 2579055985, 1458130930, 1853981684, 3660874957, 1980647325, 1193719809]

def test_land32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_arm') == [False, False, True, False, True, False, False, False, False, False, True, False, True, False, True, False, True, True, True, True, True, False, True, True, False, True, False, False, False, True, True, True, False, False, False, False, False, True, True, False, True, True, True, False, False, True, True, False, True, True]

def test_land32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_mips') == [False, False, True, False, True, False, False, False, False, False, True, False, True, False, True, False, True, True, True, True, True, False, True, True, False, True, False, False, False, True, True, True, False, False, False, False, False, True, True, False, True, True, True, False, False, True, True, False, True, True]

def test_lor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_arm') == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_lor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_mips') == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_eq32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_arm') == [False, True, False, False, False, True, False, True, False, True, False, False, False, True, False, False, False, False, True, True, False, False, False, True, False, False, False, False, False, True, False, True, False, True, True, True, False, False, False, False, False, False, False, False, False, True, True, True, False, False]

def test_eq32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_mips') == [False, True, False, False, False, True, False, True, False, True, False, False, False, True, False, False, False, False, True, True, False, False, False, True, False, False, False, False, False, True, False, True, False, True, True, True, False, False, False, False, False, False, False, False, False, True, True, True, False, False]

def test_ne32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_arm') == [True, False, True, False, False, False, True, False, False, False, False, True, True, False, True, True, True, False, True, True, True, True, False, True, False, True, False, False, False, False, True, True, True, True, False, False, False, True, False, False, True, False, False, True, True, False, True, True, True, True]

def test_ne32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_mips') == [True, False, True, False, False, False, True, False, False, False, False, True, True, False, True, True, True, False, True, True, True, True, False, True, False, True, False, False, False, False, True, True, True, True, False, False, False, True, False, False, True, False, False, True, True, False, True, True, True, True]

def test_le32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_arm') == [True, True, False, True, False, True, False, False, True, True, False, False, True, False, True, True, True, True, True, False, False, False, False, False, True, True, False, False, False, False, False, True, True, False, True, True, True, False, False, True, False, False, False, False, False, False, False, True, False, False]

def test_le32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_mips') == [True, True, False, True, False, True, False, False, True, True, False, False, True, False, True, True, True, True, True, False, False, False, False, False, True, True, False, False, False, False, False, True, True, False, True, True, True, False, False, True, False, False, False, False, False, False, False, True, False, False]

def test_lt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_arm') == [False, True, True, True, False, True, True, False, True, False, False, False, False, True, True, False, True, False, True, True, True, True, True, True, False, False, False, True, True, True, False, True, True, False, True, True, True, True, False, True, False, True, True, False, True, True, True, True, False, False]

def test_lt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_mips') == [False, True, True, True, False, True, True, False, True, False, False, False, False, True, True, False, True, False, True, True, True, True, True, True, False, False, False, True, True, True, False, True, True, False, True, True, True, True, False, True, False, True, True, False, True, True, True, True, False, False]

def test_ge32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_arm') == [True, True, False, True, False, False, False, False, False, False, False, False, False, False, True, True, True, False, False, True, False, False, False, False, True, True, False, False, False, False, False, False, True, True, False, False, True, True, True, True, True, True, False, False, False, False, False, False, True, True]

def test_ge32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_mips') == [True, True, False, True, False, False, False, False, False, False, False, False, False, False, True, True, True, False, False, True, False, False, False, False, True, True, False, False, False, False, False, False, True, True, False, False, True, True, True, True, True, True, False, False, False, False, False, False, True, True]

def test_gt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_arm') == [False, False, True, False, False, False, True, False, False, False, False, False, True, False, True, True, True, True, False, False, False, True, True, True, True, True, True, True, True, True, False, True, False, False, False, False, True, True, True, False, True, True, True, True, True, False, True, True, False, False]

def test_gt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_mips') == [False, False, True, False, False, False, True, False, False, False, False, False, True, False, True, True, True, True, False, False, False, True, True, True, True, True, True, True, True, True, False, True, False, False, False, False, True, True, True, False, True, True, True, True, True, False, True, True, False, False]

