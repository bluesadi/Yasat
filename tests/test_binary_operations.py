from .common import run_backward_slicing_on_binary

def test_add32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_arm') == [3046607165, 1013550881, 2292452589, 4045725630, 1771690493, 2743964717, 2621706789, 3753970349, 764639122, 1849975269, 1860054584, 3005684014, 1665546370, 3603598778, 1515571638, 1596877581, 576815322, 1454774742, 3884261651, 1404726640, 2960695411, 4275282722, 2575714092, 1543074106, 2622559779, 4294626744, 1702048739, 2162928780, 419351229, 2581853236, 1897019493, 1325945965, 3671973713, 3419445336, 2245223322, 2644105247, 3512747755, 3265697734, 2308667516, 2216810001, 3295596041, 1157888851, 2679905859, 2995806044, 858121098, 2449876311, 594558961, 2926399100, 2997252932, 778612886]

def test_add32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_mips') == [3046607165, 1013550881, 2292452589, 4045725630, 1771690493, 2743964717, 2621706789, 3753970349, 764639122, 1849975269, 1860054584, 3005684014, 1665546370, 3603598778, 1515571638, 1596877581, 576815322, 1454774742, 3884261651, 1404726640, 2960695411, 4275282722, 2575714092, 1543074106, 2622559779, 4294626744, 1702048739, 2162928780, 419351229, 2581853236, 1897019493, 1325945965, 3671973713, 3419445336, 2245223322, 2644105247, 3512747755, 3265697734, 2308667516, 2216810001, 3295596041, 1157888851, 2679905859, 2995806044, 858121098, 2449876311, 594558961, 2926399100, 2997252932, 778612886]

def test_sub32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_arm') == [3578688872, 3578989537, 3591127041, 3512173376, 4114478751, 3736302433, 374917889, 517717301, 3710397407, 4085370348, 3928551051, 241710676, 767359102, 1009052330, 394688703, 493981521, 4112801246, 4182726668, 2917312953, 1881445391, 3845274282, 2891107635, 2908169563, 2318973933, 1240661981, 460972092, 1213834893, 1365638687, 4053514728, 351966683, 2842014422, 1744240369, 3334753398, 3061854792, 270689254, 631486661, 1074342697, 2131356890, 3735700307, 234788698, 596251916, 2245979374, 1329152309, 3762102667, 592858781, 1079875752, 429454145, 1341914019, 607054188, 1880424939]

def test_sub32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_mips') == [3578688872, 3578989537, 3591127041, 3512173376, 4114478751, 3736302433, 374917889, 517717301, 3710397407, 4085370348, 3928551051, 241710676, 767359102, 1009052330, 394688703, 493981521, 4112801246, 4182726668, 2917312953, 1881445391, 3845274282, 2891107635, 2908169563, 2318973933, 1240661981, 460972092, 1213834893, 1365638687, 4053514728, 351966683, 2842014422, 1744240369, 3334753398, 3061854792, 270689254, 631486661, 1074342697, 2131356890, 3735700307, 234788698, 596251916, 2245979374, 1329152309, 3762102667, 592858781, 1079875752, 429454145, 1341914019, 607054188, 1880424939]

def test_mul32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_arm') == [977760456, 2341577337, 693346840, 2663645510, 3514308954, 3598895287, 441614134, 2598370880, 1117357776, 619654892, 3528173805, 2875519033, 2043507230, 4054154668, 1831567008, 3801079949, 493302376, 1268530928, 1298407557, 3718533868, 3884272230, 59534944, 3943062554, 2719979477, 1281813488, 368253556, 2739844090, 2212025204, 3131412296, 3594731840, 991431104, 74314050, 3115802576, 869896524, 404893704, 1647005534, 2426809128, 91823558, 1418163112, 1006888176, 2343138240, 3019782078, 3953094888, 1854398442, 2628565687, 3541239252, 4217737342, 1122282482, 150777996, 3629231504]

def test_mul32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_mips') == [977760456, 2341577337, 693346840, 2663645510, 3514308954, 3598895287, 441614134, 2598370880, 1117357776, 619654892, 3528173805, 2875519033, 2043507230, 4054154668, 1831567008, 3801079949, 493302376, 1268530928, 1298407557, 3718533868, 3884272230, 59534944, 3943062554, 2719979477, 1281813488, 368253556, 2739844090, 2212025204, 3131412296, 3594731840, 991431104, 74314050, 3115802576, 869896524, 404893704, 1647005534, 2426809128, 91823558, 1418163112, 1006888176, 2343138240, 3019782078, 3953094888, 1854398442, 2628565687, 3541239252, 4217737342, 1122282482, 150777996, 3629231504]

def test_shr32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_arm') == [30, 1, 6749, 0, 7519431, 6028440, 19540351, 4077167, 15, 4, 6129, 421044886, 1671, 1759, 111502035, 1478875725, 12186224, 1322014544, 23594848, 896749, 47433527, 16951199, 32069, 53246717, 46202753, 0, 56831614, 0, 13455477, 9, 10814913, 0, 0, 3074330, 375057, 59, 49, 44227, 155203947, 496335849, 1176234662, 4284, 492111, 741, 12775, 46933, 3882, 5299, 2916, 403652356]

def test_shr32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_mips') == [30, 1, 6749, 0, 7519431, 6028440, 19540351, 4077167, 15, 4, 6129, 421044886, 1671, 1759, 111502035, 1478875725, 12186224, 1322014544, 23594848, 896749, 47433527, 16951199, 32069, 53246717, 46202753, 0, 56831614, 0, 13455477, 9, 10814913, 0, 0, 3074330, 375057, 59, 49, 44227, 155203947, 496335849, 1176234662, 4284, 492111, 741, 12775, 46933, 3882, 5299, 2916, 403652356]

def test_sar32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_arm') == [126, 6, 4294943904, 0, 607, 137942539, 52413, 4294967295, 4155532267, 329, 26536014, 4294967295, 81039, 4294966461, 861691878, 4287271029, 4264602793, 4038295985, 4294965496, 4240824773, 4294966757, 4287667447, 23, 67757, 4294967295, 4294223549, 4294965694, 135, 1681996742, 4294734991, 4294967270, 0, 4287196962, 96014, 263, 0, 4268874047, 4294967293, 4294967247, 38, 4294392294, 1, 4294967295, 128876222, 0, 28, 4294965811, 2964300065, 4294640634, 53666329]

def test_sar32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_mips') == [126, 6, 4294943904, 0, 607, 137942539, 52413, 4294967295, 4155532267, 329, 26536014, 4294967295, 81039, 4294966461, 861691878, 4287271029, 4264602793, 4038295985, 4294965496, 4240824773, 4294966757, 4287667447, 23, 67757, 4294967295, 4294223549, 4294965694, 135, 1681996742, 4294734991, 4294967270, 0, 4287196962, 96014, 263, 0, 4268874047, 4294967293, 4294967247, 38, 4294392294, 1, 4294967295, 128876222, 0, 28, 4294965811, 2964300065, 4294640634, 53666329]

def test_shl32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_arm') == [3221225472, 1144360160, 2373976064, 2955219712, 193520656, 2760398080, 1043910912, 3019898880, 1920729088, 1841763840, 2351562752, 1644167168, 1029341184, 0, 526231992, 2677448448, 1778384896, 3995492352, 2442219536, 3414163456, 4255520768, 435991984, 2964504576, 2164260864, 2089575708, 3842664448, 2815950848, 0, 1632975616, 3545038592, 31558144, 1774481408, 1342177280, 2547461896, 292181920, 1735844160, 1608253440, 3794010112, 612368384, 1209532416, 54296576, 2986344448, 2844786688, 2730491904, 3577741312, 2415919104, 2214592512, 2592526336, 454331144, 2984516864]

def test_shl32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_mips') == [3221225472, 1144360160, 2373976064, 2955219712, 193520656, 2760398080, 1043910912, 3019898880, 1920729088, 1841763840, 2351562752, 1644167168, 1029341184, 0, 526231992, 2677448448, 1778384896, 3995492352, 2442219536, 3414163456, 4255520768, 435991984, 2964504576, 2164260864, 2089575708, 3842664448, 2815950848, 0, 1632975616, 3545038592, 31558144, 1774481408, 1342177280, 2547461896, 292181920, 1735844160, 1608253440, 3794010112, 612368384, 1209532416, 54296576, 2986344448, 2844786688, 2730491904, 3577741312, 2415919104, 2214592512, 2592526336, 454331144, 2984516864]

def test_and32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_arm') == [590348290, 3761242372, 2516595164, 1091440787, 617088, 528961, 1224892418, 8962480, 4629000, 271869961, 2148536482, 312821004, 2424930344, 538984704, 539771680, 268501008, 1346453504, 1930122659, 38928394, 8582664, 112298515, 1074937860, 1612848130, 270009347, 33818627, 1074201232, 135041930, 330607, 805306368, 423625986, 1109689612, 270794828, 680530224, 839788818, 1514766344, 537698316, 505454660, 1627456673, 277218328, 54525952, 1217155716, 1946944002, 610271654, 316818498, 3477782537, 771752976, 301989960, 411308548, 3162702024, 537592064]

def test_and32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_mips') == [590348290, 3761242372, 2516595164, 1091440787, 617088, 528961, 1224892418, 8962480, 4629000, 271869961, 2148536482, 312821004, 2424930344, 538984704, 539771680, 268501008, 1346453504, 1930122659, 38928394, 8582664, 112298515, 1074937860, 1612848130, 270009347, 33818627, 1074201232, 135041930, 330607, 805306368, 423625986, 1109689612, 270794828, 680530224, 839788818, 1514766344, 537698316, 505454660, 1627456673, 277218328, 54525952, 1217155716, 1946944002, 610271654, 316818498, 3477782537, 771752976, 301989960, 411308548, 3162702024, 537592064]

def test_or32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_arm') == [3017719807, 4019978103, 3287102750, 1325219741, 663713181, 3988757838, 2885679551, 4145802972, 2147146750, 4294795207, 4294966255, 2042085109, 2951477903, 1455421183, 3589259883, 2950461279, 3061702227, 372496375, 2013229054, 2077940144, 3589852154, 1073583870, 870250453, 4093074676, 3967794095, 3992810749, 4292198143, 3077946204, 3682589054, 3942447614, 3212558324, 4192181163, 4026499039, 4277726719, 4256923130, 385871357, 449148607, 3942120697, 1029035641, 4286316517, 3068723126, 3951001034, 2028993261, 3920621362, 4284201963, 3468689188, 3677978358, 3073241563, 4126538748, 3421462527]

def test_or32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_mips') == [3017719807, 4019978103, 3287102750, 1325219741, 663713181, 3988757838, 2885679551, 4145802972, 2147146750, 4294795207, 4294966255, 2042085109, 2951477903, 1455421183, 3589259883, 2950461279, 3061702227, 372496375, 2013229054, 2077940144, 3589852154, 1073583870, 870250453, 4093074676, 3967794095, 3992810749, 4292198143, 3077946204, 3682589054, 3942447614, 3212558324, 4192181163, 4026499039, 4277726719, 4256923130, 385871357, 449148607, 3942120697, 1029035641, 4286316517, 3068723126, 3951001034, 2028993261, 3920621362, 4284201963, 3468689188, 3677978358, 3073241563, 4126538748, 3421462527]

def test_xor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_arm') == [2282363159, 953379889, 1047963681, 308153266, 1673854926, 486783226, 3083342034, 4144435390, 1104411846, 4023972412, 879924188, 2978484512, 2016155086, 2191899112, 2306014055, 385497189, 1719245534, 754707159, 657899696, 2816869253, 3456543569, 891640231, 1785493892, 2539455021, 554054297, 71152322, 1983940940, 589514002, 2492536036, 3604542728, 705651003, 1370276361, 3733588807, 3177628777, 2665945511, 1044963523, 3977572705, 1497799137, 4099445325, 3938347653, 147132367, 3978190958, 3454492608, 1462717138, 2801560309, 3769331097, 561570505, 1546529113, 2811925602, 4124019493]

def test_xor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_mips') == [2282363159, 953379889, 1047963681, 308153266, 1673854926, 486783226, 3083342034, 4144435390, 1104411846, 4023972412, 879924188, 2978484512, 2016155086, 2191899112, 2306014055, 385497189, 1719245534, 754707159, 657899696, 2816869253, 3456543569, 891640231, 1785493892, 2539455021, 554054297, 71152322, 1983940940, 589514002, 2492536036, 3604542728, 705651003, 1370276361, 3733588807, 3177628777, 2665945511, 1044963523, 3977572705, 1497799137, 4099445325, 3938347653, 147132367, 3978190958, 3454492608, 1462717138, 2801560309, 3769331097, 561570505, 1546529113, 2811925602, 4124019493]

def test_land32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_arm') == [True, True, False, True, True, True, False, True, False, True, True, False, True, False, False, True, False, True, True, True, False, False, False, True, True, False, False, True, False, False, False, True, False, True, True, True, False, True, True, True, False, True, False, False, False, False, True, False, False, True]

def test_land32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_mips') == [True, True, False, True, True, True, False, True, False, True, True, False, True, False, False, True, False, True, True, True, False, False, False, True, True, False, False, True, False, False, False, True, False, True, True, True, False, True, True, True, False, True, False, False, False, False, True, False, False, True]

def test_lor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_arm') == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_lor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_mips') == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_eq32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_arm') == [False, False, True, False, True, False, False, True, True, True, True, True, False, False, True, True, False, True, False, True, True, True, True, True, True, False, True, True, False, True, False, False, False, False, False, True, False, False, True, True, False, False, False, False, False, True, True, False, False, False]

def test_eq32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_mips') == [False, False, True, False, True, False, False, True, True, True, True, True, False, False, True, True, False, True, False, True, True, True, True, True, True, False, True, True, False, True, False, False, False, False, False, True, False, False, True, True, False, False, False, False, False, True, True, False, False, False]

def test_ne32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_arm') == [True, True, True, False, True, True, True, False, False, False, False, False, True, True, True, True, False, False, False, False, False, True, False, True, False, True, False, False, True, True, True, False, True, False, False, True, False, False, True, False, False, True, False, False, False, False, False, False, True, False]

def test_ne32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_mips') == [True, True, True, False, True, True, True, False, False, False, False, False, True, True, True, True, False, False, False, False, False, True, False, True, False, True, False, False, True, True, True, False, True, False, False, True, False, False, True, False, False, True, False, False, False, False, False, False, True, False]

def test_le32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_arm') == [True, False, True, True, False, False, False, True, False, False, True, False, False, False, True, False, False, True, False, False, False, True, False, True, True, False, False, False, False, False, False, False, True, False, False, False, False, True, True, False, False, False, False, False, False, True, False, True, False, True]

def test_le32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_mips') == [True, False, True, True, False, False, False, True, False, False, True, False, False, False, True, False, False, True, False, False, False, True, False, True, True, False, False, False, False, False, False, False, True, False, False, False, False, True, True, False, False, False, False, False, False, True, False, True, False, True]

def test_lt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_arm') == [False, False, False, True, False, True, False, True, False, False, False, False, True, True, True, True, False, True, True, False, True, False, False, True, True, True, False, True, True, True, False, False, False, True, False, False, True, False, True, True, True, True, False, False, True, False, False, True, False, False]

def test_lt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_mips') == [False, False, False, True, False, True, False, True, False, False, False, False, True, True, True, True, False, True, True, False, True, False, False, True, True, True, False, True, True, True, False, False, False, True, False, False, True, False, True, True, True, True, False, False, True, False, False, True, False, False]

def test_ge32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_arm') == [False, False, True, True, True, False, True, False, False, False, True, False, False, False, False, True, False, True, True, False, True, True, True, False, False, False, True, False, True, True, False, True, False, True, True, False, True, True, True, False, True, False, True, True, False, False, False, True, False, False]

def test_ge32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_mips') == [False, False, True, True, True, False, True, False, False, False, True, False, False, False, False, True, False, True, True, False, True, True, True, False, False, False, True, False, True, True, False, True, False, True, True, False, True, True, True, False, True, False, True, True, False, False, False, True, False, False]

def test_gt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_arm') == [False, False, True, True, True, False, False, True, True, False, True, True, True, False, False, True, True, False, False, True, False, False, True, False, False, False, False, False, False, True, True, False, True, False, False, True, True, True, True, False, False, False, False, False, False, True, True, False, True, True]

def test_gt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_mips') == [False, False, True, True, True, False, False, True, True, False, True, True, True, False, False, True, True, False, False, True, False, False, True, False, False, False, False, False, False, True, True, False, True, False, False, True, True, True, True, False, False, False, False, False, False, True, True, False, True, True]
