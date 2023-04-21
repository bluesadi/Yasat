from .common import run_backward_slicing_on_binary

def test_add32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_arm', 'sink', 0) == [454230528, 4208292142, 1590461748, 2225194491, 3974133810, 1096875408, 4095740446, 3081881777, 625550632, 1673274346, 1568321644, 2341551924, 1953557184, 842025595, 1114581571, 161012424, 1423119153, 1460124317, 3952174444, 3380975137, 1463251710, 2615757717, 260690742, 3164108275, 3273947376]

def test_add32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_mips', 'sink', 0) == [454230528, 4208292142, 1590461748, 2225194491, 3974133810, 1096875408, 4095740446, 3081881777, 625550632, 1673274346, 1568321644, 2341551924, 1953557184, 842025595, 1114581571, 161012424, 1423119153, 1460124317, 3952174444, 3380975137, 1463251710, 2615757717, 260690742, 3164108275, 3273947376]

def test_sub32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_arm', 'sink', 0) == [577972322, 4263790894, 2738996205, 3910590940, 2566726866, 1438005336, 4028088762, 581433892, 4092574983, 2755745317, 5423778, 3403676654, 258588505, 1661024390, 3251040613, 3418887485, 1597680101, 4044453838, 2534878421, 3590417315, 514797763, 4247461039, 3026930387, 4207952966, 3238962688]

def test_sub32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_mips', 'sink', 0) == [577972322, 4263790894, 2738996205, 3910590940, 2566726866, 1438005336, 4028088762, 581433892, 4092574983, 2755745317, 5423778, 3403676654, 258588505, 1661024390, 3251040613, 3418887485, 1597680101, 4044453838, 2534878421, 3590417315, 514797763, 4247461039, 3026930387, 4207952966, 3238962688]

def test_mul32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_arm', 'sink', 0) == [75109604, 3771606370, 486978644, 4090731268, 3707283405, 4238201133, 2535121344, 4205599875, 2946183742, 610617152, 3161642528, 2554575429, 3791782391, 565279632, 3178350464, 794587088, 1054391576, 1391184464, 4108871804, 4266926615, 969671230, 4179369556, 4001601766, 3240813000, 1688633832]

def test_mul32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_mips', 'sink', 0) == [75109604, 3771606370, 486978644, 4090731268, 3707283405, 4238201133, 2535121344, 4205599875, 2946183742, 610617152, 3161642528, 2554575429, 3791782391, 565279632, 3178350464, 794587088, 1054391576, 1391184464, 4108871804, 4266926615, 969671230, 4179369556, 4001601766, 3240813000, 1688633832]

def test_shr32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_arm', 'sink', 0) == [266631638, 767, 69813, 982, 16, 1955, 457064, 129440, 80, 11768, 1, 12173, 473803435, 32294, 761996161, 8, 1319324005, 325287, 27, 489518333, 1006021945, 813514, 2174345, 553223, 9]

def test_shr32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_mips', 'sink', 0) == [266631638, 767, 69813, 982, 16, 1955, 457064, 129440, 80, 11768, 1, 12173, 473803435, 32294, 761996161, 8, 1319324005, 325287, 27, 489518333, 1006021945, 813514, 2174345, 553223, 9]

def test_sar32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_arm', 'sink', 0) == [4159, 9, 4136077085, 4294957295, 4294797561, 4294967198, 0, 4293040038, 4294957355, 4294963599, 3975, 29, 4294967196, 4294967294, 35864713, 223, 4294952555, 54293058, 6063, 37, 23, 880, 218731065, 4294728688, 4226990765]

def test_sar32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_mips', 'sink', 0) == [4159, 9, 4136077085, 4294957295, 4294797561, 4294967198, 0, 4293040038, 4294957355, 4294963599, 3975, 29, 4294967196, 4294967294, 35864713, 223, 4294952555, 54293058, 6063, 37, 23, 880, 218731065, 4294728688, 4226990765]

def test_shl32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_arm', 'sink', 0) == [358706286, 3687743488, 3288334336, 3444572160, 376700928, 1838995712, 989855744, 4250974336, 187439488, 1575051264, 3464416112, 2060871396, 2562719744, 1613463552, 4253024256, 2939352268, 3708289024, 1528238080, 2021346544, 204509184, 22306816, 1951295280, 1332609024, 0, 3487170656]

def test_shl32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_mips', 'sink', 0) == [358706286, 3687743488, 3288334336, 3444572160, 376700928, 1838995712, 989855744, 4250974336, 187439488, 1575051264, 3464416112, 2060871396, 2562719744, 1613463552, 4253024256, 2939352268, 3708289024, 1528238080, 2021346544, 204509184, 22306816, 1951295280, 1332609024, 0, 3487170656]

def test_and32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_arm', 'sink', 0) == [69239049, 276832769, 54053382, 282599764, 1548093976, 344076582, 6291476, 136398219, 3288342533, 153487400, 8679456, 188225600, 83888516, 1883252738, 86058001, 555903330, 1082689584, 13042176, 1109711108, 285933676, 503598592, 1074462722, 2283802698, 136396872, 36209796]

def test_and32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_mips', 'sink', 0) == [69239049, 276832769, 54053382, 282599764, 1548093976, 344076582, 6291476, 136398219, 3288342533, 153487400, 8679456, 188225600, 83888516, 1883252738, 86058001, 555903330, 1082689584, 13042176, 1109711108, 285933676, 503598592, 1074462722, 2283802698, 136396872, 36209796]

def test_or32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_arm', 'sink', 0) == [1331625918, 4084165626, 1915977583, 4277728639, 2818473827, 3347018743, 4294963195, 1744797181, 2958997490, 4227333595, 4023377855, 4273637832, 1820290815, 2809790430, 3991797439, 3758029759, 2667446239, 3988779994, 2145598751, 3689332605, 4026201015, 2951152379, 4294807549, 2104917375, 3086958184]

def test_or32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_mips', 'sink', 0) == [1331625918, 4084165626, 1915977583, 4277728639, 2818473827, 3347018743, 4294963195, 1744797181, 2958997490, 4227333595, 4023377855, 4273637832, 1820290815, 2809790430, 3991797439, 3758029759, 2667446239, 3988779994, 2145598751, 3689332605, 4026201015, 2951152379, 4294807549, 2104917375, 3086958184]

def test_xor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_arm', 'sink', 0) == [2565398870, 3582019153, 404156612, 3513439725, 1825503293, 628500728, 3874198109, 3603287464, 441513672, 4281347290, 2123968264, 2529581300, 1307804215, 3987726470, 2781168697, 444533846, 1949079528, 106329865, 1962510940, 1469118908, 365088471, 3096925882, 1798643590, 3367035760, 4185175493]

def test_xor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_mips', 'sink', 0) == [2565398870, 3582019153, 404156612, 3513439725, 1825503293, 628500728, 3874198109, 3603287464, 441513672, 4281347290, 2123968264, 2529581300, 1307804215, 3987726470, 2781168697, 444533846, 1949079528, 106329865, 1962510940, 1469118908, 365088471, 3096925882, 1798643590, 3367035760, 4185175493]

def test_land32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_arm', 'sink', 0) == [False, False, True, False, False, False, False, True, False, True, True, True, False, False, False, False, True, True, True, True, False, False, False, True, False]

def test_land32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_mips', 'sink', 0) == [False, False, True, False, False, False, False, True, False, True, True, True, False, False, False, False, True, True, True, True, False, False, False, True, False]

def test_lor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_arm', 'sink', 0) == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_lor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_mips', 'sink', 0) == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_eq32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_arm', 'sink', 0) == [True, False, True, True, True, False, True, True, True, False, False, True, True, True, True, True, True, True, True, True, True, False, True, True, False]

def test_eq32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_mips', 'sink', 0) == [True, False, True, True, True, False, True, True, True, False, False, True, True, True, True, True, True, True, True, True, True, False, True, True, False]

def test_ne32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_arm', 'sink', 0) == [True, True, False, True, True, True, True, True, True, True, False, False, True, False, False, False, True, False, False, False, False, False, False, True, True]

def test_ne32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_mips', 'sink', 0) == [True, True, False, True, True, True, True, True, True, True, False, False, True, False, False, False, True, False, False, False, False, False, False, True, True]

def test_le32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_arm', 'sink', 0) == [True, True, False, True, True, False, False, False, True, False, False, True, False, True, True, True, False, True, True, False, True, True, True, False, False]

def test_le32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_mips', 'sink', 0) == [True, True, False, True, True, False, False, False, True, False, False, True, False, True, True, True, False, True, True, False, True, True, True, False, False]

def test_lt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_arm', 'sink', 0) == [True, True, False, False, False, True, False, True, False, False, True, False, False, False, True, False, False, True, False, False, False, False, True, False, True]

def test_lt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_mips', 'sink', 0) == [True, True, False, False, False, True, False, True, False, False, True, False, False, False, True, False, False, True, False, False, False, False, True, False, True]

def test_ge32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_arm', 'sink', 0) == [False, True, True, False, True, False, True, True, True, True, False, False, True, False, True, False, False, True, False, True, True, True, True, False, True]

def test_ge32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_mips', 'sink', 0) == [False, True, True, False, True, False, True, True, True, True, False, False, True, False, True, False, False, True, False, True, True, True, True, False, True]

def test_gt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_arm', 'sink', 0) == [False, False, False, False, True, True, True, True, False, False, False, True, False, False, False, True, True, True, True, False, False, False, False, False, False]

def test_gt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_mips', 'sink', 0) == [False, False, False, False, True, True, True, True, False, False, False, True, False, False, False, True, True, True, True, False, False, False, False, False, False]

