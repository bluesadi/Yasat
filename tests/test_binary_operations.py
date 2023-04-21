from .common import run_backward_slicing_on_binary

def test_add32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_arm', 'sink', 0, cast_to=int) == [3279582820, 2940104623, 4291154098, 634330645, 3023345372, 994042299, 152084248, 4088630426, 3522050207, 2152747884, 3700635520, 3331630205, 2829857913, 512542653, 798378454, 3279426402, 571389819, 2546769656, 1393187273, 3226586014, 2625228031, 2448313098, 4292245303, 4256388741, 585451547]

def test_add32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_mips', 'sink', 0, cast_to=int) == [3279582820, 2940104623, 4291154098, 634330645, 3023345372, 994042299, 152084248, 4088630426, 3522050207, 2152747884, 3700635520, 3331630205, 2829857913, 512542653, 798378454, 3279426402, 571389819, 2546769656, 1393187273, 3226586014, 2625228031, 2448313098, 4292245303, 4256388741, 585451547]

def test_sub32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_arm', 'sink', 0, cast_to=int) == [748790321, 680079923, 219354576, 2536208071, 559449170, 2074246994, 1051560790, 3993038294, 4236810540, 1454196555, 3360878228, 4178606570, 284440564, 842594246, 976104377, 3374904086, 143082669, 2002470324, 1250916426, 3338797397, 1383206460, 1495717063, 2772726457, 4148761390, 740970816]

def test_sub32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_mips', 'sink', 0, cast_to=int) == [748790321, 680079923, 219354576, 2536208071, 559449170, 2074246994, 1051560790, 3993038294, 4236810540, 1454196555, 3360878228, 4178606570, 284440564, 842594246, 976104377, 3374904086, 143082669, 2002470324, 1250916426, 3338797397, 1383206460, 1495717063, 2772726457, 4148761390, 740970816]

def test_mul32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_arm', 'sink', 0, cast_to=int) == [1574671031, 1873877645, 4245925274, 1067587242, 3993192082, 2503164557, 3790333975, 1485743896, 898488372, 4022457808, 402918578, 870131440, 2658693830, 4246810652, 3082560041, 804403424, 81547444, 3384785121, 138380267, 1281459032, 1815136470, 3147262120, 3187301439, 2616845900, 327497615]

def test_mul32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_mips', 'sink', 0, cast_to=int) == [1574671031, 1873877645, 4245925274, 1067587242, 3993192082, 2503164557, 3790333975, 1485743896, 898488372, 4022457808, 402918578, 870131440, 2658693830, 4246810652, 3082560041, 804403424, 81547444, 3384785121, 138380267, 1281459032, 1815136470, 3147262120, 3187301439, 2616845900, 327497615]

def test_shr32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_arm', 'sink', 0, cast_to=int) == [689, 225166, 129, 546360185, 1580, 100, 2901, 933337, 51, 76195587, 15973, 8931, 1063, 32855979, 1, 1744, 24862, 8303893, 295061, 199329186, 4345123, 445224438, 1, 26534, 4]

def test_shr32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_mips', 'sink', 0, cast_to=int) == [689, 225166, 129, 546360185, 1580, 100, 2901, 933337, 51, 76195587, 15973, 8931, 1063, 32855979, 1, 1744, 24862, 8303893, 295061, 199329186, 4345123, 445224438, 1, 26534, 4]

def test_sar32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_arm', 'sink', 0, cast_to=int) == [4459, 86376, 34041, 4199364021, 4294967295, 4294967289, 211, 4294967292, 3883307158, 4294967285, 4294967292, 7460, 133880393, 4294959244, 4, 4124104191, 4267299622, 4294967264, 4294762256, 7744746, 953983, 4294966623, 7, 27, 192060]

def test_sar32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_mips', 'sink', 0, cast_to=int) == [4459, 86376, 34041, 4199364021, 4294967295, 4294967289, 211, 4294967292, 3883307158, 4294967285, 4294967292, 7460, 133880393, 4294959244, 4, 4124104191, 4267299622, 4294967264, 4294762256, 7744746, 953983, 4294966623, 7, 27, 192060]

def test_shl32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_arm', 'sink', 0, cast_to=int) == [274092032, 2840950976, 2952790016, 2109014016, 2317811712, 0, 3860201472, 3273441280, 2842726656, 3277053952, 2533359616, 1687332480, 2380464128, 2180448256, 3942609306, 805306368, 3019898880, 2675707904, 3809280000, 1879048192, 1225523200, 3901037696, 647672832, 3623878656, 1440709888]

def test_shl32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_mips', 'sink', 0, cast_to=int) == [274092032, 2840950976, 2952790016, 2109014016, 2317811712, 0, 3860201472, 3273441280, 2842726656, 3277053952, 2533359616, 1687332480, 2380464128, 2180448256, 3942609306, 805306368, 3019898880, 2675707904, 3809280000, 1879048192, 1225523200, 3901037696, 647672832, 3623878656, 1440709888]

def test_and32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_arm', 'sink', 0, cast_to=int) == [134218761, 830637666, 771757312, 174196999, 275038720, 565207688, 536891908, 304121394, 528402, 672924171, 654347778, 1095013664, 134217793, 138417186, 101905828, 3826264068, 3255394440, 303096392, 267264, 1621203968, 153123320, 891316932, 1613779528, 2853175552, 2819682930]

def test_and32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_mips', 'sink', 0, cast_to=int) == [134218761, 830637666, 771757312, 174196999, 275038720, 565207688, 536891908, 304121394, 528402, 672924171, 654347778, 1095013664, 134217793, 138417186, 101905828, 3826264068, 3255394440, 303096392, 267264, 1621203968, 153123320, 891316932, 1613779528, 2853175552, 2819682930]

def test_or32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_arm', 'sink', 0, cast_to=int) == [3354393310, 4278160102, 4294279127, 4278188029, 3219636926, 1833526207, 4160617471, 2574511007, 4265601013, 2862599407, 3321738739, 2060307446, 4276917979, 4261391998, 4177473534, 3689641407, 3724237686, 4294655933, 1827657263, 4125089759, 4292665190, 4013773291, 2407256027, 4158124027, 2109554556]

def test_or32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_mips', 'sink', 0, cast_to=int) == [3354393310, 4278160102, 4294279127, 4278188029, 3219636926, 1833526207, 4160617471, 2574511007, 4265601013, 2862599407, 3321738739, 2060307446, 4276917979, 4261391998, 4177473534, 3689641407, 3724237686, 4294655933, 1827657263, 4125089759, 4292665190, 4013773291, 2407256027, 4158124027, 2109554556]

def test_xor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_arm', 'sink', 0, cast_to=int) == [3830256785, 2394715883, 3729603782, 4032708440, 4091868414, 507040038, 2896973196, 379077573, 812726076, 2876952247, 1364118208, 234373607, 350916215, 2618339737, 1177571300, 1818399334, 2543423316, 3181909180, 2148697331, 2947693211, 1206572690, 1929007382, 630864301, 906376214, 2914058910]

def test_xor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_mips', 'sink', 0, cast_to=int) == [3830256785, 2394715883, 3729603782, 4032708440, 4091868414, 507040038, 2896973196, 379077573, 812726076, 2876952247, 1364118208, 234373607, 350916215, 2618339737, 1177571300, 1818399334, 2543423316, 3181909180, 2148697331, 2947693211, 1206572690, 1929007382, 630864301, 906376214, 2914058910]

def test_land32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_arm', 'sink', 0, cast_to=bool) == [True, True, True, True, False, False, False, False, True, True, False, True, True, True, False, False, False, False, False, True, True, False, True, False, True]

def test_land32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_mips', 'sink', 0, cast_to=bool) == [True, True, True, True, False, False, False, False, True, True, False, True, True, True, False, False, False, False, False, True, True, False, True, False, True]

def test_lor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_arm', 'sink', 0, cast_to=bool) == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_lor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_mips', 'sink', 0, cast_to=bool) == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_eq32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_arm', 'sink', 0, cast_to=bool) == [True, True, False, False, False, False, False, True, True, False, False, True, False, False, True, False, False, True, False, False, False, True, False, False, True]

def test_eq32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_mips', 'sink', 0, cast_to=bool) == [True, True, False, False, False, False, False, True, True, False, False, True, False, False, True, False, False, True, False, False, False, True, False, False, True]

def test_ne32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_arm', 'sink', 0, cast_to=bool) == [False, True, False, True, False, False, False, False, False, True, True, True, False, True, True, False, False, True, True, True, True, True, False, False, True]

def test_ne32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_mips', 'sink', 0, cast_to=bool) == [False, True, False, True, False, False, False, False, False, True, True, True, False, True, True, False, False, True, True, True, True, True, False, False, True]

def test_le32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_arm', 'sink', 0, cast_to=bool) == [False, True, True, True, True, True, True, False, False, False, True, True, False, False, False, True, True, True, True, True, True, True, True, True, False]

def test_le32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_mips', 'sink', 0, cast_to=bool) == [False, True, True, True, True, True, True, False, False, False, True, True, False, False, False, True, True, True, True, True, True, True, True, True, False]

def test_lt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_arm', 'sink', 0, cast_to=bool) == [True, False, False, True, True, True, True, True, True, False, True, True, True, True, True, False, False, False, True, True, False, False, True, True, True]

def test_lt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_mips', 'sink', 0, cast_to=bool) == [True, False, False, True, True, True, True, True, True, False, True, True, True, True, True, False, False, False, True, True, False, False, True, True, True]

def test_ge32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_arm', 'sink', 0, cast_to=bool) == [True, True, True, True, False, True, False, False, False, False, False, True, False, False, True, True, False, False, True, True, True, True, False, True, True]

def test_ge32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_mips', 'sink', 0, cast_to=bool) == [True, True, True, True, False, True, False, False, False, False, False, True, False, False, True, True, False, False, True, True, True, True, False, True, True]

def test_gt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_arm', 'sink', 0, cast_to=bool) == [False, True, True, False, True, True, False, False, True, True, True, True, False, True, True, True, False, False, True, True, False, False, False, False, True]

def test_gt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_mips', 'sink', 0, cast_to=bool) == [False, True, True, False, True, True, False, False, True, True, True, True, False, True, True, True, False, False, True, True, False, False, False, False, True]

