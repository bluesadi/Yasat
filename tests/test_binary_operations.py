from .common import run_backward_slicing_on_binary

def test_add32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_arm') == [2600269193, 2074581053, 875902516, 312140956, 926434194, 890810464, 3834315368, 2928288199, 2609153863, 7986852, 3763481218, 1417996297, 397904863, 3048452927, 3963501647, 2610914063, 2593688921, 3022596080, 2332498507, 2353448261, 1394670990, 2948441162, 3284284732, 440014771, 225201727, 2245981316, 1218101097, 2525867054, 108489664, 1161460044, 1413047433, 669673583, 2389250105, 848749615, 2829148707, 2521705533, 2875947659, 518715900, 2611303001, 1941973020, 2155926430, 2301091085, 955739172, 2266283263, 367057089, 2818375153, 872394631, 3806633539, 1726516286, 2699905333]

def test_add32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_mips') == [2600269193, 2074581053, 875902516, 312140956, 926434194, 890810464, 3834315368, 2928288199, 2609153863, 7986852, 3763481218, 1417996297, 397904863, 3048452927, 3963501647, 2610914063, 2593688921, 3022596080, 2332498507, 2353448261, 1394670990, 2948441162, 3284284732, 440014771, 225201727, 2245981316, 1218101097, 2525867054, 108489664, 1161460044, 1413047433, 669673583, 2389250105, 848749615, 2829148707, 2521705533, 2875947659, 518715900, 2611303001, 1941973020, 2155926430, 2301091085, 955739172, 2266283263, 367057089, 2818375153, 872394631, 3806633539, 1726516286, 2699905333]

def test_sub32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_arm') == [3216494959, 3002681865, 3212995903, 4176863926, 2376001082, 2722974427, 1244946651, 3128997494, 2058831528, 312343802, 400437555, 148309632, 351708006, 60922731, 3766157674, 994211471, 2762103068, 1128237815, 2276359382, 3646223368, 474589959, 261182153, 3373425957, 3375124859, 2664413373, 612884366, 3063970387, 3313017222, 1172320484, 3850597634, 4142981944, 4051379799, 2723694169, 3545428987, 1477263573, 2958180963, 348538722, 2153255786, 2010460104, 3972084973, 742205157, 2323468193, 1977295997, 2987895119, 181280107, 1599586134, 1228866762, 3189856828, 4058960152, 2079829613]

def test_sub32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_mips') == [3216494959, 3002681865, 3212995903, 4176863926, 2376001082, 2722974427, 1244946651, 3128997494, 2058831528, 312343802, 400437555, 148309632, 351708006, 60922731, 3766157674, 994211471, 2762103068, 1128237815, 2276359382, 3646223368, 474589959, 261182153, 3373425957, 3375124859, 2664413373, 612884366, 3063970387, 3313017222, 1172320484, 3850597634, 4142981944, 4051379799, 2723694169, 3545428987, 1477263573, 2958180963, 348538722, 2153255786, 2010460104, 3972084973, 742205157, 2323468193, 1977295997, 2987895119, 181280107, 1599586134, 1228866762, 3189856828, 4058960152, 2079829613]

def test_mul32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_arm') == [162925641, 2211190296, 3891587386, 601542904, 3407422429, 2658121822, 181973610, 3196173982, 1075861047, 426872550, 2021190368, 1693672929, 2280752108, 994322628, 2806505580, 1053307264, 3888624980, 4193874208, 2607931559, 4218143072, 1402522960, 3274709832, 1737815098, 2468263482, 1784263658, 1837029314, 3036049984, 2736775936, 3481750358, 381412988, 1208640255, 3865202578, 2494312448, 1289394352, 578189346, 2064785236, 2386459572, 3544465160, 1896137599, 1802597795, 4030696510, 2012952035, 3320343744, 2390696138, 1668135996, 3001150208, 1632891936, 1680918970, 2769894040, 1352079402]

def test_mul32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_mips') == [162925641, 2211190296, 3891587386, 601542904, 3407422429, 2658121822, 181973610, 3196173982, 1075861047, 426872550, 2021190368, 1693672929, 2280752108, 994322628, 2806505580, 1053307264, 3888624980, 4193874208, 2607931559, 4218143072, 1402522960, 3274709832, 1737815098, 2468263482, 1784263658, 1837029314, 3036049984, 2736775936, 3481750358, 381412988, 1208640255, 3865202578, 2494312448, 1289394352, 578189346, 2064785236, 2386459572, 3544465160, 1896137599, 1802597795, 4030696510, 2012952035, 3320343744, 2390696138, 1668135996, 3001150208, 1632891936, 1680918970, 2769894040, 1352079402]

def test_shr32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_arm') == [247, 34896558, 158734, 30, 4, 408683060, 13076, 23321794, 10, 801329, 345268568, 1, 65, 1888, 916400, 5609, 7940, 206512, 906, 332319374, 17, 3385878210, 1, 181258572, 1, 17, 8641, 17338750, 11777, 1284, 4, 821, 13, 1616509, 342, 2, 3, 412369319, 311507, 2726, 5, 5, 36871, 10, 215943937, 0, 125, 1407, 210845157, 5]

def test_shr32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_mips') == [247, 34896558, 158734, 30, 4, 408683060, 13076, 23321794, 10, 801329, 345268568, 1, 65, 1888, 916400, 5609, 7940, 206512, 906, 332319374, 17, 3385878210, 1, 181258572, 1, 17, 8641, 17338750, 11777, 1284, 4, 821, 13, 1616509, 342, 2, 3, 412369319, 311507, 2726, 5, 5, 36871, 10, 215943937, 0, 125, 1407, 210845157, 5]

def test_sar32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_arm') == [4283894006, 1, 3, 1638, 48438, 4294967294, 1, 4294967288, 3, 4294967055, 4294967286, 4294967295, 4260462604, 4294965660, 4293249460, 4294967288, 4294967291, 4292761603, 640492218, 2, 4294785406, 6785, 4294967289, 4294965755, 4294964764, 8343626, 4294956260, 4294967269, 1295, 4294734044, 4294961381, 4294826924, 4239197544, 4294966915, 4286914562, 4294945760, 4293205246, 26829204, 11234579, 4294964505, 2, 4105514002, 3054119, 998727, 4294967281, 457, 4242450692, 0, 4291378420, 4294967285]

def test_sar32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_mips') == [4283894006, 1, 3, 1638, 48438, 4294967294, 1, 4294967288, 3, 4294967055, 4294967286, 4294967295, 4260462604, 4294965660, 4293249460, 4294967288, 4294967291, 4292761603, 640492218, 2, 4294785406, 6785, 4294967289, 4294965755, 4294964764, 8343626, 4294956260, 4294967269, 1295, 4294734044, 4294961381, 4294826924, 4239197544, 4294966915, 4286914562, 4294945760, 4293205246, 26829204, 11234579, 4294964505, 2, 4105514002, 3054119, 998727, 4294967281, 457, 4242450692, 0, 4291378420, 4294967285]

def test_shl32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_arm') == [116487680, 0, 1207959552, 761485824, 2425210302, 812108688, 2852126720, 843259392, 1623807792, 598317568, 1741117893, 4026531840, 2784426752, 3758096384, 2165051392, 774537216, 1705246720, 2080374784, 2706706432, 3623878656, 3154116608, 4244635648, 3023044608, 0, 2147483648, 2683134208, 234881024, 1920851776, 1073741824, 3577741312, 1037092228, 1899153024, 3169845248, 2147483648, 3959422976, 117964800, 358584320, 66453504, 3271557120, 1341652992, 1029183744, 917766144, 3521482816, 345596928, 3019898880, 2969567232, 1610612736, 2751463424, 2181038080, 590573568]

def test_shl32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_mips') == [116487680, 0, 1207959552, 761485824, 2425210302, 812108688, 2852126720, 843259392, 1623807792, 598317568, 1741117893, 4026531840, 2784426752, 3758096384, 2165051392, 774537216, 1705246720, 2080374784, 2706706432, 3623878656, 3154116608, 4244635648, 3023044608, 0, 2147483648, 2683134208, 234881024, 1920851776, 1073741824, 3577741312, 1037092228, 1899153024, 3169845248, 2147483648, 3959422976, 117964800, 358584320, 66453504, 3271557120, 1341652992, 1029183744, 917766144, 3521482816, 345596928, 3019898880, 2969567232, 1610612736, 2751463424, 2181038080, 590573568]

def test_and32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_arm') == [415499464, 537268816, 69468360, 71696964, 738199680, 809504184, 1107836970, 35834512, 3292860443, 2290614627, 335569120, 6292655, 2808184841, 607142416, 2707687424, 163847173, 533235984, 85991683, 962690, 2337865888, 2436896784, 2402304000, 3818450496, 679739926, 271061344, 593698856, 278921248, 1105264898, 698528, 136972288, 21005864, 221380609, 2961189200, 289767552, 3285728, 1245710080, 2348810393, 2818646544, 2147492737, 3223033864, 1116275200, 1250182404, 675025027, 6063105, 2277563, 691175953, 282232386, 941678592, 3768617450, 1744961536]

def test_and32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_mips') == [415499464, 537268816, 69468360, 71696964, 738199680, 809504184, 1107836970, 35834512, 3292860443, 2290614627, 335569120, 6292655, 2808184841, 607142416, 2707687424, 163847173, 533235984, 85991683, 962690, 2337865888, 2436896784, 2402304000, 3818450496, 679739926, 271061344, 593698856, 278921248, 1105264898, 698528, 136972288, 21005864, 221380609, 2961189200, 289767552, 3285728, 1245710080, 2348810393, 2818646544, 2147492737, 3223033864, 1116275200, 1250182404, 675025027, 6063105, 2277563, 691175953, 282232386, 941678592, 3768617450, 1744961536]

def test_or32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_arm') == [2683172151, 4222500735, 4244614135, 1801109439, 3657284606, 4261145565, 4253010467, 3405117399, 4293917671, 4236225784, 4193648127, 4258902847, 4294367929, 4239251379, 2879888735, 3216957183, 2042476119, 4278157277, 2079121405, 1073711611, 1861345182, 4007653102, 4152356715, 3990064951, 2144337023, 671077371, 4043307903, 402620381, 2411069433, 3741285629, 4093639679, 3757047795, 2112825039, 938389503, 4160347902, 4294213627, 2012740095, 4294891197, 2143119359, 4292797390, 4219254718, 4155365618, 945679359, 4159700659, 527038462, 3757002143, 3485447163, 4294702566, 4227398495, 2025846631]

def test_or32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_mips') == [2683172151, 4222500735, 4244614135, 1801109439, 3657284606, 4261145565, 4253010467, 3405117399, 4293917671, 4236225784, 4193648127, 4258902847, 4294367929, 4239251379, 2879888735, 3216957183, 2042476119, 4278157277, 2079121405, 1073711611, 1861345182, 4007653102, 4152356715, 3990064951, 2144337023, 671077371, 4043307903, 402620381, 2411069433, 3741285629, 4093639679, 3757047795, 2112825039, 938389503, 4160347902, 4294213627, 2012740095, 4294891197, 2143119359, 4292797390, 4219254718, 4155365618, 945679359, 4159700659, 527038462, 3757002143, 3485447163, 4294702566, 4227398495, 2025846631]

def test_xor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_arm') == [1103852072, 3661550435, 750354373, 3895956811, 2691662333, 768269485, 736499673, 339932643, 1747552013, 3355043833, 2625413216, 760456569, 1894810701, 3228279042, 3164693287, 2117515445, 2885087885, 4243808836, 867036153, 1755072566, 3983181066, 1934039803, 3908026011, 3945515092, 2145770635, 2140531326, 31878390, 2053562541, 1024246583, 360191503, 1028858526, 1790933318, 3896345298, 3967631848, 1210071469, 1382738602, 1485856654, 2365481911, 708334522, 1932352244, 1479312425, 2011447673, 1360917167, 4125291710, 101442708, 4039303928, 921171715, 3393861376, 565760903, 2246705761]

def test_xor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_mips') == [1103852072, 3661550435, 750354373, 3895956811, 2691662333, 768269485, 736499673, 339932643, 1747552013, 3355043833, 2625413216, 760456569, 1894810701, 3228279042, 3164693287, 2117515445, 2885087885, 4243808836, 867036153, 1755072566, 3983181066, 1934039803, 3908026011, 3945515092, 2145770635, 2140531326, 31878390, 2053562541, 1024246583, 360191503, 1028858526, 1790933318, 3896345298, 3967631848, 1210071469, 1382738602, 1485856654, 2365481911, 708334522, 1932352244, 1479312425, 2011447673, 1360917167, 4125291710, 101442708, 4039303928, 921171715, 3393861376, 565760903, 2246705761]

def test_land32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_arm') == [False, False, True, True, False, False, False, True, False, False, False, True, False, True, False, True, True, False, True, True, False, False, False, False, False, False, True, True, False, False, True, False, True, True, False, False, True, True, False, False, True, True, False, True, False, False, False, True, True, False]

def test_land32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_mips') == [False, False, True, True, False, False, False, True, False, False, False, True, False, True, False, True, True, False, True, True, False, False, False, False, False, False, True, True, False, False, True, False, True, True, False, False, True, True, False, False, True, True, False, True, False, False, False, True, True, False]

def test_lor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_arm') == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_lor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_mips') == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_eq32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_arm') == [True, False, False, True, False, True, True, False, True, False, False, True, False, False, False, False, False, True, True, True, True, False, False, True, True, False, False, False, True, True, False, False, True, True, False, True, False, False, False, False, True, True, False, False, False, False, False, False, False, False]

def test_eq32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_mips') == [True, False, False, True, False, True, True, False, True, False, False, True, False, False, False, False, False, True, True, True, True, False, False, True, True, False, False, False, True, True, False, False, True, True, False, True, False, False, False, False, True, True, False, False, False, False, False, False, False, False]

def test_ne32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_arm') == [True, True, True, False, True, True, True, True, False, False, True, True, True, False, True, True, True, False, False, True, False, True, True, True, True, False, True, True, True, False, True, False, False, False, False, False, True, True, False, False, False, True, False, True, True, False, False, True, True, True]

def test_ne32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_mips') == [True, True, True, False, True, True, True, True, False, False, True, True, True, False, True, True, True, False, False, True, False, True, True, True, True, False, True, True, True, False, True, False, False, False, False, False, True, True, False, False, False, True, False, True, True, False, False, True, True, True]

def test_le32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_arm') == [True, True, True, False, False, False, False, True, False, False, False, False, False, False, False, True, False, True, True, False, False, False, True, True, False, True, True, False, True, True, True, True, True, False, True, False, True, True, False, True, False, False, True, True, False, False, False, False, True, False]

def test_le32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_mips') == [True, True, True, False, False, False, False, True, False, False, False, False, False, False, False, True, False, True, True, False, False, False, True, True, False, True, True, False, True, True, True, True, True, False, True, False, True, True, False, True, False, False, True, True, False, False, False, False, True, False]

def test_lt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_arm') == [True, False, False, False, False, True, True, True, True, True, False, False, True, False, False, True, False, False, False, False, True, False, False, True, True, False, False, True, False, True, False, False, False, True, True, False, False, False, False, True, False, True, False, True, False, True, True, False, True, False]

def test_lt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_mips') == [True, False, False, False, False, True, True, True, True, True, False, False, True, False, False, True, False, False, False, False, True, False, False, True, True, False, False, True, False, True, False, False, False, True, True, False, False, False, False, True, False, True, False, True, False, True, True, False, True, False]

def test_ge32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_arm') == [True, False, True, False, False, True, False, False, True, True, False, False, False, True, True, False, True, False, False, False, True, False, False, False, False, True, False, True, False, False, False, False, False, True, True, True, False, True, True, False, True, True, True, True, False, False, True, False, False, False]

def test_ge32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_mips') == [True, False, True, False, False, True, False, False, True, True, False, False, False, True, True, False, True, False, False, False, True, False, False, False, False, True, False, True, False, False, False, False, False, True, True, True, False, True, True, False, True, True, True, True, False, False, True, False, False, False]

def test_gt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_arm') == [False, True, False, False, True, True, True, True, False, True, False, True, True, True, False, True, True, True, True, False, True, False, True, False, True, True, False, False, False, True, False, True, True, False, True, False, False, True, False, True, False, True, True, True, True, False, True, True, False, False]

def test_gt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_mips') == [False, True, False, False, True, True, True, True, False, True, False, True, True, True, False, True, True, True, True, False, True, False, True, False, True, True, False, False, False, True, False, True, True, False, True, False, False, True, False, True, False, True, True, True, True, False, True, True, False, False]

