from .common import run_backward_slicing_on_binary

def test_add32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_arm', 'sink', 0) == [1426295990, 4192394442, 1265406873, 1669584559, 183060474, 3976023696, 1076609584, 3768344986, 3823089132, 725219093, 2075990433, 1233741396, 4010975656, 1292526310, 2246180179, 1090676496, 2115942539, 1445346946, 3666938208, 991925351, 3329148177, 3978843085, 3985255335, 2178135006, 659452406, 150396053, 2936736030, 484070171, 2204935809, 671753562, 149954542, 536531873, 3228602559, 1037457275, 3520167637, 2878960021, 80659072, 1654312812, 3007888590, 3966581929, 2122516392, 729323701, 795453652, 2172670761, 668305416, 420515158, 3297602941, 4271821235, 1833769953, 3530728670]

def test_add32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/add32_mips', 'sink', 0) == [1426295990, 4192394442, 1265406873, 1669584559, 183060474, 3976023696, 1076609584, 3768344986, 3823089132, 725219093, 2075990433, 1233741396, 4010975656, 1292526310, 2246180179, 1090676496, 2115942539, 1445346946, 3666938208, 991925351, 3329148177, 3978843085, 3985255335, 2178135006, 659452406, 150396053, 2936736030, 484070171, 2204935809, 671753562, 149954542, 536531873, 3228602559, 1037457275, 3520167637, 2878960021, 80659072, 1654312812, 3007888590, 3966581929, 2122516392, 729323701, 795453652, 2172670761, 668305416, 420515158, 3297602941, 4271821235, 1833769953, 3530728670]

def test_sub32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_arm', 'sink', 0) == [1961961723, 4075260226, 909861250, 1219317861, 640915372, 238119107, 4163857169, 1911925249, 371469008, 3632773353, 135102256, 2488379355, 1285223255, 852640283, 3640543546, 2823360258, 3348678181, 1671630753, 3895960011, 1171350746, 664999747, 1258053952, 1564169862, 1779085344, 8546092, 3975006113, 3851114874, 2876333801, 590078928, 3572716902, 2166538297, 427940950, 741684845, 880868255, 4162343170, 62564028, 2199767645, 1647835898, 3510493207, 705197117, 2747416676, 3185948953, 527613196, 3879824847, 2592161683, 3175128366, 436752696, 3211712990, 496167809, 2903927230]

def test_sub32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sub32_mips', 'sink', 0) == [1961961723, 4075260226, 909861250, 1219317861, 640915372, 238119107, 4163857169, 1911925249, 371469008, 3632773353, 135102256, 2488379355, 1285223255, 852640283, 3640543546, 2823360258, 3348678181, 1671630753, 3895960011, 1171350746, 664999747, 1258053952, 1564169862, 1779085344, 8546092, 3975006113, 3851114874, 2876333801, 590078928, 3572716902, 2166538297, 427940950, 741684845, 880868255, 4162343170, 62564028, 2199767645, 1647835898, 3510493207, 705197117, 2747416676, 3185948953, 527613196, 3879824847, 2592161683, 3175128366, 436752696, 3211712990, 496167809, 2903927230]

def test_mul32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_arm', 'sink', 0) == [2672909408, 2406804152, 888886790, 1290632788, 2774674672, 1765362447, 307121942, 4225208048, 2288328530, 3123746879, 2652312919, 4020436608, 3902123736, 3061177916, 1608366450, 2508763145, 1534674956, 2787361904, 3110835340, 279501107, 2411006616, 3858275660, 280605968, 2121261830, 3747340900, 3227052481, 1018919297, 1170555305, 392582705, 54861191, 1869451184, 4214696112, 2496762652, 1112629568, 2601967412, 2483169270, 1804151141, 1033374701, 390959721, 1895477112, 481665144, 1144895604, 2226377502, 3736218966, 2889282232, 710011776, 4280699149, 2657672444, 464629466, 984296365]

def test_mul32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/mul32_mips', 'sink', 0) == [2672909408, 2406804152, 888886790, 1290632788, 2774674672, 1765362447, 307121942, 4225208048, 2288328530, 3123746879, 2652312919, 4020436608, 3902123736, 3061177916, 1608366450, 2508763145, 1534674956, 2787361904, 3110835340, 279501107, 2411006616, 3858275660, 280605968, 2121261830, 3747340900, 3227052481, 1018919297, 1170555305, 392582705, 54861191, 1869451184, 4214696112, 2496762652, 1112629568, 2601967412, 2483169270, 1804151141, 1033374701, 390959721, 1895477112, 481665144, 1144895604, 2226377502, 3736218966, 2889282232, 710011776, 4280699149, 2657672444, 464629466, 984296365]

def test_shr32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_arm', 'sink', 0) == [545, 10693959, 3, 442, 279, 13058988, 131846, 270452085, 41, 17498426, 85, 1, 100642594, 88096, 64568, 2605209, 1, 111, 89246006, 2655, 864, 1557240494, 3411, 1, 2, 75126, 261816, 54568298, 62493, 6025393, 156868, 32105, 8, 19921, 89930569, 1693960161, 34065, 4, 14, 228054282, 311829639, 2016, 2260437267, 3917436, 23220, 3853, 1989152169, 1728, 417, 499099659]

def test_shr32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shr32_mips', 'sink', 0) == [545, 10693959, 3, 442, 279, 13058988, 131846, 270452085, 41, 17498426, 85, 1, 100642594, 88096, 64568, 2605209, 1, 111, 89246006, 2655, 864, 1557240494, 3411, 1, 2, 75126, 261816, 54568298, 62493, 6025393, 156868, 32105, 8, 19921, 89930569, 1693960161, 34065, 4, 14, 228054282, 311829639, 2016, 2260437267, 3917436, 23220, 3853, 1989152169, 1728, 417, 499099659]

def test_sar32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_arm', 'sink', 0) == [441, 4294967292, 9, 4288647196, 4294967287, 9, 4294967285, 909084986, 4294967255, 4294967295, 4294967173, 372877886, 4066961514, 2977, 45932, 8836925, 5782457, 54, 25281, 6615058, 43, 27028, 4294213296, 4294967295, 3, 117379349, 2249, 24067, 4, 56711929, 30658313, 3757620646, 6052105, 685212, 4292641884, 74, 7452, 0, 4257807650, 9123, 37307, 46617, 558007080, 48, 30604604, 4294967295, 9, 4293182182, 4294967291, 4294967062]

def test_sar32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/sar32_mips', 'sink', 0) == [441, 4294967292, 9, 4288647196, 4294967287, 9, 4294967285, 909084986, 4294967255, 4294967295, 4294967173, 372877886, 4066961514, 2977, 45932, 8836925, 5782457, 54, 25281, 6615058, 43, 27028, 4294213296, 4294967295, 3, 117379349, 2249, 24067, 4, 56711929, 30658313, 3757620646, 6052105, 685212, 4292641884, 74, 7452, 0, 4257807650, 9123, 37307, 46617, 558007080, 48, 30604604, 4294967295, 9, 4293182182, 4294967291, 4294967062]

def test_shl32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_arm', 'sink', 0) == [2684354560, 2165713892, 4264001536, 3221225472, 3710264864, 1543503872, 3297734656, 2332033024, 0, 2885681152, 2453806592, 1455177728, 868830656, 1105190724, 4232052736, 3155972976, 1828716544, 2504818176, 1073741824, 2717908992, 1643118592, 2724200448, 2372280064, 3891134464, 1259947160, 2989211648, 1275068416, 356515840, 3311403008, 1193443328, 3409969152, 1342177280, 2147483648, 2603352064, 0, 3772137704, 1609537792, 3765648692, 241075200, 2758873919, 2034286592, 3948550144, 1276854272, 1073741824, 2362691968, 4093640704, 2147483648, 3087532032, 1610612736, 1991802112]

def test_shl32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/shl32_mips', 'sink', 0) == [2684354560, 2165713892, 4264001536, 3221225472, 3710264864, 1543503872, 3297734656, 2332033024, 0, 2885681152, 2453806592, 1455177728, 868830656, 1105190724, 4232052736, 3155972976, 1828716544, 2504818176, 1073741824, 2717908992, 1643118592, 2724200448, 2372280064, 3891134464, 1259947160, 2989211648, 1275068416, 356515840, 3311403008, 1193443328, 3409969152, 1342177280, 2147483648, 2603352064, 0, 3772137704, 1609537792, 3765648692, 241075200, 2758873919, 2034286592, 3948550144, 1276854272, 1073741824, 2362691968, 4093640704, 2147483648, 3087532032, 1610612736, 1991802112]

def test_and32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_arm', 'sink', 0) == [1207984514, 39978758, 6308106, 553680901, 843579488, 139686084, 1095043465, 2843803720, 270152116, 3124384265, 9437200, 8134657, 1360020996, 48385024, 268832800, 4751656, 52723760, 606372034, 2215204498, 551030824, 973620761, 3644867755, 465715276, 208494851, 3256262770, 337424000, 9203872, 3289728834, 1442956288, 1484062727, 2097666, 677466305, 273678596, 675304544, 2236077060, 1167065216, 67117224, 3355840832, 3259252746, 1074626625, 272861394, 1531195401, 16978176, 1418900267, 872415765, 2687104, 3416326148, 2319592448, 1159356677, 3233056819]

def test_and32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/and32_mips', 'sink', 0) == [1207984514, 39978758, 6308106, 553680901, 843579488, 139686084, 1095043465, 2843803720, 270152116, 3124384265, 9437200, 8134657, 1360020996, 48385024, 268832800, 4751656, 52723760, 606372034, 2215204498, 551030824, 973620761, 3644867755, 465715276, 208494851, 3256262770, 337424000, 9203872, 3289728834, 1442956288, 1484062727, 2097666, 677466305, 273678596, 675304544, 2236077060, 1167065216, 67117224, 3355840832, 3259252746, 1074626625, 272861394, 1531195401, 16978176, 1418900267, 872415765, 2687104, 3416326148, 2319592448, 1159356677, 3233056819]

def test_or32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_arm', 'sink', 0) == [233764319, 3719068613, 4290557455, 247447292, 3757888251, 3174920061, 1870622713, 4256014319, 3087005611, 4294957567, 3522615627, 536592215, 2123151854, 3715920108, 4210540519, 3117275950, 1022869431, 4259839487, 1995930523, 3646397935, 4127194927, 4284219261, 4294836207, 2935975935, 3751701502, 1071494527, 3721330423, 4214816495, 4160679119, 4225236709, 368049983, 3154021879, 3756851163, 3485400895, 4007510014, 2130706111, 1342046197, 1476250595, 2121922027, 2084255743, 3199653827, 4260290010, 3950081529, 3069050347, 2365584383, 4226899583, 4158188134, 3353081695, 1453816703, 1743220735]

def test_or32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/or32_mips', 'sink', 0) == [233764319, 3719068613, 4290557455, 247447292, 3757888251, 3174920061, 1870622713, 4256014319, 3087005611, 4294957567, 3522615627, 536592215, 2123151854, 3715920108, 4210540519, 3117275950, 1022869431, 4259839487, 1995930523, 3646397935, 4127194927, 4284219261, 4294836207, 2935975935, 3751701502, 1071494527, 3721330423, 4214816495, 4160679119, 4225236709, 368049983, 3154021879, 3756851163, 3485400895, 4007510014, 2130706111, 1342046197, 1476250595, 2121922027, 2084255743, 3199653827, 4260290010, 3950081529, 3069050347, 2365584383, 4226899583, 4158188134, 3353081695, 1453816703, 1743220735]

def test_xor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_arm', 'sink', 0) == [512727953, 2379771537, 1765187175, 1589533453, 4148256285, 3397077086, 1934161079, 2892967896, 1249686404, 1075131344, 1374551900, 4110091084, 2775373154, 3961790437, 3710879918, 3503828642, 2025416680, 4007190326, 1185326005, 263850326, 2535333259, 369140991, 4290333125, 2755146559, 213939705, 3551148433, 1761235194, 816312108, 2882352144, 1105383812, 4210968398, 2504501193, 3219235396, 80170322, 2571671013, 616280534, 3126187526, 1901614407, 4127142777, 2752587310, 1547074159, 4003871109, 1319120893, 828762391, 2397105455, 3263704010, 1722801976, 2576362741, 4225266363, 2058423280]

def test_xor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/xor32_mips', 'sink', 0) == [512727953, 2379771537, 1765187175, 1589533453, 4148256285, 3397077086, 1934161079, 2892967896, 1249686404, 1075131344, 1374551900, 4110091084, 2775373154, 3961790437, 3710879918, 3503828642, 2025416680, 4007190326, 1185326005, 263850326, 2535333259, 369140991, 4290333125, 2755146559, 213939705, 3551148433, 1761235194, 816312108, 2882352144, 1105383812, 4210968398, 2504501193, 3219235396, 80170322, 2571671013, 616280534, 3126187526, 1901614407, 4127142777, 2752587310, 1547074159, 4003871109, 1319120893, 828762391, 2397105455, 3263704010, 1722801976, 2576362741, 4225266363, 2058423280]

def test_land32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_arm', 'sink', 0) == [False, False, False, True, True, True, False, False, False, True, False, False, False, False, False, False, False, True, False, True, True, True, True, False, False, True, False, True, True, False, True, False, True, True, False, False, False, False, False, True, True, False, False, False, False, False, True, False, True, True]

def test_land32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/land32_mips', 'sink', 0) == [False, False, False, True, True, True, False, False, False, True, False, False, False, False, False, False, False, True, False, True, True, True, True, False, False, True, False, True, True, False, True, False, True, True, False, False, False, False, False, True, True, False, False, False, False, False, True, False, True, True]

def test_lor32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_arm', 'sink', 0) == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_lor32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lor32_mips', 'sink', 0) == [True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True, True]

def test_eq32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_arm', 'sink', 0) == [False, True, False, False, False, True, True, True, False, False, False, True, False, False, True, True, True, True, False, False, False, False, False, True, False, False, False, False, True, True, True, True, True, False, True, True, False, True, True, True, True, False, True, False, False, True, True, False, False, False]

def test_eq32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/eq32_mips', 'sink', 0) == [False, True, False, False, False, True, True, True, False, False, False, True, False, False, True, True, True, True, False, False, False, False, False, True, False, False, False, False, True, True, True, True, True, False, True, True, False, True, True, True, True, False, True, False, False, True, True, False, False, False]

def test_ne32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_arm', 'sink', 0) == [True, True, True, False, True, False, False, True, True, False, True, True, True, True, False, True, True, True, False, True, True, True, False, True, True, True, True, False, True, True, False, True, True, True, False, False, False, True, True, False, False, False, True, True, False, False, False, True, True, True]

def test_ne32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ne32_mips', 'sink', 0) == [True, True, True, False, True, False, False, True, True, False, True, True, True, True, False, True, True, True, False, True, True, True, False, True, True, True, True, False, True, True, False, True, True, True, False, False, False, True, True, False, False, False, True, True, False, False, False, True, True, True]

def test_le32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_arm', 'sink', 0) == [True, False, True, True, False, False, True, False, True, False, False, False, True, True, False, True, False, False, False, True, True, True, False, True, False, True, True, False, False, True, False, True, False, False, True, False, False, True, True, False, False, True, False, True, False, True, False, True, True, True]

def test_le32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/le32_mips', 'sink', 0) == [True, False, True, True, False, False, True, False, True, False, False, False, True, True, False, True, False, False, False, True, True, True, False, True, False, True, True, False, False, True, False, True, False, False, True, False, False, True, True, False, False, True, False, True, False, True, False, True, True, True]

def test_lt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_arm', 'sink', 0) == [False, True, False, False, False, False, True, True, False, True, False, True, True, False, False, False, False, True, False, False, False, True, False, False, True, True, True, False, False, True, True, True, True, True, True, False, False, True, True, True, True, True, False, True, True, True, True, False, True, False]

def test_lt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/lt32_mips', 'sink', 0) == [False, True, False, False, False, False, True, True, False, True, False, True, True, False, False, False, False, True, False, False, False, True, False, False, True, True, True, False, False, True, True, True, True, True, True, False, False, True, True, True, True, True, False, True, True, True, True, False, True, False]

def test_ge32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_arm', 'sink', 0) == [True, True, False, False, True, True, True, False, True, False, False, True, False, False, False, False, True, True, False, True, False, True, True, False, True, True, True, False, False, False, True, True, False, False, False, False, True, True, True, False, True, True, True, False, True, True, False, False, True, True]

def test_ge32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/ge32_mips', 'sink', 0) == [True, True, False, False, True, True, True, False, True, False, False, True, False, False, False, False, True, True, False, True, False, True, True, False, True, True, True, False, False, False, True, True, False, False, False, False, True, True, True, False, True, True, True, False, True, True, False, False, True, True]

def test_gt32_arm():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_arm', 'sink', 0) == [False, True, False, False, False, True, False, True, True, True, True, True, False, True, False, False, True, False, True, True, True, False, False, False, True, True, False, False, False, True, False, True, False, True, True, False, True, True, True, True, True, True, False, False, False, False, True, False, True, True]

def test_gt32_mips():
	assert run_backward_slicing_on_binary('binaries/binary_operations/gt32_mips', 'sink', 0) == [False, True, False, False, False, True, False, True, True, True, True, True, False, True, False, False, True, False, True, True, True, False, False, False, True, True, False, False, False, True, False, True, False, True, True, False, True, True, True, True, True, True, False, False, False, False, True, False, True, True]

