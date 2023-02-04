from .common import run_backward_slicing_on_binary

def test_shl32_arm():
	assert run_backward_slicing_on_binary('binaries/shl32_arm') == [3215589376, 1508615354, 3529506816, 2197544208, 3444572160, 838217216, 1912602624, 2787741696, 2530105344, 394330112, 2765470976, 0, 1096938878, 1757700960, 1528377095, 2426922240, 4168531968, 3288865908, 3325791744, 1677721600, 3970957312, 1921220608, 2348810240, 268435456, 3623878656, 1040187392, 3820486656, 2389757440, 2677260544, 1837367296, 536870912, 695789568, 1596194816, 287309824, 1644167168, 3808303104, 1393355008, 94896128, 1841299456, 2055933952, 759300096, 1261489920, 58230144, 50331648, 828739328, 650248192, 335544320, 3900702720, 2682935552, 4129284864, 3239309696, 2100166768, 251658240, 4048482636, 2654994432, 3699376128, 888209408, 2046820352, 3221225472, 3347048448, 3858759680, 1682177536, 3136290816, 2762279204, 3617587200, 3977248768, 2818572288, 1103101952, 268435456, 2538106880, 4026531840, 2671204368, 158859264, 1082130432, 4015259648, 743440384, 2572419072, 425261354, 2179655680, 2186280960, 2751463424, 1275068416, 1614807040, 1316492364, 3124954480, 934543360, 982646784, 3566206976, 496935744, 590275387, 1073741824, 2952790016, 2961178624, 3172741632, 325083136, 1409286144, 3378425344, 0, 3443523584, 0]

def test_shl32_mips():
	assert run_backward_slicing_on_binary('binaries/shl32_mips') == [3215589376, 1508615354, 3529506816, 2197544208, 3444572160, 838217216, 1912602624, 2787741696, 2530105344, 394330112, 2765470976, 0, 1096938878, 1757700960, 1528377095, 2426922240, 4168531968, 3288865908, 3325791744, 1677721600, 3970957312, 1921220608, 2348810240, 268435456, 3623878656, 1040187392, 3820486656, 2389757440, 2677260544, 1837367296, 536870912, 695789568, 1596194816, 287309824, 1644167168, 3808303104, 1393355008, 94896128, 1841299456, 2055933952, 759300096, 1261489920, 58230144, 50331648, 828739328, 650248192, 335544320, 3900702720, 2682935552, 4129284864, 3239309696, 2100166768, 251658240, 4048482636, 2654994432, 3699376128, 888209408, 2046820352, 3221225472, 3347048448, 3858759680, 1682177536, 3136290816, 2762279204, 3617587200, 3977248768, 2818572288, 1103101952, 268435456, 2538106880, 4026531840, 2671204368, 158859264, 1082130432, 4015259648, 743440384, 2572419072, 425261354, 2179655680, 2186280960, 2751463424, 1275068416, 1614807040, 1316492364, 3124954480, 934543360, 982646784, 3566206976, 496935744, 590275387, 1073741824, 2952790016, 2961178624, 3172741632, 325083136, 1409286144, 3378425344, 0, 3443523584, 0]

