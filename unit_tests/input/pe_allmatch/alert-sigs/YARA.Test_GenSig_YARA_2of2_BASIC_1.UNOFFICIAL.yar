
rule Test_GenSig_YARA_2of2_BASIC_1
{
    strings:
        $s1 = "CLAMAV_TEST_PRINTF_STRING_e4d7_7b43_3155_040a"
    condition:
        $s1
}
