
rule Test_GenSig_YARA_1of2_BASIC_0
{
    strings:
        $s1 = "CLAMAV_TEST_PRINTF_STRING_ffa8_3994_1788_e8b6"
    condition:
        $s1
}
