rule yara_test
{
    strings:
        $string1 = "pay"
        $string2 = "immediately"

    condition:
        ($string1 and $string2)
}
