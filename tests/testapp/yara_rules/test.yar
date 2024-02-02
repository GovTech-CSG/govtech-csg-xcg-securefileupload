rule yara_rule_for_unit_tests
{
    strings:
        $string1 = "yara"
        $string2 = "test"

    condition:
        ($string1 and $string2)
}
