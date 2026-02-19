rule TestRule
{
    meta:
        description = "Simple test rule to confirm loading works"
        author = "Test"
    strings:
        $text = "This is a test string" ascii wide
    condition:
        $text
}
