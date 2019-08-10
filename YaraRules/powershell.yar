rule PowerSploitReflectiveExe
{
   strings:
       $e_magic = "if ($e_magic -ne 'MZ')"
       $ReflectiveExe  = "ReflectiveExe "
   condition:
       all of them
}