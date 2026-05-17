rule Researcher_PHP_Webshell_Common
{
  meta:
    description = "Common PHP webshell execution primitives"
    severity = "high"
  strings:
    $eval_post = "eval($_POST"
    $eval_request = "eval($_REQUEST"
    $system_any = "system("
    $system_get = "system($_GET"
    $system_post = "system($_POST"
    $shell_exec = "shell_exec("
    $passthru = "passthru("
    $base64_decode = "base64_decode("
    $assert = "assert("
  condition:
    any of them
}

rule Researcher_PHP_Obfuscated_Loader
{
  meta:
    description = "PHP loader or obfuscation patterns often used by droppers"
    severity = "high"
  strings:
    $gzinflate = "gzinflate("
    $str_rot13 = "str_rot13("
    $create_function = "create_function("
    $preg_replace_eval = "preg_replace('/.*/e'"
    $long_base64 = /[A-Za-z0-9+\/]{180,}={0,2}/
  condition:
    2 of them
}

rule Researcher_Shell_Reverse_Shell_Hints
{
  meta:
    description = "Shell reverse shell or payload execution hints"
    severity = "high"
  strings:
    $dev_tcp = "/dev/tcp/"
    $bash_i = "bash -i"
    $mkfifo = "mkfifo"
    $nc_e = "nc -e"
    $ncat_e = "ncat -e"
    $python_socket = "socket.socket"
    $chmod_exec = "chmod +x"
  condition:
    any of them
}

rule Researcher_Download_And_Execute
{
  meta:
    description = "Download-and-execute command patterns"
    severity = "medium"
  strings:
    $curl = "curl "
    $wget = "wget "
    $pipe_sh = "| sh"
    $pipe_bash = "| bash"
    $chmod = "chmod +x"
  condition:
    ($curl or $wget) and ($pipe_sh or $pipe_bash or $chmod)
}
