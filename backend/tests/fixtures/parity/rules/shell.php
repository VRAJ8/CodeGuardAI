<?php
// PHP shell rules.
$out = shell_exec("ls " . $dir);
system($cmd);
passthru($cmd);
$p = popen($cmd, "r");
$h = proc_open($cmd, $spec, $pipes);
my_system($cmd);
eval($code);
$safe = escapeshellarg($dir);
$q = "UPDATE users SET name = '" . $name . "'";
$q2 = "UPDATE users SET name = '" + $name;
