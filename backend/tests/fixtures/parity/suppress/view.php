<html>
<!-- codeguard-ignore-next-line -->
<?php eval($template); ?>
<?php eval($other); ?> <!-- codeguard-ignore: CG-EVAL -- reviewed -->
<?php system($cmd); ?> <!-- codeguard-ignore: CG-EVAL -->
<?php eval($x); -- codeguard-ignore ?>
<?php eval($y); ?> -- codeguard-ignore: CG-EVAL -- SQL-style leader
</html>
