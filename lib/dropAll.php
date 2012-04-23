<?php
require_once('wfSchema.php');
if((! isset($_SERVER)) || isset($_SERVER['REQUEST_URI'])){ echo "Running under web interface. Exiting.\n"; exit(0); }
if(! (isset($argv[1]) && isset($argv[2]) && isset($argv[3]))){ echo "Usage: {$argv[0]} <DB username> <DB password> <DB name>\n"; exit(); } $s = new wfSchema('localhost', $argv[1], $argv[2], $argv[3]); 

$s->dropAll();

?>
