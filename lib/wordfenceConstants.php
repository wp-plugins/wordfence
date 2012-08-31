<?php
define('WORDFENCE_API_VERSION', '2.3');
define('WORDFENCE_API_URL_SEC', 'https://noc1.wordfence.com/');
define('WORDFENCE_API_URL_NONSEC', 'http://noc1.wordfence.com/');
define('WORDFENCE_MAX_SCAN_TIME', 600);
define('WORDFENCE_TRANSIENTS_TIMEOUT', 3600); //how long are items cached in seconds e.g. files downloaded for diffing
define('WORDFENCE_MAX_IPLOC_AGE', 604800); //1 week
define('WORDFENCE_CRAWLER_VERIFY_CACHE_TIME', 604800); 
define('WORDFENCE_REVERSE_LOOKUP_CACHE_TIME', 86400);
define('WORDFENCE_MAX_FILE_SIZE_TO_PROCESS', 52428800); //50 megs
?>
