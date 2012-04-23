<?php
class wfUtils {
	private static $reverseLookupCache = array();
	public static function makeTimeAgo($secs, $noSeconds = false) {
		if($secs < 1){
			return "a moment";
		}
		$months = floor($secs / (86400 * 30));
		$days = floor($secs / 86400);
		$hours = floor($secs / 3600);
		$minutes = floor($secs / 60);
		if($months) {
			$days -= $months * 30;
			return self::pluralize($months, 'month', $days, 'day');
		} else if($days) {
			$hours -= $days * 24;
			return self::pluralize($days, 'day', $hours, 'hour');
		} else if($hours) {
			$minutes -= $hours * 60;
			return self::pluralize($hours, 'hour', $minutes, 'min');
		} else if($minutes) {
			$secs -= $minutes * 60;
			return self::pluralize($minutes, 'min');
		} else {
			if($noSeconds){
				return "less than a minute";
			} else {
				return floor($secs) . " secs";
			}
		}
	}
	public static function pluralize($m1, $t1, $m2 = false, $t2 = false) {
		if($m1 != 1) {
			$t1 = $t1 . 's';
		}
		if($m2 != 1) {
			$t2 = $t2 . 's';
		}
		if($m1 && $m2){
			return "$m1 $t1 $m2 $t2";
		} else {
			return "$m1 $t1";
		}
	}
	public static function formatBytes($bytes, $precision = 2) { 
		$units = array('B', 'KB', 'MB', 'GB', 'TB'); 

		$bytes = max($bytes, 0); 
		$pow = floor(($bytes ? log($bytes) : 0) / log(1024)); 
		$pow = min($pow, count($units) - 1); 

		// Uncomment one of the following alternatives
		$bytes /= pow(1024, $pow);
		// $bytes /= (1 << (10 * $pow)); 

		return round($bytes, $precision) . ' ' . $units[$pow]; 
	} 
	public static function inet_ntoa($ip){
		$long = 4294967295 - ($ip - 1);
		return long2ip(-$long);
	}
	public static function inet_aton($ip){
		return sprintf("%u", ip2long($ip));
	}
	public static function getBaseURL(){
		return plugins_url() . '/wordfence/';
	}
	public static function getPluginBaseDir(){
		return ABSPATH . 'wp-content/plugins/';
	}
	public static function getIP(){
		$ip = 0;
		if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
			$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		}
		if((! $ip) && isset($_SERVER['REMOTE_ADDR'])){
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		return $ip;
	}
	public static function getRequestedURL(){
		return ($_SERVER['HTTPS'] ? 'https' : 'http') . '://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
	}
	public static function reverseLookup($IP){
		if(! isset(self::$reverseLookupCache[$IP])){
			$ptr = implode(".", array_reverse(explode(".",$IP))) . ".in-addr.arpa";
			$host = dns_get_record($ptr, DNS_PTR);
			if($host == null){
				self::$reverseLookupCache[$IP] = '';
			} else {
				self::$reverseLookupCache[$IP] = $host[0]['target'];
			}
		}
		return self::$reverseLookupCache[$IP];
	}
	public static function editUserLink($userID){
		return get_admin_url() . 'user-edit.php?user_id=' . $userID;
	}
	public static function wdie($err){
		$trace=debug_backtrace(); $caller=array_shift($trace); 
		error_log("Wordfence error in " . $caller['file'] . " line " . $caller['line'] . ": $err");
		exit();
	}
	public static function tmpl($file, $data){
		extract($data);
		ob_start();
		include $file;
		return ob_get_contents() . (ob_end_clean() ? "" : "");
	}
	public static function bigRandomHex(){
		return dechex(rand(0, 2147483647)) . dechex(rand(0, 2147483647)) . dechex(rand(0, 2147483647));
	}
	public static function encrypt($str){
		$key = wfConfig::get('encKey');
		if(! $key){
			error_log("Wordfence error: No encryption key found!");
			exit();
		}
		$db = new wfDB();
		return $db->querySingle("select HEX(AES_ENCRYPT('%s', '%s')) as val", $str, $key);
	}
	public static function decrypt($str){
		$key = wfConfig::get('encKey');
		if(! $key){
			error_log("Wordfence error: No encryption key found!");
			exit();
		}
		$db = new wfDB();
		return $db->querySingle("select AES_DECRYPT(UNHEX('%s'), '%s') as val", $str, $key);
	}
	public static function logCaller(){
		$trace=debug_backtrace(); 
		$caller=array_shift($trace); 
		$c2 = array_shift($trace);
		error_log("Caller for " . $caller['file'] . " line " . $caller['line'] . " is " . $c2['file'] . ' line ' . $c2['line']);
	}
	public static function getWPVersion(){
		global $wp_version;
		global $wordfence_wp_version;
		if(isset($wordfence_wp_version)){
			return $wordfence_wp_version;
		} else {
			return $wp_version;
		}
	}
}


?>
