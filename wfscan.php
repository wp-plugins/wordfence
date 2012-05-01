<?php
ignore_user_abort(true);
$wordfence_wp_version = false;
if ( !defined('ABSPATH') ) {
	/** Set up WordPress environment */
	if($_SERVER['SCRIPT_FILENAME']){
		$wfBaseDir = preg_replace('/[^\/]+\/[^\/]+\/[^\/]+\/wfscan\.php$/', '', $_SERVER['SCRIPT_FILENAME']);
		require_once($wfBaseDir . 'wp-load.php');
		global $wp_version;
		global $wordfence_wp_version;
		require($wfBaseDir . 'wp-includes/version.php');
		$wordfence_wp_version = $wp_version;
	} else {
		require_once('../../../wp-load.php');
		require_once('../../../wp-includes/version.php');
	}
}
require_once('lib/wordfenceConstants.php');
require_once('lib/wfScanEngine.php');

class wfScan {
	public static function wfScanMain(){
		if(! $_SERVER['HTTP_X_WORDFENCE_CRONKEY']){ 
			self::errorExit("The Wordfence scanner did not receive the x_wordfence_cronkey secure header.");
		}
		$currentCronKey = wfConfig::get('currentCronKey', false);
		if(! $currentCronKey){
			self::errorExit("Wordfence could not find a saved cron key to start the scan.");
		}

		$savedKey = explode(',',$currentCronKey);
		if(time() - $savedKey[0] > 60){ 
			self::errorExit("The key used to start a scan has expired.");
		} //keys only last 60 seconds and are used within milliseconds of creation
		if($savedKey[1] != $_SERVER['HTTP_X_WORDFENCE_CRONKEY']){ 
			self::errorExit("Wordfence could not start a scan because the cron key does not match the saved key.");
		}
		wfConfig::set('currentCronKey', '');
		ini_set('max_execution_time', 1800); //30 mins
		self::becomeAdmin();

		$scanRunning = wfConfig::get('wf_scanRunning');
		if($scanRunning && time() - $scanRunning < WORDFENCE_MAX_SCAN_TIME){
			self::errorExit("There is already a scan running.");
		}
		if(wfConfig::get('maxMem', false) && (int) wfConfig::get('maxMem') > 0){
			$maxMem = (int) wfConfig::get('maxMem');
		} else {
			$maxMem = 256;
		}
		if( function_exists('memory_get_usage') && ( (int) @ini_get('memory_limit') < $maxMem ) ){
			wordfence::status(1, 'info', "Requesting a maximum memory limit of $maxMem megabytes from PHP.");
			@ini_set('memory_limit', $maxMem . 'M');
		}

		set_error_handler('wfScan::error_handler', E_ALL);
		register_shutdown_function('wfScan::shutdown');
		ob_start('wfScan::obHandler');
		@error_reporting(E_ALL);
		@ini_set('display_errors','On');

		wfConfig::set('wf_scanRunning', time());
		$scan = new wfScanEngine();
		$scan->go();
		wfConfig::set('wf_scanRunning', '');
	}
	public static function obHandler($buf){
		if(strlen($buf) > 1000){
			$buf = substr($buf, 0, 255);
		}
		if(empty($buf) === false && preg_match('/[a-zA-Z0-9]+/', $buf)){
			wordfence::status(1, 'error', $buf);
		}
	}
	public static function error_handler($errno, $errstr, $errfile, $errline){
		wordfence::status(1, 'error', "$errstr ($errno) File: $errfile Line: $errline");
	}
	public static function shutdown(){
		wfConfig::set('wf_scanRunning', '');
	}
	private static function errorExit($msg){
		echo json_encode(array('errorMsg' => $msg)); 
		exit();	
	}
	public static function becomeAdmin(){
		global $wpdb;
		$ws = $wpdb->get_results("SELECT ID, user_login FROM $wpdb->users");
		$users = array();
		foreach($ws as $user){
			$userDat = get_userdata($user->ID);
			array_push($users, array(
				'id' => $user->ID,
				'user_login' => $user->user_login,
				'level' => $userDat->user_level
				));
		}
		usort($users, 'wfScan::usort');
		wp_set_current_user($users[0]['id'], $users[0]['user_login']);
	}
	public static function usort($b, $a){
		if($a['level'] == $b['level']){ return 0; }
		return ($a['level'] < $b['level']) ? -1 : 1;
	}
}
wfScan::wfScanMain();
?>
