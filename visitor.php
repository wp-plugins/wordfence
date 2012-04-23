<?php 
ignore_user_abort(true);
if ( !defined('ABSPATH') ) {
	/** Set up WordPress environment */
	if($_SERVER['SCRIPT_FILENAME']){
		$wfBaseDir = preg_replace('/[^\/]+\/[^\/]+\/[^\/]+\/visitor\.php$/', '', $_SERVER['SCRIPT_FILENAME']);
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
require_once('lib/wfUtils.php');
require_once('lib/wfDB.php');
function wfVisitor(){
	$hid = $_GET['hid'];
	$hid = wfUtils::decrypt($hid);
	if(! preg_match('/^\d+$/', $hid)){ exit(); }
	$db = new wfDB();
	global $wpdb; $p = $wpdb->prefix;
	$db->query("update $p"."wfHits set jsRun=1 where id=%d", $hid);
	exit();
}
wfVisitor();

?>
