<?php 
ignore_user_abort(true);
if ( !defined('ABSPATH') ) {
	/** Set up WordPress environment */
	require_once('../../../wp-load.php');
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
