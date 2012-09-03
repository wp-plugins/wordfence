<?php
/*
Plugin Name: Wordfence Security
Plugin URI: http://wordfence.com/
Description: Wordfence Security - Anti-virus and Firewall security plugin for WordPress 
Author: Mark Maunder
Version: 3.2.7
Author URI: http://wordfence.com/
*/
define('WORDFENCE_VERSION', '3.2.7');
if(! defined('WORDFENCE_VERSIONONLY_MODE')){
	if((int) @ini_get('memory_limit') < 64){
		@ini_set('memory_limit', '64M'); //Some hosts have ini set at as little as 32 megs. 64 is the min sane amount of memory.
	}
	require_once('lib/wordfenceConstants.php');
	require_once('lib/wordfenceClass.php');
	register_activation_hook(WP_PLUGIN_DIR . '/wordfence/wordfence.php', 'wordfence::installPlugin');
	register_deactivation_hook(WP_PLUGIN_DIR . '/wordfence/wordfence.php', 'wordfence::uninstallPlugin');
	wordfence::install_actions();
}

?>
