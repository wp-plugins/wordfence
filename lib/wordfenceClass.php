<?php
require_once('wordfenceConstants.php');
require_once('wfScanEngine.php');
require_once('wfCrawl.php');
require_once 'Diff.php';
require_once 'Diff/Renderer/Html/SideBySide.php';
require_once 'wfAPI.php';
require_once 'wfIssues.php';
require_once('wfDB.php');
require_once('wfUtils.php');
require_once('wfLog.php');
require_once('wfConfig.php');
require_once('wfSchema.php');
class wordfence {
	public static $printStatus = false;
	public static $wordfence_wp_version = false;
	protected static $lastURLError = false;
	protected static $curlContent = "";
	protected static $curlDataWritten = 0;
	protected static $hasher = '';
	protected static $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
	protected static $ignoreList = false;
	public static $newVisit = false;
	private static $wfLog = false;
	private static $hitID = 0;
	private static $statusStartMsgs = array();
	private static $debugOn = null;
	public static function installPlugin(){
		self::runInstall();
		//Used by MU code below
		update_option('wordfenceActivated', 1);
	}
	public static function uninstallPlugin(){
		//Used by MU code below
		update_option('wordfenceActivated', 0);
		wp_clear_scheduled_hook('wordfence_daily_cron');
		wp_clear_scheduled_hook('wordfence_hourly_cron');
		
		//Remove old legacy cron job if it exists
		wp_clear_scheduled_hook('wordfence_scheduled_scan');
		
		//Remove all scheduled scans.
		self::unscheduleAllScans();
		
		if(wfConfig::get('deleteTablesOnDeact')){
			$schema = new wfSchema();
			$schema->dropAll();
			foreach(array('wordfence_version', 'wordfenceActivated') as $opt){
				delete_option($opt);
			}
		}
	}
	public static function hourlyCron(){
		global $wpdb; $p = $wpdb->base_prefix;
		$api = new wfAPI(wfConfig::get('apiKey'), wfUtils::getWPVersion());
			
		
		if(wfConfig::get('other_WFNet')){
			$wfdb = new wfDB();
			$q1 = $wfdb->querySelect("select URI from $p"."wfNet404s where ctime > unix_timestamp() - 3600 limit 1000");
			$URIs = array();
			foreach($q1 as $rec){
				array_push($URIs, $rec['URI']);
			}
			$wfdb->truncate($p . "wfNet404s");
			if(sizeof($URIs) > 0){
				try {
					$api->call('send_net_404s', array(), array( 'URIs' => json_encode($URIs) ));
				} catch(Exception $e){
					//Ignore
				}
			}

			$q2 = $wfdb->querySelect("select INET_NTOA(IP) as IP from $p"."wfVulnScanners where ctime > unix_timestamp() - 3600");
			$scanCont = "";
			foreach($q2 as $rec){
				$scanCont .= pack('N', ip2long($rec['IP']));
			}
			$wfdb->truncate($p . "wfVulnScanners");

			$q3 = $wfdb->querySelect("select INET_NTOA(IP) as IP from $p"."wfLockedOut where blockedTime > unix_timestamp() - 3600");
			$lockCont = "";
			foreach($q3 as $rec){
				$lockCont .= pack('N', ip2long($rec['IP']));
			}
			if(strlen($lockCont) > 0 || strlen($scanCont) > 0){
				$cont = pack('N', strlen($lockCont) / 4) . $lockCont . pack('N', strlen($scanCont) / 4) . $scanCont;
				try {
					$resp = $api->binCall('get_net_bad_ips', $cont);
					if($resp['code'] == 200){
						$len = strlen($resp['data']);
						$reason = "WFSN: Blocked by Wordfence Security Network";
						$wfdb->queryWrite("delete from $p"."wfBlocks where wfsn=1 and permanent=0");
						if($len > 0 && $len % 4 == 0){
							for($i = 0; $i < $len; $i += 4){
								list($ipLong) = array_values(unpack('N', substr($resp['data'], $i, 4)));
								$IPStr = long2ip($ipLong);
								if(! self::getLog()->isWhitelisted($IPStr)){ 
									self::getLog()->blockIP($IPStr, $reason, true);
								}
							}
						}
					}
				} catch(Exception $e){
					//Ignore
				}
			}
		}
	}
	public static function dailyCron(){
		$wfdb = new wfDB();
		global $wpdb; $p = $wpdb->base_prefix;
		$api = new wfAPI(wfConfig::get('apiKey'), wfUtils::getWPVersion());
		try {
			$patData = $api->call('get_known_vuln_pattern');
			if(is_array($patData) && $patData['pat']){
				if(@preg_match($patData['pat'], 'wordfence_test_vuln_match')){
					wfConfig::set('vulnRegex', $patData['pat']);
				}
			}
		} catch(Exception $e){
			wordfence::status(4, 'error', "Could not fetch vulnerability patterns in scheduled job: " . $e->getMessage());
		}

		$wfdb->queryWrite("delete from $p"."wfLocs where ctime < unix_timestamp() - %d", WORDFENCE_MAX_IPLOC_AGE); 
		$wfdb->truncate($p . "wfBadLeechers"); //only uses date that's less than 1 minute old
		$wfdb->queryWrite("delete from $p"."wfBlocks where (blockedTime + %s < unix_timestamp()) and permanent=0", wfConfig::get('blockedTime'));
		$wfdb->queryWrite("delete from $p"."wfCrawlers where lastUpdate < unix_timestamp() - (86400 * 7)");

		$count = $wfdb->querySingle("select count(*) as cnt from $p"."wfHits");
		if($count > 20000){
			$wfdb->queryWrite("delete from $p"."wfHits order by id asc limit " . ($count - 20000));
		}
		$maxRows = 1000; //affects stuff further down too
		foreach(array('wfLeechers', 'wfScanners') as $table){
			//This is time based per IP so shouldn't get too big
			$wfdb->queryWrite("delete from $p"."$table where eMin < ((unix_timestamp() - (86400 * 2)) / 60)");
		}
		$wfdb->queryWrite("delete from $p"."wfLockedOut where blockedTime + %s < unix_timestamp()", wfConfig::get('loginSec_lockoutMins') * 60);
		$count2 = $wfdb->querySingle("select count(*) as cnt from $p"."wfLogins");
		if($count2 > 20000){
			$wfdb->truncate($p . "wfLogins"); //in case of Dos
		} else if($count2 > $maxRows){
			$wfdb->queryWrite("delete from $p"."wfLogins order by ctime asc limit %d", ($count2 - $maxRows));
		}
		$wfdb->queryWrite("delete from $p"."wfReverseCache where unix_timestamp() - lastUpdate > 86400");
		$count3 = $wfdb->querySingle("select count(*) as cnt from $p"."wfThrottleLog");
		if($count3 > 20000){
			$wfdb->truncate($p . "wfThrottleLog"); //in case of DoS
		} else if($count3 > $maxRows){
			$wfdb->queryWrite("delete from $p"."wfThrottleLog order by endTime asc limit %d", ($count3 - $maxRows));
		}
		$count4 = $wfdb->querySingle("select count(*) as cnt from $p"."wfStatus");
		if($count4 > 100000){
			$wfdb->truncate($p . "wfStatus");
		} else if($count4 > 1000){ //max status events we keep. This determines how much gets emailed to us when users sends us a debug report. 
			$wfdb->queryWrite("delete from $p"."wfStatus where level != 10 order by ctime asc limit %d", ($count4 - 1000));
			$count5 = $wfdb->querySingle("select count(*) as cnt from $p"."wfStatus where level=10");
			if($count5 > 100){
				$wfdb->queryWrite("delete from $p"."wfStatus where level = 10 order by ctime asc limit %d", ($count5 - 100) );
			}
		}

	}
	public static function runInstall(){
		update_option('wordfence_version', WORDFENCE_VERSION); //In case we have a fatal error we don't want to keep running install.
		//EVERYTHING HERE MUST BE IDEMPOTENT

		//Remove old legacy cron job if exists
		wp_clear_scheduled_hook('wordfence_scheduled_scan');


		$schema = new wfSchema();
		$schema->createAll(); //if not exists
		wfConfig::setDefaults(); //If not set

		//Install new schedule. If schedule config is blank it will install the default 'auto' schedule.
		wordfence::scheduleScans();

		if(! wfConfig::get('apiKey')){
			$api = new wfAPI('', wfUtils::getWPVersion());
			try {
				$keyData = $api->call('get_anon_api_key');
				if($keyData['ok'] && $keyData['apiKey']){
					wfConfig::set('apiKey', $keyData['apiKey']);
				} else {
					throw new Exception("Could not understand the response we received from the Wordfence servers when applying for a free API key.");
				}
			} catch(Exception $e){
				error_log("Could not fetch free API key from Wordfence: " . $e->getMessage());
				return;
			}
		}
		wp_clear_scheduled_hook('wordfence_daily_cron');
		wp_clear_scheduled_hook('wordfence_hourly_cron');
		wp_schedule_event(time(), 'daily', 'wordfence_daily_cron');
		wp_schedule_event(time(), 'hourly', 'wordfence_hourly_cron');
		$db = new wfDB();

		if($db->columnExists('wfHits', 'HTTPHeaders')){ //Upgrade from 3.0.4
			global $wpdb;
			$prefix = $wpdb->base_prefix;
			$count = $db->querySingle("select count(*) as cnt from $prefix"."wfHits");
			if($count > 20000){
				$db->queryWrite("delete from $prefix"."wfHits order by id asc limit " . ($count - 20000));
			}
			$db->dropColumn('wfHits', 'HTTPHeaders');
		}

		//Upgrading from 1.5.6 or earlier needs:
		$db->createKeyIfNotExists('wfStatus', 'level', 'k2');
		if(wfConfig::get('isPaid') == 'free'){
			wfConfig::set('isPaid', '');
		}
		//End upgrade from 1.5.6

		global $wpdb;
		$prefix = $wpdb->base_prefix;
		$db->queryWriteIgnoreError("alter table $prefix"."wfConfig modify column val longblob");
		$db->queryWriteIgnoreError("alter table $prefix"."wfBlocks add column permanent tinyint UNSIGNED default 0");
		$db->queryWriteIgnoreError("alter table $prefix"."wfStatus modify column msg varchar(1000) NOT NULL");
		//3.1.2 to 3.1.4
		$db->queryWriteIgnoreError("alter table $prefix"."wfBlocks modify column blockedTime bigint signed NOT NULL");
		//3.2.1 to 3.2.2
		$db->queryWriteIgnoreError("alter table $prefix"."wfLockedOut modify column blockedTime bigint signed NOT NULL");
		$db->queryWriteIgnoreError("drop table if exists $prefix"."wfFileQueue");
		$db->queryWriteIgnoreError("drop table if exists $prefix"."wfFileChanges");

		$optScanEnabled = $db->querySingle("select val from $prefix"."wfConfig where name='scansEnabled_options'");
		if($optScanEnabled != '0' && $optScanEnabled != '1'){
			$db->queryWrite("update $prefix"."wfConfig set val='1' where name='scansEnabled_options'");
		}
		
		//Must be the final line
	}
	public static function install_actions(){
		$versionInOptions = get_option('wordfence_version', false);
		if( (! $versionInOptions) || version_compare(WORDFENCE_VERSION, $versionInOptions, '>')){
			//Either there is no version in options or the version in options is greater and we need to run the upgrade
			self::runInstall();
		}
		if(defined('MULTISITE') && MULTISITE === true){
			global $blog_id;
			if($blog_id == 1 && get_option('wordfenceActivated') != 1){ return; } //Because the plugin is active once installed, even before it's network activated, for site 1 (WordPress team, why?!)
		}
		//User may be logged in or not, so register both handlers
		add_action('wp_ajax_nopriv_wordfence_logHuman', 'wordfence::ajax_logHuman_callback');
		add_action('wp_ajax_wordfence_logHuman', 'wordfence::ajax_logHuman_callback');
		add_action('wp_ajax_nopriv_wordfence_doScan', 'wordfence::ajax_doScan_callback');
		add_action('wp_ajax_wordfence_doScan', 'wordfence::ajax_doScan_callback');
		add_action('wp_ajax_nopriv_wordfence_testAjax', 'wordfence::ajax_testAjax_callback');
		add_action('wp_ajax_wordfence_testAjax', 'wordfence::ajax_testAjax_callback');


		add_action('wordfence_start_scheduled_scan', 'wordfence::wordfenceStartScheduledScan');
		add_action('wordfence_daily_cron', 'wordfence::dailyCron');
		add_action('wordfence_hourly_cron', 'wordfence::hourlyCron');
		add_action('plugins_loaded', 'wordfence::veryFirstAction');
		add_action('init', 'wordfence::initAction');
		add_action('template_redirect', 'wordfence::templateRedir');
		add_action('shutdown', 'wordfence::shutdownAction');
		add_action('wp_authenticate','wordfence::authAction');
		add_action('login_init','wordfence::loginInitAction');
		add_action('wp_login','wordfence::loginAction');
		add_action('wp_logout','wordfence::logoutAction');
		add_action('profile_update', 'wordfence::profileUpdateAction', '99', 2);
		add_action('lostpassword_post', 'wordfence::lostPasswordPost', '1');
		//add_filter('cron_schedules', 'wordfence::moreCronReccurences'); 
		add_filter('pre_comment_approved', 'wordfence::preCommentApprovedFilter', '99', 2);
		add_filter('authenticate', 'wordfence::authenticateFilter', 99, 3);
		//html|xhtml|atom|rss2|rdf|comment|export
		add_filter('get_the_generator_html', 'wordfence::genFilter', 99, 2);
		add_filter('get_the_generator_xhtml', 'wordfence::genFilter', 99, 2);
		add_filter('get_the_generator_atom', 'wordfence::genFilter', 99, 2);
		add_filter('get_the_generator_rss2', 'wordfence::genFilter', 99, 2);
		add_filter('get_the_generator_rdf', 'wordfence::genFilter', 99, 2);
		add_filter('get_the_generator_comment', 'wordfence::genFilter', 99, 2);
		add_filter('get_the_generator_export', 'wordfence::genFilter', 99, 2);
		add_filter('registration_errors', 'wordfence::registrationFilter', 99, 3);
		if(is_admin()){
			add_action('admin_init', 'wordfence::admin_init');
			if(is_multisite()){
				if(wfUtils::isAdminPageMU()){
					add_action('network_admin_menu', 'wordfence::admin_menus');
				} //else don't show menu
			} else {
				add_action('admin_menu', 'wordfence::admin_menus');
			}
		}
	}
	public static function ajax_testAjax_callback(){
		die("WFSCANTESTOK");
	}
	public static function ajax_doScan_callback(){
		ignore_user_abort(true);
		self::$wordfence_wp_version = false;
		require(ABSPATH . 'wp-includes/version.php');
		self::$wordfence_wp_version = $wp_version;
		require('wfScan.php');
		wfScan::wfScanMain();

	} //END doScan
	public static function ajax_logHuman_callback(){
		wfUtils::doNotCache();
		$hid = $_GET['hid'];
		$hid = wfUtils::decrypt($hid);
		if(! preg_match('/^\d+$/', $hid)){ exit(); }
		$db = new wfDB();
		global $wpdb; $p = $wpdb->base_prefix;
		$db->queryWrite("update LOW_PRIORITY $p"."wfHits set jsRun=1 where id=%d", $hid);
		if(! headers_sent()){ //suppress content-type warning in chrome
			header('Content-type: image/gif');
		}
		die("");
	}
	public static function ajaxReceiver(){
		if(! wfUtils::isAdmin()){
			die(json_encode(array('errorMsg' => "You appear to have logged out or you are not an admin. Please sign-out and sign-in again.")));
		}
		$func = $_POST['action'];
		$nonce = $_POST['nonce'];
		if(! wp_verify_nonce($nonce, 'wp-ajax')){ 
			die(json_encode(array('errorMsg' => "Your browser sent an invalid security token to Wordfence. Please try reloading this page or signing out and in again.")));
		}
		//func is e.g. wordfence_ticker so need to munge it
		$func = str_replace('wordfence_', '', $func);
		$returnArr = call_user_func('wordfence::ajax_' . $func . '_callback');
		if($returnArr === false){
			$returnArr = array('errorMsg' => "Wordfence encountered an internal error executing that request.");
		}
			
		if(! is_array($returnArr)){
			error_log("Function $func did not return an array and did not generate an error.");
			$returnArr = array();
		}
		if(isset($returnARr['nonce'])){
			error_log("Wordfence ajax function return an array with 'nonce' already set. This could be a bug.");
		}
		$returnArr['nonce'] = wp_create_nonce('wp-ajax');
		die(json_encode($returnArr));
	}
	public static function lostPasswordPost(){
		$IP = wfUtils::getIP();
		if(self::getLog()->isWhitelisted($IP)){
			return;
		}
		if(self::isLockedOut($IP)){
			require('wfLockedOut.php');
		}
		$email = $_POST['user_login'];
		if(empty($email)){ return; }
		$user = get_user_by('email', $_POST['user_login']);
		if($user){
			if(wfConfig::get('alertOn_lostPasswdForm')){
				wordfence::alert("Password recovery attempted", "Someone tried to recover the password for user with email address: $email", $IP);
			}
		}
		if(wfConfig::get('loginSecurityEnabled')){
			$tKey = 'wffgt_' . wfUtils::inet_aton($IP);
			$forgotAttempts = get_transient($tKey);
			if($forgotAttempts){
				$forgotAttempts++;
			} else {
				$forgotAttempts = 1;
			}
			if($forgotAttempts >= wfConfig::get('loginSec_maxForgotPasswd')){
				self::lockOutIP($IP, "Exceeded the maximum number of tries to recover their password which is set at: " . wfConfig::get('loginSec_maxForgotPasswd') . ". The last username or email they entered before getting locked out was: '" . $_POST['user_login'] . "'");
				require('wfLockedOut.php');
			}
			set_transient($tKey, $forgotAttempts, wfConfig::get('loginSec_countFailMins') * 60);
		}
	}
	public static function lockOutIP($IP, $reason){
		if(wfConfig::get('alertOn_loginLockout')){
			wordfence::alert("User locked out from signing in", "A user with IP address $IP has been locked out from the signing in or using the password recovery form for the following reason: $reason", $IP);
		}
		self::getLog()->lockOutIP(wfUtils::getIP(), $reason);
	}
	public static function isLockedOut($IP){
		return self::getLog()->isIPLockedOut($IP);
	}
	public static function veryFirstAction(){
		$wfFunc = @$_GET['_wfsf'];
		if($wfFunc == 'unlockEmail'){
			$numTries = get_transient('wordfenceUnlockTries');
			if($numTries > 10){
				echo "<html><body><h1>Please wait 3 minutes and try again</h1><p>You have used this form too much. Please wait 3 minutes and try again.</p></body></html>";
				exit();
			}
			if(! $numTries){ $numTries = 1; } else { $numTries = $numTries + 1; }
			set_transient('wordfenceUnlockTries', $numTries, 180);

			$email = trim($_POST['email']);
			global $wpdb;
			$ws = $wpdb->get_results("SELECT ID, user_login FROM $wpdb->users");
			$users = array();
			foreach($ws as $user){
				$userDat = get_userdata($user->ID);
				if($userDat->user_level > 7){
					if($email == $userDat->user_email){
						$found = true;
						break;
					}
				}
			}
			if(! $found){
				foreach(wfConfig::getAlertEmails() as $alertEmail){
					if($alertEmail == $email){
						$found = true;
						break;
					}
				}
			}
			if($found){
				$key = wfUtils::bigRandomHex();
				$IP = wfUtils::getIP();
				set_transient('wfunlock_' . $key, $IP, 1800);
				$content = wfUtils::tmpl('email_unlockRequest.php', array(
					'siteName' => get_bloginfo('name', 'raw'),
					'siteURL' => wfUtils::getSiteBaseURL(),
					'unlockHref' => wfUtils::getSiteBaseURL() . '?_wfsf=unlockAccess&key=' . $key,
					'key' => $key,
					'IP' => $IP
					));
				wp_mail($email, "Unlock email requested", $content, "Content-Type: text/html");
			}
			echo "<html><body><h1>Your request was received</h1><p>We received a request to email \"" . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . "\" instructions to unlock their access. If that is the email address of a site administrator or someone on the Wordfence alert list, then they have been emailed instructions on how to regain access to this sytem. The instructions we sent will expire 30 minutes from now.</body></html>";
			exit();
		} else if($wfFunc == 'unlockAccess'){
			if(! preg_match('/^\d+\.\d+\.\d+\.\d+$/', get_transient('wfunlock_' . $_GET['key']))){
				echo "Invalid key provided for authentication.";
				exit();
			}
			/* You can enable this for paranoid security leve.
			if(get_transient('wfunlock_' . $_GET['key']) != wfUtils::getIP()){
				echo "You can only use this link from the IP address you used to generate the unlock email.";
				exit();
			}
			*/
			$wfLog = new wfLog(wfConfig::get('apiKey'), wfUtils::getWPVersion());
			if($_GET['func'] == 'unlockMyIP'){
				$wfLog->unblockIP(wfUtils::getIP());
				$wfLog->unlockOutIP(wfUtils::getIP());
				delete_transient('wflginfl_' . wfUtils::inet_aton(wfUtils::getIP())); //Reset login failure counter
				header('Location: ' . wp_login_url());
				exit();
			} else if($_GET['func'] == 'unlockAllIPs'){
				wordfence::status(1, 'info', "Request received via unlock email link to unblock all IP's.");
				$wfLog->unblockAllIPs();
				$wfLog->unlockAllIPs();
				delete_transient('wflginfl_' . wfUtils::inet_aton(wfUtils::getIP())); //Reset login failure counter
				header('Location: ' . wp_login_url());
				exit();
			} else if($_GET['func'] == 'disableRules'){
				wfConfig::set('firewallEnabled', 0);
				wfConfig::set('loginSecurityEnabled', 0);
				wordfence::status(1, 'info', "Request received via unlock email link to unblock all IP's via disabling firewall rules.");
				$wfLog->unblockAllIPs();
				$wfLog->unlockAllIPs();
				delete_transient('wflginfl_' . wfUtils::inet_aton(wfUtils::getIP())); //Reset login failure counter
				wfConfig::set('cbl_countries', ''); //unblock all countries
				header('Location: ' . wp_login_url());
				exit();
			} else {
				echo "Invalid function specified. Please check the link we emailed you and make sure it was not cut-off by your email reader.";
				exit();
			}
		}

		if(wfConfig::get('firewallEnabled')){
			$wfLog = self::getLog();
			$wfLog->firewallBadIPs();
		}
	}
	public static function loginAction($username){
		if(sizeof($_POST) < 1){ return; } //only execute if login form is posted
		if(! $username){ return; }
		$user = get_user_by('login', $username);
		$userID = $user ? $user->ID : 0;
		self::getLog()->logLogin('loginOK', 0, $username);
		if(user_can($userID, 'update_core')){
			if(wfConfig::get('alertOn_adminLogin')){ 
				wordfence::alert("Admin Login", "A user with username \"$username\" who has administrator access signed in to your WordPress site.", wfUtils::getIP());
			}
		} else {
			if(wfConfig::get('alertOn_nonAdminLogin')){
				wordfence::alert("User login", "A non-admin user with username \"$username\" signed in to your WordPress site.", wfUtils::getIP());
			}
		}
	}
	public static function registrationFilter($errors, $santizedLogin, $userEmail){
		if(wfConfig::get('loginSec_blockAdminReg') && $santizedLogin == 'admin'){
			$errors->add('user_login_error', '<strong>ERROR</strong>: You can\'t register using that username');
		}
		return $errors;
	}
	public static function authenticateFilter($authResult){
		$IP = wfUtils::getIP();	
		if(self::getLog()->isWhitelisted($IP)){
			return $authResult;
		}
		if(wfConfig::get('loginSecurityEnabled')){
			if(is_wp_error($authResult) && $authResult->get_error_code() == 'invalid_username' && wfConfig::get('loginSec_lockInvalidUsers')){
				self::lockOutIP($IP, "Used an invalid username '" . $_POST['log'] . "' to try to sign in.");
				require('wfLockedOut.php');
			}
			$tKey = 'wflginfl_' . wfUtils::inet_aton($IP);
			if(is_wp_error($authResult) && ($authResult->get_error_code() == 'invalid_username' || $authResult->get_error_code() == 'incorrect_password') ){
				$tries = get_transient($tKey);
				if($tries){
					$tries++;
				} else {
					$tries = 1;
				}
				if($tries >= wfConfig::get('loginSec_maxFailures')){
					self::lockOutIP($IP, "Exceeded the maximum number of login failures which is: " . wfConfig::get('loginSec_maxFailures') . ". The last username they tried to sign in with was: '" . $_POST['log'] . "'");
					require('wfLockedOut.php');
				}
				set_transient($tKey, $tries, wfConfig::get('loginSec_countFailMins') * 60);
			} else if(get_class($authResult) == 'WP_User'){
				delete_transient($tKey); //reset counter on success
			}
		}
		if(is_wp_error($authResult) && ($authResult->get_error_code() == 'invalid_username' || $authResult->get_error_code() == 'incorrect_password') && wfConfig::get('loginSec_maskLoginErrors')){
			return new WP_Error( 'incorrect_password', sprintf( __( '<strong>ERROR</strong>: The username or password you entered is incorrect. <a href="%2$s" title="Password Lost and Found">Lost your password</a>?' ), $username, wp_lostpassword_url() ) );
		}
		return $authResult;
	}
	public static function logoutAction(){
		$userID = get_current_user_id();
		$userDat = get_user_by('id', $userID);
		self::getLog()->logLogin('logout', 0, $userDat->user_login); 
	}
	public static function loginInitAction(){
		if(self::isLockedOut(wfUtils::getIP())){
			require('wfLockedOut.php');
		}
	}
	public static function authAction($username){
		if(self::isLockedOut(wfUtils::getIP())){
			require('wfLockedOut.php');
		}
		if(! $username){ return; } 
		$userDat = get_user_by('login', $username);
		if($userDat){
			require_once( ABSPATH . 'wp-includes/class-phpass.php');
			$hasher = new PasswordHash(8, TRUE);
			if(! $hasher->CheckPassword($_POST['pwd'], $userDat->user_pass)){
				self::getLog()->logLogin('loginFailValidUsername', 1, $username); 
			}
		} else {
			self::getLog()->logLogin('loginFailInvalidUsername', 1, $username); 
		}
	}
	public static function getWPFileContent($file, $cType, $cName, $cVersion){
		if($cType == 'plugin'){
			if(preg_match('#^/?wp-content/plugins/[^/]+/#', $file)){
				$file = preg_replace('#^/?wp-content/plugins/[^/]+/#', '', $file);
			} else {
				//If user is using non-standard wp-content dir, then use /plugins/ in pattern to figure out what to strip off
				$file = preg_replace('#^.*[^/]+/plugins/[^/]+/#', '', $file);
			}
		} else if($cType == 'theme'){
			if(preg_match('#/?wp-content/themes/[^/]+/#', $file)){
				$file = preg_replace('#/?wp-content/themes/[^/]+/#', '', $file);
			} else {
				$file = preg_replace('#^.*[^/]+/themes/[^/]+/#', '', $file);
			}
		} else if($cType == 'core'){

		} else {
			return array('errorMsg' => "An invalid type was specified to get file.");
		}
		$api = new wfAPI(wfConfig::get('apiKey'), wfUtils::getWPVersion());
		try {
			$contResult = $api->binCall('get_wp_file_content', array(
				'v' => wfUtils::getWPVersion(),
				'file' => $file,
				'cType' => $cType,
				'cName' => $cName,
				'cVersion' => $cVersion
				));
			if($contResult['data']){
				return array('fileContent' => $contResult['data']);
			} else {
				throw new Exception("We could not fetch a core WordPress file from the Wordfence API.");
			}
		} catch (Exception $e){
			return array('errorMsg' => $e->getMessage());
		}
	}
	public static function ajax_saveScanSchedule_callback(){
		if(! wfConfig::get('isPaid')){
			return array('errorMsg' => "Sorry but this feature is only available for paid customers.");
		}
		$schedDays = explode('|', $_POST['schedTxt']);
		$schedule = array();
		for($day = 0; $day <= 6; $day++){
			$schedule[$day] = explode(',', $schedDays[$day]);
		}
		$schedMode = $_POST['schedMode'];
		wfConfig::set_ser('scanSched', $schedule);
		wfConfig::set('schedMode', $schedMode);
		wordfence::scheduleScans();
		$nextTime = self::getNextScanStartTime();
		return array(
			'ok' => 1,
			'nextStart' => ($nextTime ? $nextTime : '') 
			);
	}
	public static function getNextScanStartTime(){
		$nextTime = false;
		$cron = _get_cron_array(); 
		foreach($cron as $key => $val){
			if(isset($val['wordfence_start_scheduled_scan'])){
				$nextTime = $key;
				break;
			}
		}
		return ($nextTime ? date('l jS \of F Y H:i:s A', $nextTime + (3600 * get_option('gmt_offset'))) : '');
	}
	public static function wordfenceStartScheduledScan(){
		//This prevents scheduled scans from piling up on low traffic blogs and all being run at once.
		//Only one scheduled scan runs within a given 60 min window. Won't run if another scan has run within 30 mins.
		$lastScanStart = wfConfig::get('lastScheduledScanStart', 0);
		if($lastScanStart && (time() - $lastScanStart) < 1800){
			//A scheduled scan was started in the last 30 mins, so skip this one.
			return;
		}
		wfConfig::set('lastScheduledScanStart', time());
		wordfence::status(1, 'info', "Scheduled Wordfence scan starting at " . date('l jS \of F Y h:i:s A', current_time('timestamp')) );
		
		//We call this before the scan actually starts to advance the schedule for the next week.
		//This  ensures that if the scan crashes for some reason, the schedule will hold.
		wordfence::scheduleScans();

		wfScanEngine::startScan();
	}
	public static function scheduleScans(){ //Idempotent. Deschedules everything and schedules the following week.
		self::unscheduleAllScans();
		$sched = wfConfig::get_ser('scanSched', array());
		$mode = wfConfig::get('schedMode');
		if($mode == 'manual' && is_array($sched) && is_array($sched[0]) ){
			//Use sched as it is	
		} else { //Default to setting scans to run once a day at a randomly selected time.
			$sched = array();
			$runAt = rand(0,23);
			for($day = 0; $day <= 6; $day++){
				$sched[$day] = array();
				for($hour = 0; $hour <= 23; $hour++){
					if($hour == $runAt){
						$sched[$day][$hour] = 1;
					} else {
						$sched[$day][$hour] = 0;
					}
				}
			}
		}
		for($scheduledDay = 0; $scheduledDay <= 6; $scheduledDay++){
			//0 is sunday
			//6 is Saturday
			for($scheduledHour = 0; $scheduledHour <= 23; $scheduledHour++){
				if($sched[$scheduledDay][$scheduledHour]){
					$wpTime = current_time('timestamp');
					$currentDayOfWeek = date('w', $wpTime);
					$daysInFuture = $scheduledDay - $currentDayOfWeek; //It's monday and scheduledDay is Wed (3) then result is 2 days in future. It's Wed and sched day is monday, then result is 3 - 1 = -2
					if($daysInFuture < 0){ $daysInFuture += 7; } //Turns -2 into 5 days in future
					$currentHour = date('G', $wpTime);
					$secsOffset = ($scheduledHour - $currentHour) * 3600; //Offset from current hour, can be negative
					$secondsInFuture = ($daysInFuture * 86400) + $secsOffset; //Can be negative, so we schedule those 1 week ahead
					if($secondsInFuture < 1){
						$secondsInFuture += (86400 * 7); //Add a week
					}
					$futureTime = time() - (time() % 3600) + $secondsInFuture; //Modulo rounds down to top of the hour
					$futureTime += rand(0,3600); //Prevent a stampede of scans on our scanning server
					wordfence::status(4, 'info', "Scheduled time for day $scheduledDay hour $scheduledHour is: " . date('l jS \of F Y h:i:s A', $futureTime));
					self::scheduleSingleScan($futureTime);
				}
			}
		}
	}
	private static function scheduleSingleScan($futureTime){
		wp_schedule_single_event($futureTime, 'wordfence_start_scheduled_scan', array($futureTime));
		$schedArgs = wfConfig::get_ser('schedScanArgs', array());
		if(! is_array($schedArgs)){ //paranoia
			$schedArgs = array();
		}
		$schedArgs[] = $futureTime;
		wfConfig::set_ser('schedScanArgs', $schedArgs);
	}
	private static function unscheduleAllScans(){
		wp_clear_scheduled_hook('wordfence_start_scheduled_scan'); //Unschedule legacy scans without args

		$schedArgs = wfConfig::get_ser('schedScanArgs', array());
		if(is_array($schedArgs)){
			foreach($schedArgs as $futureTime){
				wp_clear_scheduled_hook('wordfence_start_scheduled_scan', array($futureTime));
			}
		}
		wfConfig::set_ser('schedScanArgs', array());
	}
	public static function ajax_saveCountryBlocking_callback(){
		if(! wfConfig::get('isPaid')){
			return array('errorMsg' => "Sorry but this feature is only available for paid customers.");
		}
		wfConfig::set('cbl_action', $_POST['blockAction']);
		wfConfig::set('cbl_countries', $_POST['codes']);
		wfConfig::set('cbl_redirURL', $_POST['redirURL']);
		wfConfig::set('cbl_loggedInBlocked', $_POST['loggedInBlocked']);
		wfConfig::set('cbl_loginFormBlocked', $_POST['loginFormBlocked']);
		wfConfig::set('cbl_bypassRedirURL', $_POST['bypassRedirURL']);
		wfConfig::set('cbl_bypassRedirDest', $_POST['bypassRedirDest']);
		wfConfig::set('cbl_bypassViewURL', $_POST['bypassViewURL']);
		return array('ok' => 1);
	}
	public static function ajax_sendActivityLog_callback(){
		$content = "SITE: " . site_url() . "\nPLUGIN VERSION: " . WORDFENCE_VERSION . "\nWP VERSION: " . wfUtils::getWPVersion() . "\nAPI KEY: " . wfConfig::get('apiKey') . "\nADMIN EMAIL: " . get_option('admin_email') . "\nLOG:\n\n";
		$wfdb = new wfDB();
		global $wpdb;
		$p = $wpdb->base_prefix;
		$q = $wfdb->querySelect("select ctime, level, type, msg from $p"."wfStatus order by ctime desc limit 10000");
		$timeOffset = 3600 * get_option('gmt_offset');
		foreach($q as $r){
			if($r['type'] == 'error'){
				$content .= "\n";
			}
			$content .= date(DATE_RFC822, $r['ctime'] + $timeOffset) . '::' . sprintf('%.4f', $r['ctime']) . ':' . $r['level'] . ':' . $r['type'] . '::' . $r['msg'] . "\n";
		}
		$content .= "\n\n";
		
		ob_start();
		phpinfo();
		$phpinfo = ob_get_contents();
		ob_get_clean();

		$content .= $phpinfo;
		
		wp_mail($_POST['email'], "Wordfence Activity Log", $content);	
		return array('ok' => 1);
	}
	public static function ajax_startTourAgain_callback(){
		wfConfig::set('tourClosed', 0);
		return array('ok' => 1);
	}
	public static function ajax_tourClosed_callback(){
		wfConfig::set('tourClosed', 1);
		return array('ok' => 1);
	}
	public static function ajax_saveConfig_callback(){
		$reload = '';
		$opts = wfConfig::parseOptions();
		$emails = array();
		foreach(explode(',', preg_replace('/[\r\n\s\t]+/', '', $opts['alertEmails'])) as $email){
			if(strlen($email) > 0){
				array_push($emails, $email);
			}
		}
		if(sizeof($emails) > 0){
			$badEmails = array();
			foreach($emails as $email){
				if(! preg_match('/^[^@]+@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,8})$/i', $email)){
					array_push($badEmails, $email);
				}
			}
			if(sizeof($badEmails) > 0){
				return array('errorMsg' => "The following emails are invalid: " . implode(', ', $badEmails));
			}
			$opts['alertEmails'] = implode(',', $emails);
		} else {
			$opts['alertEmails'] = '';
		}
		$whiteIPs = array();
		foreach(explode(',', preg_replace('/[\r\n\s\t]+/', '', $opts['whitelisted'])) as $whiteIP){
			if(strlen($whiteIP) > 0){
				array_push($whiteIPs, $whiteIP);
			}
		}
		if(sizeof($whiteIPs) > 0){
			$badWhiteIPs = array();
			foreach($whiteIPs as $whiteIP){
				if(! preg_match('/^[\[\]\-\d]+\.[\[\]\-\d]+\.[\[\]\-\d]+\.[\[\]\-\d]+$/', $whiteIP)){
					array_push($badWhiteIPs, $whiteIP);
				}
			}
			if(sizeof($badWhiteIPs) > 0){
				return array('errorMsg' => "Please make sure you separate your IP addresses with commas. The following whitelisted IP addresses are invalid: " . implode(', ', $badWhiteIPs));
			}
			$opts['whitelisted'] = implode(',', $whiteIPs);
		} else {
			$opts['whitelisted'] = '';
		}
		$validUsers = array();
		$invalidUsers = array();
		foreach(explode(',', $opts['liveTraf_ignoreUsers']) as $val){
			$val = trim($val);
			if(strlen($val) > 0){
				if(get_user_by('login', $val)){
					array_push($validUsers, $val);
				} else {
					array_push($invalidUsers, $val);
				}
			}
		}
		$opts['apiKey'] = trim($opts['apiKey']);
		if($opts['apiKey'] && (! preg_match('/^[a-fA-F0-9]+$/', $opts['apiKey'])) ){ //User entered something but it's garbage.
			return array('errorMsg' => "You entered an API key but it is not in a valid format. It must consist only of characters A to F and 0 to 9.");
		}

		if(sizeof($invalidUsers) > 0){
			return array('errorMsg' => "The following users you selected to ignore in live traffic reports are not valid on this system: " . implode(', ', $invalidUsers));
		}
		if(sizeof($validUsers) > 0){
			$opts['liveTraf_ignoreUsers'] = implode(',', $validUsers);
		} else {
			$opts['liveTraf_ignoreUsers'] = '';
		}

		$validIPs = array();
		$invalidIPs = array();
		foreach(explode(',', preg_replace('/[\r\n\s\t]+/', '', $opts['liveTraf_ignoreIPs'])) as $val){
			if(strlen($val) > 0){
				if(preg_match('/^\d+\.\d+\.\d+\.\d+$/', $val)){
					array_push($validIPs, $val);
				} else {
					array_push($invalidIPs, $val);
				}
			}
		}
		if(sizeof($invalidIPs) > 0){
			return array('errorMsg' => "The following IPs you selected to ignore in live traffic reports are not valid: " . implode(', ', $invalidIPs));
		}
		if(sizeof($validIPs) > 0){
			$opts['liveTraf_ignoreIPs'] = implode(',', $validIPs);
		}
			
		if(preg_match('/[a-zA-Z0-9\d]+/', $opts['liveTraf_ignoreUA'])){
			$opts['liveTraf_ignoreUA'] = trim($opts['liveTraf_ignoreUA']);
		} else {
			$opts['liveTraf_ignoreUA'] = '';
		}
		if(! $opts['other_WFNet']){	
			$wfdb = new wfDB();
			global $wpdb;
			$p = $wpdb->base_prefix;
			$wfdb->queryWrite("delete from $p"."wfBlocks where wfsn=1 and permanent=0");
		}
		if($opts['howGetIPs'] != wfConfig::get('howGetIPs', '')){
			$reload = 'reload';
		}


		foreach($opts as $key => $val){
			if($key != 'apiKey'){ //Don't save API key yet
				wfConfig::set($key, $val);
			}
		}
		
		$paidKeyMsg = false;


		if(! $opts['apiKey']){ //Empty API key (after trim above), then try to get one.
			$api = new wfAPI('', wfUtils::getWPVersion());
			try {
				$keyData = $api->call('get_anon_api_key');
				if($keyData['ok'] && $keyData['apiKey']){
					wfConfig::set('apiKey', $keyData['apiKey']);
					wfConfig::set('isPaid', 0);
					$reload = 'reload';
				} else {
					throw new Exception("We could not understand the Wordfence server's response because it did not contain an 'ok' and 'apiKey' element.");
				}
			} catch(Exception $e){
				return array('errorMsg' => "Your options have been saved, but we encountered a problem. You left your API key blank, so we tried to get you a free API key from the Wordfence servers. However we encountered a problem fetching the free key: " . $e->getMessage());
			}
		} else if($opts['apiKey'] != wfConfig::get('apiKey')){
			$api = new wfAPI($opts['apiKey'], wfUtils::getWPVersion());
			try {
				$res = $api->call('check_api_key', array(), array());
				if($res['ok'] && isset($res['isPaid'])){
					wfConfig::set('apiKey', $opts['apiKey']);
					$reload = 'reload';
					wfConfig::set('isPaid', $res['isPaid']); //res['isPaid'] is boolean coming back as JSON and turned back into PHP struct. Assuming JSON to PHP handles bools.
					if($res['isPaid']){
						$paidKeyMsg = true;
					}
				} else {
					throw new Exception("We could not understand the Wordfence API server reply when updating your API key.");
				}
			} catch (Exception $e){
				return array('errorMsg' => "Your options have been saved. However we noticed you changed your API key and we tried to verify it with the Wordfence servers and received an error: " . $e->getMessage());
			}
		}
		//Clears next scan if scans are disabled. Schedules next scan if enabled.
		if($err){
			return array('errorMsg' => $err);
		} else {
			return array('ok' => 1, 'reload' => $reload, 'paidKeyMsg' => $paidKeyMsg );
		}
	}
	public static function ajax_clearAllBlocked_callback(){
		$op = $_POST['op'];
		$wfLog = self::getLog();
		if($op == 'blocked'){
			wordfence::status(1, 'info', "Ajax request received to unblock All IP's including permanent blocks.");	
			$wfLog->unblockAllIPs();
		} else if($op == 'locked'){
			$wfLog->unlockAllIPs();
		}
		return array('ok' => 1);
	}
	public static function ajax_unlockOutIP_callback(){
		$IP = $_POST['IP'];
		self::getLog()->unlockOutIP($IP);
		return array('ok' => 1);
	}
	public static function ajax_unblockIP_callback(){
		$IP = $_POST['IP'];
		self::getLog()->unblockIP($IP);
		return array('ok' => 1);
	}
	public static function ajax_permBlockIP_callback(){
		$IP = $_POST['IP'];
		self::getLog()->blockIP($IP, "Manual permanent block by admin", false, true);
		return array('ok' => 1);
	}
	public static function ajax_loadStaticPanel_callback(){
		$mode = $_POST['mode'];
		$wfLog = self::getLog();
		if($mode == 'topScanners' || $mode == 'topLeechers'){
			$results = $wfLog->getLeechers($mode);
		} else if($mode == 'blockedIPs'){
			$results = $wfLog->getBlockedIPs();
		} else if($mode == 'lockedOutIPs'){
			$results = $wfLog->getLockedOutIPs();
		} else if($mode == 'throttledIPs'){
			$results = $wfLog->getThrottledIPs();
		}
		return array('ok' => 1, 'results' => $results);
	}
	public static function ajax_loadBlockRanges_callback(){
		$results = self::getLog()->getRanges();
		return array('ok' => 1, 'results' => $results);
	}
	public static function ajax_unblockRange_callback(){
		$id = trim($_POST['id']);
		self::getLog()->unblockRange($id);
		return array('ok' => 1);
	}
	public static function ajax_blockIPUARange_callback(){
		$ipRange = trim($_POST['ipRange']);
		$uaRange = trim($_POST['uaRange']);
		$reason = trim($_POST['reason']);
		if(preg_match('/\|+/', $ipRange . $uaRange)){
			return array('err' => 1, 'errorMsg' => "You are not allowed to include a pipe character \"|\" in your IP range or browser pattern");
		}
		if( (! $ipRange) && wfUtils::isUABlocked($uaRange)){
			return array('err' => 1, 'errorMsg' => "The browser pattern you specified will block you from your own website. We have not accepted this pattern to protect you from being blocked.");
		}
		if($ipRange && (! preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ipRange ))){
			return array('err' => 1, 'errorMsg' => "The IP range you specified is not valid. Please specify an IP range like the following example: \"1.2.3.4 - 1.2.3.8\" without quotes.");
		}
		if($ipRange){
			$ips = explode('-', $ipRange);
			$ip1 = wfUtils::inet_aton($ips[0]);
			$ip2 = wfUtils::inet_aton($ips[1]);
			if($ip1 >= $ip2){
				return array('err' => 1, 'errorMsg' => "The first IP address in your range must be less than the second IP address in your range.");
			}
			$clientIP = wfUtils::inet_aton(wfUtils::getIP());
			if($ip1 <= $clientIP && $ip2 >= $clientIP){
				return array('err' => 1, 'errorMsg' => "You are trying to block yourself. Your IP address is " . wfUtils::getIP() . " which falls into the range $ipRange. This blocking action has been cancelled so that you don't block yourself from your website.");
			}
			$ipRange = $ip1 . '-' . $ip2;
		}
		$range = $ipRange . '|' . $uaRange;
		self::getLog()->blockRange('IU', $range, $reason);
		return array('ok' => 1);
	}
	public static function ajax_whois_callback(){
		require_once('whois/whois.main.php');
		$val = trim($_POST['val']);
		$whois = new Whois();
		$result = $whois->Lookup($val);
		return array('ok' => 1, 'result' => $result);
	}
	public static function ajax_blockIP_callback(){
		$IP = trim($_POST['IP']);
		$perm = $_POST['perm'] == '1' ? true : false;
		if(! preg_match('/^\d+\.\d+\.\d+\.\d+$/', $IP)){
			return array('err' => 1, 'errorMsg' => "Please enter a valid IP address to block.");
		}
		if($IP == wfUtils::getIP()){
			return array('err' => 1, 'errorMsg' => "You can't block your own IP address.");
		}
		if(self::getLog()->isWhitelisted($IP)){
			return array('err' => 1, 'errorMsg' => "The IP address $IP is whitelisted and can't be blocked or it is in a range of internal IP addresses that Wordfence does not block. You can remove this IP from the whitelist on the Wordfence options page.");
		}
		if(wfConfig::get('neverBlockBG') != 'treatAsOtherCrawlers'){ //Either neverBlockVerified or neverBlockUA is selected which means the user doesn't want to block google 
			if(wfCrawl::verifyCrawlerPTR('/googlebot\.com$/i', $IP)){
				return array('err' => 1, 'errorMsg' => "The IP address you're trying to block belongs to Google. Your options are currently set to not block these crawlers. Change this in Wordfence options if you want to manually block Google.");
			}
		}
		self::getLog()->blockIP($IP, $_POST['reason'], false, $perm);
		return array('ok' => 1);
	}
	public static function ajax_reverseLookup_callback(){
		$ips = explode(',', $_POST['ips']);
		$res = array();
		foreach($ips as $ip){
			$res[$ip] = wfUtils::reverseLookup($ip);
		}
		return array('ok' => 1, 'ips' => $res);
	}
	public static function ajax_deleteIssue_callback(){
		$wfIssues = new wfIssues();
		$issueID = $_POST['id'];
		$wfIssues->deleteIssue($issueID);
		return array('ok' => 1);
	}
	public static function ajax_updateAllIssues_callback(){
		$op = $_POST['op'];
		$i = new wfIssues();
		if($op == 'deleteIgnored'){
			$i->deleteIgnored();	
		} else if($op == 'deleteNew'){
			$i->deleteNew();
		} else if($op == 'ignoreAllNew'){
			$i->ignoreAllNew();
		} else {
			return array('errorMsg' => "An invalid operation was called.");
		}
		return array('ok' => 1);
	}
	public static function ajax_updateIssueStatus_callback(){
		$wfIssues = new wfIssues();
		$status = $_POST['status'];
		$issueID = $_POST['id'];
		if(! preg_match('/^(?:new|delete|ignoreP|ignoreC)$/', $status)){
			return array('errorMsg' => "An invalid status was specified when trying to update that issue.");
		}
		$wfIssues->updateIssue($issueID, $status);
		return array('ok' => 1);
	}
	public static function ajax_killScan_callback(){
		wordfence::status(1, 'info', "Scan kill request received.");
		wordfence::status(10, 'info', "SUM_KILLED:A request was received to kill the previous scan.");
		wfUtils::clearScanLock(); //Clear the lock now because there may not be a scan running to pick up the kill request and clear the lock
		wfScanEngine::requestKill();
		return array(
			'ok' => 1,
			);
	}
	public static function ajax_loadIssues_callback(){
		$i = new wfIssues();
		$iss = $i->getIssues();
		return array(
			'issuesLists' => $iss,
			'summary' => $i->getSummaryItems(),
			'lastScanCompleted' => wfConfig::get('lastScanCompleted')
			);
	}
	public static function ajax_ticker_callback(){
		$wfdb = new wfDB();
		global $wpdb;
		$p = $wpdb->base_prefix;

		$serverTime = $wfdb->querySingle("select unix_timestamp()");
		$issues = new wfIssues();
		$jsonData = array(
			'serverTime' => $serverTime,
			'msg' => $wfdb->querySingle("select msg from $p"."wfStatus where level < 3 order by ctime desc limit 1")
			);
		$events = array();
		$alsoGet = $_POST['alsoGet'];
		if(preg_match('/^logList_(404|hit|human|ruser|crawler|gCrawler|loginLogout)$/', $alsoGet, $m)){
			$type = $m[1];
			$newestEventTime = $_POST['otherParams'];
			$listType = 'hits';
			if($type == 'loginLogout'){
				$listType = 'logins';
			}
			$events = self::getLog()->getHits($listType, $type, $newestEventTime);
		}
		$jsonData['events'] = $events;
		$jsonData['alsoGet'] = $alsoGet; //send it back so we don't load data if panel has changed
		return $jsonData;
	}
	public static function ajax_activityLogUpdate_callback(){
		$issues = new wfIssues();
		return array(
			'ok' => 1,
			'items' => self::getLog()->getStatusEvents($_POST['lastctime']),
			'currentScanID' => $issues->getScanTime()
			);
	}
	public static function ajax_deleteFile_callback(){
		$issueID = $_POST['issueID'];
		$wfIssues = new wfIssues();
		$issue = $wfIssues->getIssueByID($issueID);
		if(! $issue){
			return array('errorMsg' => "Could not delete file because we could not find that issue.");
		}
		if(! $issue['data']['file']){
			return array('errorMsg' => "Could not delete file because that issue does not appear to be a file related issue.");
		}
		$file = $issue['data']['file'];
		$localFile = ABSPATH . '/' . preg_replace('/^[\.\/]+/', '', $file);
		$localFile = realpath($localFile);
		if(strpos($localFile, ABSPATH) !== 0){
			return array('errorMsg' => "An invalid file was requested for deletion.");
		}
		if(@unlink($localFile)){
			$wfIssues->updateIssue($issueID, 'delete');
			return array(
				'ok' => 1,
				'localFile' => $localFile,
				'file' => $file
				);
		} else {
			$err = error_get_last();
			return array('errorMsg' => "Could not delete file $file. The error was: " . $err['message']);
		}
	}
	public static function ajax_restoreFile_callback(){
		$issueID = $_POST['issueID'];
		$wfIssues = new wfIssues();
		$issue = $wfIssues->getIssueByID($issueID);
		if(! $issue){
			return array('cerrorMsg' => "We could not find that issue in our database.");
		}
		$dat = $issue['data'];	
		$result = self::getWPFileContent($dat['file'], $dat['cType'], $dat['cName'], $dat['cVersion']);
		$file = $dat['file'];
		if($result['cerrorMsg']){
			return $result;
		} else if(! $result['fileContent']){
			return array('cerrorMsg' => "We could not get the original file to do a repair.");
		}
		
		if(preg_match('/\.\./', $file)){
			return array('cerrorMsg' => "An invalid file was specified for repair.");
		}
		$localFile = ABSPATH . '/' . preg_replace('/^[\.\/]+/', '', $file);
		$fh = fopen($localFile, 'w');
		if(! $fh){
			$err = error_get_last();
			if(preg_match('/Permission denied/i', $err['message'])){
				$errMsg = "You don't have permission to repair that file. You need to either fix the file manually using FTP or change the file permissions and ownership so that your web server has write access to repair the file.";
			} else {
				$errMsg = "We could not write to that file. The error was: " . $err['message'];
			}
			return array('cerrorMsg' => $errMsg);
		}
		flock($fh, LOCK_EX);
		$bytes = fwrite($fh, $result['fileContent']);
		flock($fh, LOCK_UN);
		fclose($fh);
		if($bytes < 1){
			return array('cerrorMsg' => "We could not write to that file. ($bytes bytes written) You may not have permission to modify files on your WordPress server.");
		}
		$wfIssues->updateIssue($issueID, 'delete');
		return array(
			'ok' => 1,
			'file' => $localFile
			);
	}
	public static function ajax_scan_callback(){
		self::status(4, 'info', "Ajax request received to start scan.");
		$err = wfScanEngine::startScan();
		if($err){
			return array('errorMsg' => $err);
		} else {
			return array("ok" => 1);
		}
	}
	public static function startScan(){
		wfScanEngine::startScan();
	}
	public static function templateRedir(){
		$wfFunc = get_query_var('_wfsf');		
		$wfLog = self::getLog();
		if($wfLog->logHitOK()){
			if( (! empty($wfFunc)) && is_404() ){
				$wfLog->logLeechAndBlock('404');
			} else {
				$wfLog->logLeechAndBlock('hit');
			}
			if(wfConfig::get('liveTrafficEnabled')){ 
				self::$hitID = $wfLog->logHit();
				add_action('wp_head', 'wordfence::wp_head');
			}
		}

		if(! ($wfFunc == 'diff' || $wfFunc == 'view' || $wfFunc == 'sysinfo' || $wfFunc == 'conntest' || $wfFunc == 'unknownFiles' || $wfFunc == 'IPTraf' || $wfFunc == 'viewActivityLog' || $wfFunc == 'testmem' || $wfFunc == 'testtime')){
			return;
		}
		if(! wfUtils::isAdmin()){
			return;
		}

		$nonce = $_GET['nonce'];
		if(! wp_verify_nonce($nonce, 'wp-ajax')){
			echo "Bad security token. It may have been more than 12 hours since you reloaded the page you came from. Try reloading the page you came from. If that doesn't work, please sign out and sign-in again.";
			exit(0);
		}
		if($wfFunc == 'diff'){
			self::wfFunc_diff();
		} else if($wfFunc == 'view'){
			self::wfFunc_view();
		} else if($wfFunc == 'sysinfo'){
			require('sysinfo.php');
		} else if($wfFunc == 'conntest'){
			require('conntest.php');
		} else if($wfFunc == 'unknownFiles'){
			require('unknownFiles.php');
		} else if($wfFunc == 'IPTraf'){
			self::wfFunc_IPTraf();
		} else if($wfFunc == 'viewActivityLog'){
			self::wfFunc_viewActivityLog();
		} else if($wfFunc == 'testmem'){
			self::wfFunc_testmem();
		} else if($wfFunc == 'testtime'){
			self::wfFunc_testtime();
		}	
		exit(0);
	}
	public static function memtest_error_handler($errno, $errstr, $errfile, $errline){
		echo "Error received: $errstr\n";
	}
	private static function wfFunc_testtime(){
		header('Content-Type: text/plain');
		@error_reporting(E_ALL);
		wfUtils::iniSet('display_errors','On');
		set_error_handler('wordfence::memtest_error_handler', E_ALL);

		echo "Wordfence process duration benchmarking utility version " . WORDFENCE_VERSION . ".\n";
		echo "This utility tests how long your WordPress host allows a process to run.\n\n--Starting test--\n";
		echo "Starting timed test. This will take at least three minutes. Seconds elapsed are printed below.\nAn error after this line is not unusual. Read it and the elapsed seconds to determine max process running time on your host.\n";
		for($i = 1; $i <= 180; $i++){
			echo "\n$i:";
			for($j = 0; $j < 1000; $j++){
				echo '.';
			}
			flush();
			sleep(1);
		}
		echo "\n--Test complete.--\n\nCongratulations, your web host allows your PHP processes to run at least 3 minutes.\n";
		exit();
	}
	private static function wfFunc_testmem(){
		header('Content-Type: text/plain');
		@error_reporting(E_ALL);
		wfUtils::iniSet('display_errors','On');
		set_error_handler('wordfence::memtest_error_handler', E_ALL);

		echo "Wordfence Memory benchmarking utility version " . WORDFENCE_VERSION . ".\n";
		echo "This utility tests if your WordPress host respects the maximum memory configured\nin their php.ini file, or if they are using other methods to limit your access to memory.\n\n--Starting test--\n";
		echo "Current maximum memory configured in php.ini: " . ini_get('memory_limit') . "\n";
		echo "Current memory usage: " . sprintf('%.2f', memory_get_usage(true) / (1024 * 1024)) . "M\n";
		echo "Setting max memory to 90M.\n";
		wfUtils::iniSet('memory_limit', '90M');
		echo "Starting memory benchmark. Seeing an error after this line is not unusual. Read the error carefully\nto determine how much memory your host allows. We have requested 90 megabytes.\n";
		if(memory_get_usage(true) < 1){
			echo "Exiting test because memory_get_usage() returned a negative number\n";
		}
		if(memory_get_usage(true) > (1024 * 1024 * 1024)){
			echo "Exiting because current memory usage is greater than a gigabyte.\n";
		}
		$arr = array();
		//256 bytes
		$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111222222222222222222233333333333333334444444444444444444444444555555555555666666666666666666";
		$finalUsage = '0';
		while(true){
			if(memory_get_usage(true) > 80 * 1024 * 1024){
				$finalUsage = sprintf('%.2f', (memory_get_usage(true) / 1024 / 1024));
				echo "Completing test after benchmarking up to " . $finalUsage . " megabytes.\n";
				break;
			}
			for($i = 0; $i < 1024; $i++){ //Roughly 1 megabyte if it's 256K and actual array size is 4x data size
				$arr[] = $chars;
			}
		}
		echo "--Test complete.--\n\nCongratulations, your web host allows you to use at least $finalUsage megabytes of memory for each PHP process hosting your WordPress site.\n";
		exit();
	}
	public static function wp_head(){
		$URL = admin_url('admin-ajax.php');
		$URL .= '?action=wordfence_logHuman&hid=' . wfUtils::encrypt(self::$hitID);
		echo '<script type="text/javascript">var src="' . $URL . '"; if(window.location.protocol == "https:"){ src = src.replace("http:", "https:"); } var wfHTImg = new Image();  wfHTImg.src=src;</script>';
	}
	public static function shutdownAction(){
	}
	public static function wfFunc_viewActivityLog(){
		require('viewFullActivityLog.php');
		exit(0);
	}
	public static function wfFunc_IPTraf(){
		$IP = $_GET['IP'];
		$reverseLookup = wfUtils::reverseLookup($IP);
		if(! preg_match('/^\d+\.\d+\.\d+\.\d+$/', $IP)){
			echo "An invalid IP address was specified.";
			exit(0);
		}
		$wfLog = new wfLog(wfConfig::get('apiKey'), wfUtils::getWPVersion());
		$results = array_merge(
			$wfLog->getHits('hits', 'hit', 0, 10000, $IP), 
			$wfLog->getHits('hits', '404', 0, 10000, $IP)
			);
		usort($results, 'wordfence::iptrafsort');
		for($i = 0; $i < sizeof($results); $i++){
			if(array_key_exists($i + 1, $results)){
				$results[$i]['timeSinceLastHit'] = sprintf('%.4f', $results[$i]['ctime'] - $results[$i + 1]['ctime']);
			} else {
				$results[$i]['timeSinceLastHit'] = '';
			}
		}
		require('IPTraf.php');
		exit(0);
	}
	public static function iptrafsort($b, $a){
		if($a['ctime'] == $b['ctime']){ return 0; }
		return ($a['ctime'] < $b['ctime']) ? -1 : 1;
	}
	public static function wfFunc_view(){
		$localFile = ABSPATH . '/' . preg_replace('/^(?:\.\.|[\/]+)/', '', $_GET['file']);
		if(strpos($localFile, '..') !== false){
			echo "Invalid file requested. (Relative paths not allowed)";
			exit();
		}
		$lang = false;
		$cont = @file_get_contents($localFile);
		$isEmpty = false;
		if(! $cont){
			if(file_exists($localFile) && filesize($localFile) === 0){ //There's a remote possibility that very large files on 32 bit systems will return 0 here, but it's about 1 in 2 billion
				$isEmpty = true;
			} else {
				$err = error_get_last();
				echo "We could not open the requested file for reading. The error was: " . $err['message'];
				exit(0);
			}
		}
		$fileMTime = @filemtime($localFile);
		$fileMTime = date('l jS \of F Y h:i:s A', $fileMTime);
		if(wfUtils::fileOver2Gigs($localFile)){ 
			$fileSize = "Greater than 2 Gigs";
		} else {
			$fileSize = @filesize($localFile); //Checked if over 2 gigs above
			$fileSize = number_format($fileSize, 0, '', ',') . ' bytes';
		}

		require 'wfViewResult.php';
		exit(0);
	}
	public static function wfFunc_diff(){
		$result = self::getWPFileContent($_GET['file'], $_GET['cType'], $_GET['cName'], $_GET['cVersion']);
		if($result['errorMsg']){
			echo $result['errorMsg'];
			exit(0);
		} else if(! $result['fileContent']){
			echo "We could not get the contents of the original file to do a comparison.";
			exit(0);
		}

		$localFile = realpath(ABSPATH . '/' . preg_replace('/^[\.\/]+/', '', $_GET['file']));
		$localContents = file_get_contents($localFile);
		if($localContents == $result['fileContent']){
			$diffResult = '';
		} else {
			$diff = new Diff(
				//Treat DOS and Unix files the same
				preg_split("/(?:\r\n|\n)/", $result['fileContent']), 
				preg_split("/(?:\r\n|\n)/", $localContents), 
				array()
				);
			$renderer = new Diff_Renderer_Html_SideBySide;
			$diffResult = $diff->Render($renderer);
		}
		require 'diffResult.php';
		exit(0);
	}
	public static function initAction(){
		global $wp;
		if (!is_object($wp)) return; //Suggested fix for compatability with "Portable phpmyadmin"

		$wp->add_query_var('_wfsf');
		//add_rewrite_rule('wfStaticFunc/([a-zA-Z0-9]+)/?$', 'index.php?wfStaticFunc=' . $matches[1], 'top');
		$cookieName = 'wfvt_' . crc32(site_url());
		$c = isset($_COOKIE[$cookieName]) ? isset($_COOKIE[$cookieName]) : false;
		if($c){
			self::$newVisit = false;
		} else {
			self::$newVisit = true;
		}
		@setcookie($cookieName, uniqid(), time() + 1800, '/');
	}
	public static function admin_init(){
		if(! wfUtils::isAdmin()){ return; }
		foreach(array('activate', 'scan', 'sendActivityLog', 'restoreFile', 'deleteFile', 'removeExclusion', 'activityLogUpdate', 'ticker', 'loadIssues', 'updateIssueStatus', 'deleteIssue', 'updateAllIssues', 'reverseLookup', 'unlockOutIP', 'loadBlockRanges', 'unblockRange', 'blockIPUARange', 'whois', 'unblockIP', 'blockIP', 'permBlockIP', 'loadStaticPanel', 'saveConfig', 'clearAllBlocked', 'killScan', 'saveCountryBlocking', 'saveScanSchedule', 'tourClosed', 'startTourAgain') as $func){
			add_action('wp_ajax_wordfence_' . $func, 'wordfence::ajaxReceiver');
		}

		if(isset($_GET['page']) && preg_match('/^Wordfence/', @$_GET['page']) ){
			wp_enqueue_style('wp-pointer');
			wp_enqueue_script('wp-pointer');
			wp_enqueue_style('wordfence-main-style', wfUtils::getBaseURL() . 'css/main.css', '', WORDFENCE_VERSION);
			wp_enqueue_style('wordfence-colorbox-style', wfUtils::getBaseURL() . 'css/colorbox.css', '', WORDFENCE_VERSION);
			wp_enqueue_style('wordfence-dttable-style', wfUtils::getBaseURL() . 'css/dt_table.css', '', WORDFENCE_VERSION);

			wp_enqueue_script('json2');
			wp_enqueue_script('jquery.tmpl', wfUtils::getBaseURL() . 'js/jquery.tmpl.min.js', array('jquery'), WORDFENCE_VERSION);
			wp_enqueue_script('jquery.colorbox', wfUtils::getBaseURL() . 'js/jquery.colorbox-min.js', array('jquery'), WORDFENCE_VERSION);
			wp_enqueue_script('jquery.dataTables', wfUtils::getBaseURL() . 'js/jquery.dataTables.min.js', array('jquery'), WORDFENCE_VERSION);
			//wp_enqueue_script('jquery.tools', wfUtils::getBaseURL() . 'js/jquery.tools.min.js', array('jquery'));
			wp_enqueue_script('wordfenceAdminjs', wfUtils::getBaseURL() . 'js/admin.js', array('jquery'), WORDFENCE_VERSION);
			self::setupAdminVars();
		} else {
			wp_enqueue_style('wp-pointer');
			wp_enqueue_script('wp-pointer');
			wp_enqueue_script('wordfenceAdminjs', wfUtils::getBaseURL() . 'js/tourTip.js', array('jquery'), WORDFENCE_VERSION);
			self::setupAdminVars();
		}

	}
	private static function setupAdminVars(){
		$updateInt = wfConfig::get('actUpdateInterval', 2);
		if(! preg_match('/^\d+$/', $updateInt)){
			$updateInt = 2;
		}
		$updateInt *= 1000;

		wp_localize_script('wordfenceAdminjs', 'WordfenceAdminVars', array(
			'ajaxURL' => admin_url('admin-ajax.php'),
			'firstNonce' => wp_create_nonce('wp-ajax'),
			'siteBaseURL' => wfUtils::getSiteBaseURL(),
			'debugOn' => wfConfig::get('debugOn', 0),
			'actUpdateInterval' => $updateInt,
			'tourClosed' => wfConfig::get('tourClosed', 0)
			));
	}
	public static function activation_warning(){
		$activationError = get_option('wf_plugin_act_error', '');
		if(strlen($activationError) > 400){
			$activationError = substr($activationError, 0, 400) . '...[output truncated]';
		}
		if($activationError){
			echo '<div id="wordfenceConfigWarning" class="updated fade"><p><strong>Wordfence generated an error on activation. Please report this on <a href="http://www.wordfence.com/forums/" target="_blank">our support forum</a>. The output we received during activation was:</strong> ' . htmlspecialchars($activationError) . '</p></div>';
		}
		delete_option('wf_plugin_act_error');
	}
	public static function noKeyError(){
		echo '<div id="wordfenceConfigWarning" class="fade error"><p><strong>Wordfence could not get an API key from the Wordfence scanning servers when it activated.</strong> You can try to fix this by going to the Wordfence "options" page and hitting "Save Changes". This will cause Wordfence to retry fetching an API key for you. If you keep seeing this error it usually means your WordPress server can\'t connect to our scanning servers. You can try asking your WordPress host to allow your WordPress server to connect to noc1.wordfence.com.</p></div>';
	}
	public static function admin_menus(){
		if(! wfUtils::isAdmin()){ return; }
		$warningAdded = false;
		if(get_option('wf_plugin_act_error', false)){
			if(wfUtils::isAdminPageMU()){
				add_action('network_admin_notices', 'wordfence::activation_warning');
			} else {
				add_action('admin_notices', 'wordfence::activation_warning');
			}
			$warningAdded = true;
		}
		if(! wfConfig::get('apiKey')){
			if(wfUtils::isAdminPageMU()){
				add_action('network_admin_notices', 'wordfence::noKeyError');
			} else {
				add_action('admin_notices', 'wordfence::noKeyError');
			}
			$warningAdded = true;
		}
		/*
		if(is_plugin_active('w3-total-cache/w3-total-cache.php') && wfConfig::get('liveTrafficEnabled')){
			wfConfig::set('liveTrafficEnabled', 0);
			if(wfUtils::isAdminPageMU()){
				add_action('network_admin_notices', 'wordfence::liveTrafficW3TCWarning');
			} else {
				add_action('admin_notices', 'wordfence::liveTrafficW3TCWarning');
			}
		}
		if(is_plugin_active('wp-super-cache/wp-cache.php') && wfConfig::get('liveTrafficEnabled')){
			wfConfig::set('liveTrafficEnabled', 0);
			if(wfUtils::isAdminPageMU()){
				add_action('network_admin_notices', 'wordfence::liveTrafficSuperCacheWarning');
			} else {
				add_action('admin_notices', 'wordfence::liveTrafficSuperCacheWarning');
			}
		}
		*/

		add_submenu_page("Wordfence", "Scan", "Scan", "activate_plugins", "Wordfence", 'wordfence::menu_scan');
		add_menu_page('Wordfence', 'Wordfence', 'activate_plugins', 'Wordfence', 'wordfence::menu_scan', wfUtils::getBaseURL() . 'images/wordfence-logo-16x16.png'); 
		if(wfConfig::get('liveTrafficEnabled')){
			add_submenu_page("Wordfence", "Live Traffic", "Live Traffic", "activate_plugins", "WordfenceActivity", 'wordfence::menu_activity');
		}
		add_submenu_page('Wordfence', 'Blocked IPs', 'Blocked IPs', 'activate_plugins', 'WordfenceBlockedIPs', 'wordfence::menu_blockedIPs');
		add_submenu_page("Wordfence", "Country Blocking", "Country Blocking", "activate_plugins", "WordfenceCountryBlocking", 'wordfence::menu_countryBlocking');
		add_submenu_page("Wordfence", "Scan Schedule", "Scan Schedule", "activate_plugins", "WordfenceScanSchedule", 'wordfence::menu_scanSchedule');
		add_submenu_page("Wordfence", "Whois Lookup", "Whois Lookup", "activate_plugins", "WordfenceWhois", 'wordfence::menu_whois');
		add_submenu_page("Wordfence", "Advanced Blocking", "Advanced Blocking", "activate_plugins", "WordfenceRangeBlocking", 'wordfence::menu_rangeBlocking');
		add_submenu_page("Wordfence", "Options", "Options", "activate_plugins", "WordfenceSecOpt", 'wordfence::menu_options');
	}
	public static function menu_options(){
		require 'menu_options.php';
	}
	public static function menu_blockedIPs(){
		require 'menu_blockedIPs.php';
	}
	public static function menu_scanSchedule(){
		require 'menu_scanSchedule.php';
	}
	public static function menu_countryBlocking(){
		require 'menu_countryBlocking.php';
	}
	public static function menu_whois(){
		require 'menu_whois.php';
	}

	public static function menu_rangeBlocking(){
		require 'menu_rangeBlocking.php';
	}
	public static function liveTrafficW3TCWarning(){
		echo self::cachingWarning("W3 Total Cache");
	}
	public static function liveTrafficSuperCacheWarning(){
		echo self::cachingWarning("WP Super Cache");
	}
	public static function cachingWarning($plugin){
		return '<div id="wordfenceConfigWarning" class="error fade"><p><strong>The Wordfence Live Traffic feature has been disabled because you have ' . $plugin . ' active which is not compatible with Wordfence Live Traffic.</strong> If you want to reenable Wordfence Live Traffic, you need to deactivate ' . $plugin . ' and then go to the Wordfence options page and reenable Live Traffic there. Wordfence does work with ' . $plugin . ', however Live Traffic will be disabled and the Wordfence firewall will also count less hits per visitor because of the ' . $plugin . ' caching function. All other functions should work correctly.</p></div>';
	}
	public static function menu_activity(){
		require 'menu_activity.php';
	}
	public static function menu_scan(){
		require 'menu_scan.php';
	}
	public static function status($level /* 1 has highest visibility */, $type /* info|error */, $msg){
		if($level > 3 && $level < 10 && (! self::isDebugOn())){ //level 10 and higher is for summary messages
			return false;
		}
		if($type != 'info' && $type != 'error'){ error_log("Invalid status type: $type"); return; }
		if(self::$printStatus){
			echo "STATUS: $level : $type : $msg\n";
		} else {
			self::getLog()->addStatus($level, $type, $msg);
		}
	}
	public static function profileUpdateAction($userID, $newDat){
		if(wfConfig::get('other_pwStrengthOnUpdate')){
			$oldDat = get_userdata($userID);
			if($newDat->user_pass != $oldDat->user_pass){
				$wf = new wfScanEngine();	
				$wf->scanUserPassword($userID);
				$wf->emailNewIssues();
			}
		}
	}
	public static function genFilter($gen, $type){
		if(wfConfig::get('other_hideWPVersion')){
			return '';
		} else {
			return $gen;
		}
	}
	public static function preCommentApprovedFilter($approved, $cData){
		if( $approved == 1 && (! is_user_logged_in()) && wfConfig::get('other_noAnonMemberComments') ){
			$user = get_user_by('email', trim($cData['comment_author_email']));
			if($user){
				return 0; //hold for moderation if the user is not signed in but used a members email
			}
		}
		
		if(($approved == 1 || $approved == 0) && wfConfig::get('other_scanComments')){
			$wf = new wfScanEngine();
			try {
				if($wf->isBadComment($cData['comment_author'], $cData['comment_author_email'], $cData['comment_author_url'],  $cData['comment_author_IP'], $cData['comment_content'])){
					return 'spam';
				}
			} catch(Exception $e){
				//This will most likely be an API exception because we can't contact the API, so we ignore it and let the normal comment mechanisms run.
			}
		}
		return $approved;
	}
	public static function getMyHomeURL(){
		return admin_url('admin.php?page=Wordfence', 'http');
	}
	public static function getMyOptionsURL(){
		return admin_url('admin.php?page=WordfenceSecOpt', 'http');
	}

	public static function alert($subject, $alertMsg, $IP){
		$IPMsg = "";
		if($IP){
			$IPMsg = "User IP: $IP\n";
			$reverse = wfUtils::reverseLookup($IP);
			if($reverse){
				$IPMsg .= "User hostname: " . $reverse . "\n";
			}
			$userLoc = wfUtils::getIPGeo($IP);
			if($userLoc){
				$IPMsg .= "User location: ";
				if($userLoc['city']){
					$IPMsg .= $userLoc['city'] . ', ';
				}
				$IPMsg .= $userLoc['countryName'] . "\n";
			}
		}	
		$content = wfUtils::tmpl('email_genericAlert.php', array(
			'subject' => $subject,
			'blogName' => get_bloginfo('name', 'raw'),
			'alertMsg' => $alertMsg,
			'IPMsg' => $IPMsg,
			'date' => wfUtils::localHumanDate(),
			'myHomeURL' => self::getMyHomeURL(),
			'myOptionsURL' => self::getMyOptionsURL()
			));
		$emails = wfConfig::getAlertEmails();
		if(sizeof($emails) < 1){ return; }
		$shortSiteURL = preg_replace('/^https?:\/\//i', '', site_url());
		$subject = "[Wordfence Alert] $shortSiteURL " . $subject;
		wp_mail(implode(',', $emails), $subject, $content);
	}
	private static function getLog(){
		if(! self::$wfLog){
			$wfLog = new wfLog(wfConfig::get('apiKey'), wfUtils::getWPVersion());
			self::$wfLog = $wfLog;
		}
		return self::$wfLog;
	}
	public static function statusPrep(){
		wfConfig::set_ser('wfStatusStartMsgs', array());
		wordfence::status(10, 'info', "SUM_PREP:Preparing a new scan.");
	}
	//In the following functions statusStartMsgs is serialized into the DB so it persists between forks
	public static function statusStart($msg){
		$statusStartMsgs = wfConfig::get_ser('wfStatusStartMsgs', array());
		$statusStartMsgs[] = $msg;
		wfConfig::set_ser('wfStatusStartMsgs', $statusStartMsgs);
		self::status(10, 'info', 'SUM_START:' . $msg);
		return sizeof($statusStartMsgs) - 1;
	}
	public static function statusEnd($idx, $haveIssues, $successFailed = false){
		$statusStartMsgs = wfConfig::get_ser('wfStatusStartMsgs', array());
		if($haveIssues){
			if($successFailed){
				self::status(10, 'info', 'SUM_ENDFAILED:' . $statusStartMsgs[$idx]);
			} else {
				self::status(10, 'info', 'SUM_ENDBAD:' . $statusStartMsgs[$idx]);
			}
		} else {
			if($successFailed){
				self::status(10, 'info', 'SUM_ENDSUCCESS:' . $statusStartMsgs[$idx]);
			} else {
				self::status(10, 'info', 'SUM_ENDOK:' . $statusStartMsgs[$idx]);
			}
		}
		$statusStartMsgs[$idx] = '';
		wfConfig::set_ser('wfStatusStartMsgs', $statusStartMsgs);
	}
	public static function statusEndErr(){
		$statusStartMsgs = wfConfig::get_ser('wfStatusStartMsgs', array());
		for($i = 0; $i < sizeof($statusStartMsgs); $i++){
			if(empty($statusStartMsgs[$i]) === false){
				self::status(10, 'info', 'SUM_ENDERR:' . $statusStartMsgs[$i]);
				$statusStartMsgs[$i] = '';
			}
		}
	}
	public static function statusDisabled($msg){
		self::status(10, 'info', "SUM_DISABLED:" . $msg);
	}
	public static function statusPaidOnly($msg){
		self::status(10, 'info', "SUM_PAIDONLY:" . $msg);
	}
	public static function wfSchemaExists(){
		$db = new wfDB();
		global $wpdb; $prefix = $wpdb->base_prefix;
		$exists = $db->querySingle("show tables like '$prefix"."wfConfig'");
		return $exists ? true : false;
	}
	public static function isDebugOn(){
		if(is_null(self::$debugOn)){
			if(wfConfig::get('debugOn')){
				self::$debugOn = true;
			} else {
				self::$debugOn = false;
			}
		}
		return self::$debugOn;
	}
	/*
	public static function moreCronReccurences(){
		return array(
			'everyminute' => array('interval' => 60, 'display' => 'Once Every Minute'),
		);
	}
	*/
}
?>
