<?php
class wfConfig {
	private static $table = false;
	private static $cache = array();
	private static $DB = false;
	public static $securityLevels = array(
		array( //level 0
			"checkboxes" => array(
				"alertOn_critical" => false,
				"alertOn_warnings" => false,
				"alertOn_throttle" => false,
				"alertOn_block" => false,
				"alertOn_loginLockout" => false,
				"alertOn_lostPasswdForm" => false,
				"alertOn_adminLogin" => false,
				"alertOn_nonAdminLogin" => false,
				"liveTrafficEnabled" => true,
				"liveTraf_ignorePublishers" => true,
				"scheduledScansEnabled" => false,
				"scansEnabled_core" => false,
				"scansEnabled_themes" => false,
				"scansEnabled_plugins" => false,
				"scansEnabled_malware" => false,
				"scansEnabled_fileContents" => false,
				"scansEnabled_posts" => false,
				"scansEnabled_comments" => false,
				"scansEnabled_passwds" => false,
				"scansEnabled_diskSpace" => false,
				"scansEnabled_dns" => false,
				"scansEnabled_oldVersions" => false,
				"firewallEnabled" => false,
				"blockFakeBots" => false,
				"autoBlockScanners" => false,
				"loginSecurityEnabled" => false,
				"loginSec_lockInvalidUsers" => false,
				"loginSec_maskLoginErrors" => false,
				"other_hideWPVersion" => false,
				"other_noAnonMemberComments" => false,
				"other_scanComments" => false,
				"other_pwStrengthOnUpdate" => false,
				"other_WFNet" => true
			),
			"otherParams" => array(
				'securityLevel' => '0',
				"alertEmails" => "", "liveTraf_ignoreUsers" => "", "liveTraf_ignoreIPs" => "", "liveTraf_ignoreUA" => "", "apiKey" => "",
				"liveTraf_hitsMaxSize" => 10,
				"neverBlockBG" => "neverBlockVerified",
				"loginSec_countFailMins" => "5",
				"loginSec_lockoutMins" => "5",
				'loginSec_maxFailures' => "5",
				'loginSec_maxForgotPasswd' => "5",
				'maxGlobalRequests' => "DISABLED",
				'maxGlobalRequests_action' => "throttle",
				'maxRequestsCrawlers' => "DISABLED",
				'maxRequestsCrawlers_action' => "throttle",
				'maxRequestsHumans' => "DISABLED",
				'maxRequestsHumans_action' => "throttle",
				'max404Crawlers' => "DISABLED",
				'max404Crawlers_action' => "throttle",
				'max404Humans' => "DISABLED",
				'max404Humans_action' => "throttle",
				'maxScanHits' => "DISABLED",
				'maxScanHits_action' => "throttle",
				'blockedTime' => "300"
			)
		),
		array( //level 1
			"checkboxes" => array(
				"alertOn_critical" => true,
				"alertOn_warnings" => false,
				"alertOn_throttle" => false,
				"alertOn_block" => false,
				"alertOn_loginLockout" => false,
				"alertOn_lostPasswdForm" => false,
				"alertOn_adminLogin" => false,
				"alertOn_nonAdminLogin" => false,
				"liveTrafficEnabled" => true,
				"liveTraf_ignorePublishers" => true,
				"scheduledScansEnabled" => true,
				"scansEnabled_core" => true,
				"scansEnabled_themes" => false,
				"scansEnabled_plugins" => false,
				"scansEnabled_malware" => true,
				"scansEnabled_fileContents" => true,
				"scansEnabled_posts" => true,
				"scansEnabled_comments" => true,
				"scansEnabled_passwds" => true,
				"scansEnabled_diskSpace" => true,
				"scansEnabled_dns" => true,
				"scansEnabled_oldVersions" => true,
				"firewallEnabled" => true,
				"blockFakeBots" => false,
				"autoBlockScanners" => true,
				"loginSecurityEnabled" => true,
				"loginSec_lockInvalidUsers" => false,
				"loginSec_maskLoginErrors" => true,
				"other_hideWPVersion" => true,
				"other_noAnonMemberComments" => true,
				"other_scanComments" => true,
				"other_pwStrengthOnUpdate" => true,
				"other_WFNet" => true
			),
			"otherParams" => array(
				'securityLevel' => '1',
				"alertEmails" => "", "liveTraf_ignoreUsers" => "", "liveTraf_ignoreIPs" => "", "liveTraf_ignoreUA" => "",  "apiKey" => "",
				"liveTraf_hitsMaxSize" => 10,
				"neverBlockBG" => "neverBlockVerified",
				"loginSec_countFailMins" => "5",
				"loginSec_lockoutMins" => "5",
				'loginSec_maxFailures' => "10",
				'loginSec_maxForgotPasswd' => "10",
				'maxGlobalRequests' => "960",
				'maxGlobalRequests_action' => "throttle",
				'maxRequestsCrawlers' => "960",
				'maxRequestsCrawlers_action' => "throttle",
				'maxRequestsHumans' => "60",
				'maxRequestsHumans_action' => "throttle",
				'max404Crawlers' => "240",
				'max404Crawlers_action' => "throttle",
				'max404Humans' => "60",
				'max404Humans_action' => "throttle",
				'maxScanHits' => "60",
				'maxScanHits_action' => "throttle",
				'blockedTime' => "3600"
			)
		),
		array( //level 2
			"checkboxes" => array(
				"alertOn_critical" => true,
				"alertOn_warnings" => true,
				"alertOn_throttle" => false,
				"alertOn_block" => false,
				"alertOn_loginLockout" => false,
				"alertOn_lostPasswdForm" => false,
				"alertOn_adminLogin" => false,
				"alertOn_nonAdminLogin" => false,
				"liveTrafficEnabled" => true,
				"liveTraf_ignorePublishers" => true,
				"scheduledScansEnabled" => true,
				"scansEnabled_core" => true,
				"scansEnabled_themes" => false,
				"scansEnabled_plugins" => false,
				"scansEnabled_malware" => true,
				"scansEnabled_fileContents" => true,
				"scansEnabled_posts" => true,
				"scansEnabled_comments" => true,
				"scansEnabled_passwds" => true,
				"scansEnabled_diskSpace" => true,
				"scansEnabled_dns" => true,
				"scansEnabled_oldVersions" => true,
				"firewallEnabled" => true,
				"blockFakeBots" => true,
				"autoBlockScanners" => true,
				"loginSecurityEnabled" => true,
				"loginSec_lockInvalidUsers" => false,
				"loginSec_maskLoginErrors" => true,
				"other_hideWPVersion" => true,
				"other_noAnonMemberComments" => true,
				"other_scanComments" => true,
				"other_pwStrengthOnUpdate" => true,
				"other_WFNet" => true
			),
			"otherParams" => array(
				'securityLevel' => '2',
				"alertEmails" => "", "liveTraf_ignoreUsers" => "", "liveTraf_ignoreIPs" => "", "liveTraf_ignoreUA" => "",  "apiKey" => "",
				"liveTraf_hitsMaxSize" => 10,
				"neverBlockBG" => "neverBlockVerified",
				"loginSec_countFailMins" => "240",
				"loginSec_lockoutMins" => "240",
				'loginSec_maxFailures' => "3",
				'loginSec_maxForgotPasswd' => "5",
				'maxGlobalRequests' => "960",
				'maxGlobalRequests_action' => "throttle",
				'maxRequestsCrawlers' => "960",
				'maxRequestsCrawlers_action' => "throttle",
				'maxRequestsHumans' => "120",
				'maxRequestsHumans_action' => "throttle",
				'max404Crawlers' => "240",
				'max404Crawlers_action' => "throttle",
				'max404Humans' => "30",
				'max404Humans_action' => "throttle",
				'maxScanHits' => "15",
				'maxScanHits_action' => "throttle",
				'blockedTime' => "7200"
			)
		),
		array( //level 3
			"checkboxes" => array(
				"alertOn_critical" => true,
				"alertOn_warnings" => true,
				"alertOn_throttle" => false,
				"alertOn_block" => false,
				"alertOn_loginLockout" => false,
				"alertOn_lostPasswdForm" => false,
				"alertOn_adminLogin" => false,
				"alertOn_nonAdminLogin" => false,
				"liveTrafficEnabled" => true,
				"liveTraf_ignorePublishers" => true,
				"scheduledScansEnabled" => true,
				"scansEnabled_core" => true,
				"scansEnabled_themes" => false,
				"scansEnabled_plugins" => false,
				"scansEnabled_malware" => true,
				"scansEnabled_fileContents" => true,
				"scansEnabled_posts" => true,
				"scansEnabled_comments" => true,
				"scansEnabled_passwds" => true,
				"scansEnabled_diskSpace" => true,
				"scansEnabled_dns" => true,
				"scansEnabled_oldVersions" => true,
				"firewallEnabled" => true,
				"blockFakeBots" => true,
				"autoBlockScanners" => true,
				"loginSecurityEnabled" => true,
				"loginSec_lockInvalidUsers" => false,
				"loginSec_maskLoginErrors" => true,
				"other_hideWPVersion" => true,
				"other_noAnonMemberComments" => true,
				"other_scanComments" => true,
				"other_pwStrengthOnUpdate" => true,
				"other_WFNet" => true
			),
			"otherParams" => array(
				'securityLevel' => '3',
				"alertEmails" => "", "liveTraf_ignoreUsers" => "", "liveTraf_ignoreIPs" => "", "liveTraf_ignoreUA" => "",  "apiKey" => "",
				"liveTraf_hitsMaxSize" => 10,
				"neverBlockBG" => "neverBlockVerified",
				"loginSec_countFailMins" => "1440",
				"loginSec_lockoutMins" => "1440",
				'loginSec_maxFailures' => "3",
				'loginSec_maxForgotPasswd' => "3",
				'maxGlobalRequests' => "960",
				'maxGlobalRequests_action' => "throttle",
				'maxRequestsCrawlers' => "960",
				'maxRequestsCrawlers_action' => "throttle",
				'maxRequestsHumans' => "60",
				'maxRequestsHumans_action' => "block",
				'max404Crawlers' => "60",
				'max404Crawlers_action' => "block",
				'max404Humans' => "30",
				'max404Humans_action' => "block",
				'maxScanHits' => "10",
				'maxScanHits_action' => "block",
				'blockedTime' => "86400"
			)
		),
		array( //level 4
			"checkboxes" => array(
				"alertOn_critical" => true,
				"alertOn_warnings" => true,
				"alertOn_throttle" => false,
				"alertOn_block" => false,
				"alertOn_loginLockout" => false,
				"alertOn_lostPasswdForm" => false,
				"alertOn_adminLogin" => false,
				"alertOn_nonAdminLogin" => false,
				"liveTrafficEnabled" => true,
				"liveTraf_ignorePublishers" => true,
				"scheduledScansEnabled" => true,
				"scansEnabled_core" => true,
				"scansEnabled_themes" => false,
				"scansEnabled_plugins" => false,
				"scansEnabled_malware" => true,
				"scansEnabled_fileContents" => true,
				"scansEnabled_posts" => true,
				"scansEnabled_comments" => true,
				"scansEnabled_passwds" => true,
				"scansEnabled_diskSpace" => true,
				"scansEnabled_dns" => true,
				"scansEnabled_oldVersions" => true,
				"firewallEnabled" => true,
				"blockFakeBots" => true,
				"autoBlockScanners" => true,
				"loginSecurityEnabled" => true,
				"loginSec_lockInvalidUsers" => true,
				"loginSec_maskLoginErrors" => true,
				"other_hideWPVersion" => true,
				"other_noAnonMemberComments" => true,
				"other_scanComments" => true,
				"other_pwStrengthOnUpdate" => true,
				"other_WFNet" => true
			),
			"otherParams" => array(
				'securityLevel' => '4',
				"alertEmails" => "", "liveTraf_ignoreUsers" => "", "liveTraf_ignoreIPs" => "", "liveTraf_ignoreUA" => "",  "apiKey" => "",
				"liveTraf_hitsMaxSize" => 10,
				"neverBlockBG" => "neverBlockVerified",
				"loginSec_countFailMins" => "1440",
				"loginSec_lockoutMins" => "1440",
				'loginSec_maxFailures' => "3",
				'loginSec_maxForgotPasswd' => "3",
				'maxGlobalRequests' => "960",
				'maxGlobalRequests_action' => "throttle",
				'maxRequestsCrawlers' => "960",
				'maxRequestsCrawlers_action' => "throttle",
				'maxRequestsHumans' => "30",
				'maxRequestsHumans_action' => "block",
				'max404Crawlers' => "10",
				'max404Crawlers_action' => "block",
				'max404Humans' => "5",
				'max404Humans_action' => "block",
				'maxScanHits' => "2",
				'maxScanHits_action' => "block",
				'blockedTime' => "86400"
			)
		)
	);
	public static function setDefaults(){
		foreach(self::$securityLevels[2]['checkboxes'] as $key => $val){
			if(self::get($key) === false){
				self::set($key, $val ? '1' : '0');
			}
		}
		foreach(self::$securityLevels[2]['otherParams'] as $key => $val){
			if(self::get($key) === false){
				self::set($key, $val);
			}
		}
		self::set('encKey', substr(wfUtils::bigRandomHex(),0 ,16) );
		if(! self::get('isPaid', false)){
			self::set('isPaid', 'free');
		}
	}
	public static function parseOptions(){
		$ret = array();
		foreach(self::$securityLevels[2]['checkboxes'] as $key => $val){ //value is not used. We just need the keys for validation
			$ret[$key] = isset($_POST[$key]) ? '1' : '0';
		}
		foreach(self::$securityLevels[2]['otherParams'] as $key => $val){
			if(isset($_POST[$key])){
				$ret[$key] = $_POST[$key];
			} else {
				error_log("Missing options param \"$key\" when parsing parameters.");
			}
		}
		/* for debugging only:
		foreach($_POST as $key => $val){
			if($key != 'action' && $key != 'nonce' && (! array_key_exists($key, self::$checkboxes)) && (! array_key_exists($key, self::$otherParams)) ){
				error_log("Unrecognized option: $key");
			}
		}
		*/
		return $ret;
	}
	public static function setArray($arr){
		foreach($arr as $key => $val){
			self::set($key, $val);
		}
	}
	public static function clearCache(){
		self::$cache = array();
	}
	public static function set($key, $val){
		if(is_array($val)){
			$trace=debug_backtrace(); $caller=array_shift($trace); error_log("wfConfig::set() got array as second param. Please use ser_ser(). " . $caller['file'] . " line " . $caller['line']);	
		}

		self::getDB()->query("insert into " . self::table() . " (name, val) values ('%s', '%s') ON DUPLICATE KEY UPDATE val='%s'", $key, $val, $val);
		self::$cache[$key] = $val;
	}
	public static function getHTML($key){
		return htmlspecialchars(self::get($key));
	}
	public static function get($key, $default = false){
		if(! isset(self::$cache[$key])){ 
			$val = self::getDB()->querySingle("select val from " . self::table() . " where name='%s'", $key);
			if($val){
				self::$cache[$key] = $val;
			} else {
				self::$cache[$key] = $default;
			}
		}
		return self::$cache[$key];
	}
	public static function get_ser($key, $default){
		$val = self::get($key, $default);
		if($val){
			$val = unserialize($val);
		}
		return $val;
	}
	public static function set_ser($key, $val){
		return self::set($key, serialize($val));
	}
	public static function f($key){
		echo esc_attr(self::get($key));
	}
	public static function cb($key){
		if(self::get($key)){
			echo ' checked ';
		}
	}
	public static function sel($key, $val, $isDefault = false){
		if((! self::get($key)) && $isDefault){ echo ' selected '; }
		if(self::get($key) == $val){ echo ' selected '; }
	}
	public static function getArray(){
		$ret = array();
		$q = self::getDB()->query("select name, val from " . self::table());
		while($row = mysql_fetch_assoc($q)){
			self::$cache[$row['name']] = $row['val'];
		}
		return self::$cache;
	}
	private static function getDB(){
		if(! self::$DB){ 
			self::$DB = new wfDB();
		}
		return self::$DB;
	}
	private static function table(){
		if(! self::$table){
			global $wpdb;
			self::$table = $wpdb->prefix . 'wfConfig';
		}
		return self::$table;
	}
	public static function haveAlertEmails(){
		$emails = self::getAlertEmails();
		return sizeof($emails) > 0 ? true : false;
	}
	public static function getAlertEmails(){
		$dat = explode(',', self::get('alertEmails'));
		$emails = array();
		foreach($dat as $email){
			if(preg_match('/\@/', $email)){
				$emails[] = $email;
			}
		}
		return $emails;
	}
	public static function getAlertLevel(){
		if(self::get('alertOn_warnings')){
			return 2;
		} else if(self::get('alertOn_critical')){
			return 1;
		} else {
			return 0;
		}
	}
}
?>
