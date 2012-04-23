<?php
require_once('wfDB.php');
require_once('wfUtils.php');
require_once('wfBrowscap.php');
class wfLog {
	private $hitsTable = '';
	private $locsTable = '';
	private $apiKey = '';
	private $wp_version = '';
	private $db = false;
	private $googlePattern = '/\.(?:googlebot\.com|google\.[a-z]{2,3}|google\.[a-z]{2}\.[a-z]{2}|1e100\.net)$/i';
	private static $gbSafeCache = array();
	public function __construct($apiKey, $wp_version){
		$this->apiKey = $apiKey;
		$this->wp_version = $wp_version;
		global $wpdb;
		$this->hitsTable = $wpdb->prefix . 'wfHits';
		$this->loginsTable = $wpdb->prefix . 'wfLogins';
		$this->locsTable = $wpdb->prefix . 'wfLocs';
		$this->blocksTable = $wpdb->prefix . 'wfBlocks';
		$this->lockOutTable = $wpdb->prefix . 'wfLockedOut';
		$this->leechTable = $wpdb->prefix . 'wfLeechers';
		$this->badLeechersTable = $wpdb->prefix . 'wfBadLeechers';
		$this->scanTable = $wpdb->prefix . 'wfScanners';
		$this->reverseTable = $wpdb->prefix . 'wfReverseCache';
		$this->throttleTable = $wpdb->prefix . 'wfThrottleLog';
		$this->statusTable = $wpdb->prefix . 'wfStatus';
	}
	public function logLogin($action, $fail, $username){
		$user = get_user_by('login', $username);
		$userID = 0;
		if($user){
			$userID = $user->ID;
		}
		$this->getDB()->query("insert into " . $this->loginsTable . " (ctime, fail, action, username, userID, IP, UA) values (%f, %d, '%s', '%s', %s, %s, '%s')", 
			sprintf('%.6f', microtime(true)),
			$fail,
			$action,
			$username,
			$userID,
			wfUtils::inet_aton(wfUtils::getIP()),
			(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '')
			);
	}
	private function getCurrentUserID(){
		$id = get_current_user_id();
		return $id ? $id : 0;
	}
	private function getPagename(){
		global $wp_query;
		$post = $wp_query->get_queried_object();
		$pagename = $post->post_name;
		return $pagename;
	}
	public function logLeechAndBlock($type){ //404 or hit
		if($type == '404'){
			$table = $this->scanTable;
		} else if($type == 'hit'){
			$table = $this->leechTable;
		} else {
			wfUtils::wdie("Invalid type to logLeechAndBlock(): $type");
		}
		$IP = wfUtils::getIP();
		$this->getDB()->query("insert into $table (eMin, IP, hits) values (floor(unix_timestamp() / 60), %s, 1) ON DUPLICATE KEY update hits = IF(@wfcurrenthits := hits + 1, hits + 1, hits + 1)", wfUtils::inet_aton($IP)); 
		$hitsPerMinute = $this->getDB()->querySingle("select @wfcurrenthits");
		if(wfConfig::get('firewallEnabled')){
			if(wfConfig::get('blockFakeBots')){
				if(wfCrawl::isGoogleCrawler() && (! wfCrawl::verifyCrawlerPTR($this->googlePattern, $IP) )){
					wordfence::status(2, 'info', "Blocking fake Googlebot at IP $IP");
					$this->blockIP($IP, "Fake Google crawler automatically blocked");
				}
			}

			if(wfConfig::get('maxGlobalRequests') != 'DISABLED' && $hitsPerMinute > wfConfig::get('maxGlobalRequests')){ //Applies to 404 or pageview
				$this->takeBlockingAction('maxGlobalRequests', "Exceeded the maximum global requests per minute for crawlers or humans.");
			}
			if($type == '404'){
				global $wpdb; $p = $wpdb->prefix;
				if(wfConfig::get('other_WFNet')){
					$this->getDB()->query("insert IGNORE into $p"."wfNet404s (sig, ctime, URI) values (UNHEX(MD5('%s')), unix_timestamp(), '%s')", $_SERVER['REQUEST_URI'], $_SERVER['REQUEST_URI']);
				}
				$pat = wfConfig::get('vulnRegex');
				if($pat){
					$URL = wfUtils::getRequestedURL();
					if(preg_match($pat, $URL)){
						$this->getDB()->query("insert IGNORE into $p"."wfVulnScanners (IP, ctime, hits) values (INET_ATON('%s'), unix_timestamp(), 1) ON DUPLICATE KEY UPDATE ctime = unix_timestamp, hits = hits + 1", $IP);
						if(wfConfig::get('maxScanHits') != 'DISABLED'){
							if( empty($_SERVER['HTTP_REFERER'] )){
								$this->getDB()->query("insert into " . $this->badLeechersTable . " (eMin, IP, hits) values (floor(unix_timestamp() / 60), %s, 1) ON DUPLICATE KEY update hits = IF(@wfblcurrenthits := hits + 1, hits + 1, hits + 1)", wfUtils::inet_aton($IP)); 
								$BL_hitsPerMinute = $this->getDB()->querySingle("select @wfblcurrenthits");
								if($BL_hitsPerMinute > wfConfig::get('maxScanHits')){
									$this->takeBlockingAction('maxScanHits', "Exceeded the maximum number of 404 requests per minute for a known security vulnerability.");
								}
							}
						}
					}
				}
			}
			if(wfCrawl::isCrawler($_SERVER['HTTP_USER_AGENT'])){
				if($type == 'hit' && wfConfig::get('maxRequestsCrawlers') != 'DISABLED' && $hitsPerMinute > wfConfig::get('maxRequestsCrawlers')){
					$this->takeBlockingAction('maxRequestsCrawlers', "Exceeded the maximum number of requests per minute for crawlers."); //may not exit
				} else if($type == '404' && wfConfig::get('max404Crawlers') != 'DISABLED' && $hitsPerMinute > wfConfig::get('max404Crawlers')){
					$this->takeBlockingAction('max404Crawlers', "Exceeded the maximum number of page not found errors per minute for a crawler.");
				}
			} else {
				if($type == 'hit' && wfConfig::get('maxRequestsHumans') != 'DISABLED' && $hitsPerMinute > wfConfig::get('maxRequestsHumans')){
					$this->takeBlockingAction('maxRequestsHumans', "Exceeded the maximum number of page requests per minute for humans.");
				} else if($type == '404' && wfConfig::get('max404Humans') != 'DISABLED' && $hitsPerMinute > wfConfig::get('max404Humans')){
					$this->takeBlockingAction('max404Humans', "Exceeded the maximum number of page not found errors per minute for humans.");
				}
			}
		}
	}
	public function unblockAllIPs(){
		$this->getDB()->query("delete from " . $this->blocksTable);
	}
	public function unlockAllIPs(){
		$this->getDB()->query("delete from " . $this->lockOutTable);
	}
	public function unblockIP($IP){
		$this->getDB()->query("delete from " . $this->blocksTable . " where IP=%s", wfUtils::inet_aton($IP));
	}
	public function blockIP($IP, $reason, $wfsn = false){				
		$wfsn = $wfsn ? 1 : 0;
		$this->getDB()->query("insert into " . $this->blocksTable . " (IP, blockedTime, reason, wfsn) values (%s, unix_timestamp(), '%s', %d) ON DUPLICATE KEY update blockedTime=unix_timestamp(), reason='%s', wfsn=%d",
			wfUtils::inet_aton($IP),
			$reason,
			$wfsn,
			$reason,
			$wfsn
			);
	}
	public function lockOutIP($IP, $reason){
		$this->getDB()->query("insert into " . $this->lockOutTable . " (IP, blockedTime, reason) values(%s, unix_timestamp(), '%s') ON DUPLICATE KEY update blockedTime=unix_timestamp(), reason='%s'",
			wfUtils::inet_aton($IP),
			$reason,
			$reason
			);
	}
	public function unlockOutIP($IP){
		$this->getDB()->query("delete from " . $this->lockOutTable . " where IP=%s", wfUtils::inet_aton($IP));
	}
	public function isIPLockedOut($IP){
		if($this->getDB()->querySingle("select IP from " . $this->lockOutTable . " where IP=%s and blockedTime + %s > unix_timestamp()", wfUtils::inet_aton($IP), wfConfig::get('loginSec_lockoutMins') * 60)){
			$this->getDB()->query("update " . $this->lockOutTable . " set blockedHits = blockedHits + 1, lastAttempt = unix_timestamp() where IP=%s", wfUtils::inet_aton($IP));
			return true;
		} else {
			return false;
		}
	}
	public function getThrottledIPs(){
		$res = $this->getDB()->query("select IP, startTime, endTime, timesThrottled, lastReason, unix_timestamp() - startTime as startTimeAgo, unix_timestamp() - endTime as endTimeAgo from " . $this->throttleTable . " order by endTime desc limit 50");
		$results = array();
		while($elem = mysql_fetch_assoc($res)){			
			$elem['startTimeAgo'] = wfUtils::makeTimeAgo($elem['startTimeAgo']);
			$elem['endTimeAgo'] = wfUtils::makeTimeAgo($elem['endTimeAgo']);
			array_push($results, $elem);
		}
		$this->resolveIPs($results);
		foreach($results as &$elem){
			$elem['IP'] = wfUtils::inet_ntoa($elem['IP']);
		}
		return $results;
	}
	public function getLockedOutIPs(){
		$res = $this->getDB()->query("select IP, unix_timestamp() - blockedTime as createdAgo, reason, unix_timestamp() - lastAttempt as lastAttemptAgo, lastAttempt, blockedHits, (blockedTime + %s) - unix_timestamp() as blockedFor from " . $this->lockOutTable . " where blockedTime + %s > unix_timestamp() order by blockedTime desc", wfConfig::get('blockedTime'), wfConfig::get('blockedTime'));
		$results = array();
		while($elem = mysql_fetch_assoc($res)){			
			$elem['lastAttemptAgo'] = $elem['lastAttempt'] ? wfUtils::makeTimeAgo($elem['lastAttemptAgo']) : '';
			$elem['blockedForAgo'] = wfUtils::makeTimeAgo($elem['blockedFor']);
			array_push($results, $elem);
		}
		$this->resolveIPs($results);
		foreach($results as &$elem){
			$elem['IP'] = wfUtils::inet_ntoa($elem['IP']);
		}
		return $results;
	}
	public function getBlockedIPs(){
		$res = $this->getDB()->query("select IP, unix_timestamp() - blockedTime as createdAgo, reason, unix_timestamp() - lastAttempt as lastAttemptAgo, lastAttempt, blockedHits, (blockedTime + %s) - unix_timestamp() as blockedFor from " . $this->blocksTable . " where blockedTime + %s > unix_timestamp() order by blockedTime desc", wfConfig::get('blockedTime'), wfConfig::get('blockedTime'));
		$results = array();
		while($elem = mysql_fetch_assoc($res)){			
			$lastHitAgo = 0;
			$totalHits = 0;
			$lastLeech = $this->getDB()->querySingleRec("select unix_timestamp() as serverTime, max(eMin) * 60 as lastHit, sum(hits) as totalHits from " . $this->leechTable . " where IP=%s", $elem['IP']);
			if($lastLeech){ $totalHits += $lastLeech['totalHits']; $lastHitAgo = $lastLeech['serverTime'] - $lastLeech['lastHit']; }
			$lastScan = $this->getDB()->querySingleRec("select unix_timestamp() as serverTime, max(eMin) * 60 as lastHit, sum(hits) as totalHits from " . $this->scanTable . " where IP=%s", $elem['IP']);
			if($lastScan){ 
				$totalHits += $lastScan['totalHits'];
				$ago = $lastScan['serverTime'] - $lastScan['lastHit']; 
				if($ago < $lastHitAgo){
					$lastHitAgo = $ago;
				}
			}
			$elem['totalHits'] = $totalHits;
			$elem['lastHitAgo'] = $lastHitAgo ? wfUtils::makeTimeAgo($lastHitAgo) : '';
			$elem['lastAttemptAgo'] = $elem['lastAttempt'] ? wfUtils::makeTimeAgo($elem['lastAttemptAgo']) : '';
			$elem['blockedForAgo'] = wfUtils::makeTimeAgo($elem['blockedFor']);
			array_push($results, $elem);
		}
		$this->resolveIPs($results);
		foreach($results as &$elem){
			$elem['blocked'] = 1;
			$elem['IP'] = wfUtils::inet_ntoa($elem['IP']);
		}
		return $results;
	}
	public function getLeechers($type){
		if($type == 'topScanners'){
			$table = $this->scanTable;
		} else if($type == 'topLeechers'){
			$table = $this->leechTable;
		} else {
			wfUtils::wdie("Invalid type to getLeechers(): $type");
		}
		$res = $this->getDB()->query("select IP, sum(hits) as totalHits from $table where eMin > ((unix_timestamp() - 86400) / 60) group by IP order by totalHits desc limit 20");
		$results = array();
		while($elem = mysql_fetch_assoc($res)){			
			array_push($results, $elem);
		}
		$this->resolveIPs($results);
		foreach($results as &$elem){
			$elem['timeAgo'] = wfUtils::makeTimeAgo($this->getDB()->querySingle("select unix_timestamp() - (eMin * 60) from $table where IP=%s", $elem['IP']));
			$elem['blocked'] = $this->getDB()->querySingle("select blockedTime from " . $this->blocksTable . " where IP=%s and blockedTime + %s > unix_timestamp()", $elem['IP'], wfConfig::get('blockedTime'));
			//take action
			$elem['IP'] = wfUtils::inet_ntoa($elem['IP']);
		}
		return $results;
	}
	public function logHit(){
		if(! wfConfig::get('liveTrafficEnabled')){ return; }	
		$headers = array();
		foreach($_SERVER as $h=>$v){
			if(preg_match('/^HTTP_(.+)$/', $h, $matches) ){
				$headers[$matches[1]] = $v;
			}
		}
		$this->getDB()->query("insert into " . $this->hitsTable . " (ctime, is404, isGoogle, IP, userID, newVisit, URL, referer, UA, HTTPHeaders) values (%f, %d, %d, %s, %s, %d, '%s', '%s', '%s', '%s')", 
			sprintf('%.6f', microtime(true)),
			(is_404() ? 1 : 0),
			(wfCrawl::isGoogleCrawler() ? 1 : 0),
			wfUtils::inet_aton(wfUtils::getIP()),
			$this->getCurrentUserID(),
			(wordfence::$newVisit ? 1 : 0),
			wfUtils::getRequestedURL(),
			(isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : ''),
			(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''),
			serialize($headers)
			);
		return $this->getDB()->querySingle("select last_insert_id()");
	}
	public function getHits($hitType /* 'hits' or 'logins' */, $type, $afterTime, $limit = 50, $IP = false){
		$serverTime = $this->getDB()->querySingle("select unix_timestamp()");
		$IPSQL = "";
		if($IP){
			$IPSQL = " and IP=INET_ATON('" . mysql_real_escape_string($IP) . "') ";
		}
		if($hitType == 'hits'){
			if($type == 'hit'){
				$typeSQL = " ";
			} else if($type == 'crawler'){
				$now = time();
				$typeSQL = " and jsRun = 0 and $now - ctime > 30 ";
			} else if($type == 'gCrawler'){
				$typeSQL = " and isGoogle = 1 ";
			} else if($type == '404'){
				$typeSQL = " and is404 = 1 ";
			} else if($type == 'human'){
				$typeSQL = " and jsRun = 1 ";
			} else if($type == 'ruser'){
				$typeSQL = " and userID > 0 ";
			} else {
				wfUtils::wdie("Invalid log type to wfLog: $type");
			}

			$r1 = $this->getDB()->query("select * from " . $this->hitsTable . " where ctime > %f $IPSQL $typeSQL order by ctime desc limit %s", 
				$afterTime,
				$limit
				);

		} else if($hitType == 'logins'){
			$r1 = $this->getDB()->query("select * from " . $this->loginsTable . " where ctime > %f $IPSQL order by ctime desc limit %s", 
				$afterTime,
				$limit
				);

		} else {
			wfUtils::wdie("getHits got invalid hitType: $hitType");
		}
		$results = array();
		while($res = mysql_fetch_assoc($r1)){
			array_push($results, $res);
		}
		$this->resolveIPs($results);
		$ourURL = parse_url(site_url());
		$ourHost = strtolower($ourURL['host']);
		$ourHost = preg_replace('/^www\./i', '', $ourHost);
		$browscap = new wfBrowscap();
		foreach($results as &$res){ 
			$res['type'] = $type;
			if(isset($res['HTTPHeaders'])){
				$res['HTTPHeaders'] = unserialize($res['HTTPHeaders']);
			}
			$res['timeAgo'] = wfUtils::makeTimeAgo($serverTime - $res['ctime']);
			$res['blocked'] = $this->getDB()->querySingle("select blockedTime from " . $this->blocksTable . " where IP=%s and blockedTime + %s > unix_timestamp()", $res['IP'], wfConfig::get('blockedTime'));
			$res['IP'] = wfUtils::inet_ntoa($res['IP']); 
			$res['extReferer'] = false;
			if($res['referer']){
				$refURL = parse_url($res['referer']);
				if(is_array($refURL) && $refURL['host']){
					$refHost = strtolower(preg_replace('/^www\./i', '', $refURL['host']));
					if($refHost != $ourHost){
						$res['extReferer'] = true;
						//now extract search terms
						$q = false;
						if(preg_match('/(?:google|bing|alltheweb|aol|ask)\./i', $refURL['host'])){
							$q = 'q';
						} else if(stristr($refURL['host'], 'yahoo.')){
							$q = 'p';
						} else if(stristr($refURL['host'], 'baidu.')){
							$q = 'wd';
						}
						if($q){
							$queryVars = array();
							parse_str($refURL['query'], $queryVars);
							if(isset($queryVars[$q])){
								$res['searchTerms'] = $queryVars[$q];
							}
						}
					}
				}
				if($res['extReferer']){
					if ( stristr( $referringPage['host'], 'google.' ) )
					{
						parse_str( $referringPage['query'], $queryVars );
						echo $queryVars['q']; // This is the search term used
					}
				}
			}
			$res['browser'] = false;
			if($res['UA']){
				$b = $browscap->getBrowser($res['UA']);
				if($b){
					$res['browser'] = array(
						'browser' => $b['Browser'],
						'version' => $b['Version'],
						'platform' => $b['Platform'],
						'isMobile' => $b['isMobileDevice'],
						'isCrawler' => $b['Crawler']
						);
				}
			}

						
			if($res['userID']){
				$ud = get_userdata($res['userID']);
				if($ud){
					$res['user'] = array(
						'editLink' => wfUtils::editUserLink($res['userID']),
						'display_name' => $ud->display_name,
						'ID' => $res['userID']
						);
					$res['user']['avatar'] = get_avatar($res['userID'], 16);
				}
			} else {
				$res['user'] = false;
			}
		}
		return $results;
	}
	public function resolveIPs(&$results){
		if(sizeof($results) < 1){ return; }
		$IPs = array();
		foreach($results as &$res){
			if($res['IP']){ //Can also be zero in case of non IP events
				$IPs[] = $res['IP'];
			}
		}
		$IPs = array_unique($IPs);
		$IPLocs = array();
		$toResolve = array();
		foreach($IPs as $IP){
			$r1 = $this->getDB()->query("select IP, ctime, failed, city, region, countryName, countryCode, lat, lon, unix_timestamp() - ctime as age from " . $this->locsTable . " where IP=%s", $IP);
			if($r1){
				if($row = mysql_fetch_assoc($r1)){
					if($row['age'] > WORDFENCE_MAX_IPLOC_AGE){
						$this->getDB()->query("delete from " . $this->locsTable . " where IP=%s", $row['IP']);
					} else {
						if($row['failed'] == 1){
							$IPLocs[$IP] = false;
						} else {
							$IPLocs[$IP] = $row;
						}
					}
				}
			}
			if(! isset($IPLocs[$IP])){
				$toResolve[] = $IP;
			}
		}
		if(sizeof($toResolve) > 0){
			$api = new wfAPI($this->apiKey, $this->wp_version); 
			$freshIPs = $api->call('resolve_ips', array(), array(
				'ips' => implode(',', $toResolve)
				));
			if(is_array($freshIPs)){
				foreach($freshIPs as $IP => $value){
					if($value == 'failed'){
						$this->getDB()->query("insert IGNORE into " . $this->locsTable . " (IP, ctime, failed) values (%s, unix_timestamp(), 1)", $IP);
						$IPLocs[$IP] = false;
					} else {
						$this->getDB()->query("insert IGNORE into " . $this->locsTable . " (IP, ctime, failed, city, region, countryName, countryCode, lat, lon) values (%s, unix_timestamp(), 0, '%s', '%s', '%s', '%s', %s, %s)", 
							$IP,
							$value[3], //city
							$value[2], //region
							$value[1], //countryName
							$value[0],//countryCode
							$value[4],//lat
							$value[5]//lon
							);
						$IPLocs[$IP] = array(
							'IP' => $IP,
							'city' => $value[3],
							'region' => $value[2],
							'countryName' => $value[1],
							'countryCode' => $value[0],
							'lat' => $value[4],
							'lon' => $value[5]
							);
					}
				}
			}
		}
		foreach($results as &$res){
			if(isset($IPLocs[$res['IP']])){
				$res['loc'] = $IPLocs[$res['IP']];
			} else {
				$res['loc'] = false;
			}
		}
	}
	public function logHitOK(){
		if(stristr($_SERVER['REQUEST_URI'], 'wp-admin/admin-ajax.php')){ return false; } //Don't log wordpress ajax requests.
		if(is_admin()){ return false; } //Don't log admin pageviews
		if(preg_match('/WordPress\/' . $this->wp_version . '/i', $_SERVER['HTTP_USER_AGENT'])){ return false; } //Ignore requests generated by WP UA.
		if($userID = get_current_user_id()){
			if(wfConfig::get('liveTraf_ignorePublishers') && (current_user_can('publish_posts') || current_user_can('publish_pages')) ){ return false; } //User is logged in and can publish, so we don't log them. 
			$user = get_userdata($userID);
			if($user){
				if(wfConfig::get('liveTraf_ignoreUsers')){
					foreach(explode(',', wfConfig::get('liveTraf_ignoreUsers')) as $ignoreLogin){
						if($user->user_login == $ignoreLogin){
							return false;
						}
					}
				}
			}
		}
		if(wfConfig::get('liveTraf_ignoreIPs')){
			$IPs = explode(',', wfConfig::get('liveTraf_ignoreIPs'));
			$IP = wfUtils::getIP();
			foreach($IPs as $ignoreIP){
				if($ignoreIP == $IP){
					return false;
				}
			}
		}
		if(wfConfig::get('liveTraf_ignoreUA')){
			if($_SERVER['HTTP_USER_AGENT'] == wfConfig::get('liveTraf_ignoreUA')){
				return false;
			}
		}

		return true;
	}
	private function getDB(){
		if(! $this->db){
			$this->db = new wfDB();
		}
		return $this->db;
	}
	public function firewallBadIPs(){
		$IP = wfUtils::inet_aton(wfUtils::getIP());
		if($secsToGo = $this->getDB()->querySingle("select (blockedTime + %s) - unix_timestamp() as secsToGo from " . $this->blocksTable . " where IP=%s and blockedTime + %s > unix_timestamp()", wfConfig::get('blockedTime'), $IP, wfConfig::get('blockedTime'))){
			$this->getDB()->query("update " . $this->blocksTable . " set lastAttempt=unix_timestamp(), blockedHits = blockedHits + 1 where IP=%s", $IP); 
			$this->do503($secsToGo); 
		}
	}
	private function takeBlockingAction($configVar, $reason){
		if($this->googleSafetyCheckOK()){
			$action = wfConfig::get($configVar . '_action');
			if(! $action){
				error_log("Wordfence action missing for configVar: $configVar");
				return;
			}
			$secsToGo = 0;
			if($action == 'block'){
				$IP = wfUtils::getIP();
				if(wfConfig::get('alertOn_block')){
					wordfence::alert("Blocking IP $IP", "Wordfence has blocked IP address $IP.\n The reason is: \"$reason\".\n When we did a reverse lookup on this address it resolved to:\n \"" . $this->reverseLookup($IP) . "\".");
				}
				wordfence::status(2, 'info', "Blocking IP $IP. $reason");
				$this->blockIP($IP, $reason);
				$secsToGo = wfConfig::get('blockedTime');
			} else if($action == 'throttle'){
				$IP = wfUtils::inet_aton(wfUtils::getIP());
				$this->getDB()->query("insert into " . $this->throttleTable . " (IP, startTime, endTime, timesThrottled, lastReason) values (%s, unix_timestamp(), unix_timestamp(), 1, '%s') ON DUPLICATE KEY UPDATE endTime=unix_timestamp(), timesThrottled = timesThrottled + 1, lastReason='%s'", $IP, $reason, $reason);
				wordfence::status(2, 'info', "Throttling IP $IP. $reason");
				$secsToGo = 60;
			}
			$this->do503($secsToGo);
		} else {
			return;
		}
	}
	private function do503($secsToGo){
		header('HTTP/1.1 503 Service Temporarily Unavailable');
		header('Status: 503 Service Temporarily Unavailable');
		header('Retry-After: ' . $secsToGo);
		require_once('wf503.php');
		exit();
	}
	private function googleSafetyCheckOK(){ //returns true if OK to block. Returns false if we must not block.
		$cacheKey = md5($_SERVER['HTTP_USER_AGENT'] . ' ' . wfUtils::getIP());
		//Cache so we can call this multiple times in one request
		if(! isset(self::$gbSafeCache[$cacheKey])){
			$nb = wfConfig::get('neverBlockBG');
			if($nb == 'treatAsOtherCrawlers'){
				self::$gbSafeCache[$cacheKey] = true; //OK to block because we're treating google like everyone else
			} else if($nb == 'neverBlockUA' || $nb == 'neverBlockVerified'){
				if(wfCrawl::isGoogleCrawler()){ //Check the UA using regex
					if($nb == 'neverBlockVerified'){
						if(wfCrawl::verifyCrawlerPTR($this->googlePattern, wfUtils::getIP())){ //UA check passed, now verify using PTR if configured to
							self::$gbSafeCache[$cacheKey] = false; //This is a verified Google crawler, so no we can't block it
						} else {
							self::$gbSafeCache[$cacheKey] = true; //This is a crawler claiming to be Google but it did not verify
						}
					} else { //neverBlockUA
						self::$gbSafeCache[$cacheKey] = false; //User configured us to only do a UA check and this claims to be google so don't block
					}
				} else {
					self::$gbSafeCache[$cacheKey] = true; //This isn't a Google UA, so it's OK to block
				}
			} else {
				error_log("Wordfence error: neverBlockBG option is not set.");
				self::$gbSafeCache[$cacheKey] = false; //Oops the config option is not set. This should never happen because it's set on install. So we return false to indicate it's not OK to block just for safety.
			}
		}
		if(! isset(self::$gbSafeCache[$cacheKey])){
			error_log("Wordfence assertion fail in googleSafetyCheckOK: cached value is not set.");
			return false; //for safety
		}
		return self::$gbSafeCache[$cacheKey]; //return cached value
	}
	public function reverseLookup($IP){
		$IPn = wfUtils::inet_aton($IP);
		$host = $this->getDB()->querySingle("select host from " . $this->reverseTable . " where IP=%s and unix_timestamp() - lastUpdate < %d", $IPn, WORDFENCE_REVERSE_LOOKUP_CACHE_TIME);
		if(! $host){
			$ptr = implode(".", array_reverse(explode(".",$IP))) . ".in-addr.arpa";
			$host = dns_get_record($ptr, DNS_PTR);
			if($host == null){
				$host = 'NONE';
			} else {
				$host = $host[0]['target'];
			}
			$this->getDB()->query("insert into " . $this->reverseTable . " (IP, host, lastUpdate) values (%s, '%s', unix_timestamp()) ON DUPLICATE KEY UPDATE host='%s', lastUpdate=unix_timestamp()", $IPn, $host, $host);
		}
		if($host == 'NONE'){
			return '';
		} else {
			return $host;
		}
	}
	public function addStatus($level, $type, $msg){
		$this->getDB()->query("insert into " . $this->statusTable . " (ctime, level, type, msg) values (%s, %d, '%s', '%s')", microtime(true), $level, $type, $msg);
	}
	public function getStatusEvents(){
		$res = $this->getDB()->query("select ctime, level, type, msg from " . $this->statusTable . " order by ctime desc limit 1000");
		$results = array();
		$lastTime = false;
		while($rec = mysql_fetch_assoc($res)){
			$rec['timeAgo'] = wfUtils::makeTimeAgo(time() - $rec['ctime']);
			array_push($results, $rec);
		}
		return $results;
	}
}

?>
