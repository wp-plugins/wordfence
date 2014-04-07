<?php
class wfCache {
	private static $cacheType = false;
	private static $fileCache = array();
	private static $cacheStats = array();
	private static $cacheClearedThisRequest = false;
	private static $clearScheduledThisRequest = false;
	public static function setupCaching(){
		self::$cacheType = wfConfig::get('cacheType');
		if(self::$cacheType != 'php' && self::$cacheType != 'falcon'){
			return; //cache is disabled
		}
		if(wfUtils::hasLoginCookie()){	
			add_action('publish_post', 'wfCache::action_publishPost');
			add_action('publish_page', 'wfCache::action_publishPost');
			foreach(array('clean_object_term_cache', 'clean_post_cache', 'clean_term_cache', 'clean_page_cache', 'after_switch_theme', 'customize_save_after', 'activated_plugin', 'deactivated_plugin', 'update_option_sidebars_widgets') as $action){
				add_action($action, 'wfCache::action_clearPageCache'); //Schedules a cache clear for immediately so it won't lag current request.
			}
			if($_SERVER['REQUEST_METHOD'] == 'POST'){
				foreach(array(
					'/\/wp\-admin\/options\.php$/',
					'/\/wp\-admin\/options\-permalink\.php$/'
					) as $pattern){
					if(preg_match($pattern, $_SERVER['REQUEST_URI'])){
						self::scheduleCacheClear();
						break;
					}
				}
			}
		}
		add_action('wordfence_cache_clear', 'wfCache::scheduledCacheClear');
		add_action('wordfence_update_blocked_IPs', 'wfCache::scheduleUpdateBlockedIPs');
		add_action('comment_post', 'wfCache::action_commentPost'); //Might not be logged in
		add_filter('wp_redirect', 'wfCache::redirectFilter');

		//Routines to clear cache run even if cache is disabled
		$file = self::fileFromRequest( ($_SERVER['HTTP_HOST'] ? $_SERVER['HTTP_HOST'] : $_SERVER['SERVER_NAME']), $_SERVER['REQUEST_URI']);
		$fileDeleted = false;
		$doDelete = false;
		if($_SERVER['REQUEST_METHOD'] != 'GET'){ //If our URL is hit with a POST, PUT, DELETE or any other non 'GET' request, then clear cache.
			$doDelete = true;
		}

		if($doDelete){
			@unlink($file);
			$fileDeleted = true;
		}


		add_action('wp_logout', 'wfCache::logout');
		if(self::isCachable()){
			if( (! $fileDeleted) && self::$cacheType == 'php'){ //Then serve the file if it's still valid
				$stat = @stat($file);
				if($stat){
					$age = time() - $stat[9];
					if($age < 10000){
						readfile($file); //sends file to stdout
						die();
					}
				}
			}
			ob_start('wfCache::obComplete'); //Setup routine to store the file
		}
	}
	public static function redirectFilter($status){
		define('WFDONOTCACHE', true);
		return $status;
	}
	public static function isCachable(){
		if(defined('WFDONOTCACHE') || defined('DONOTCACHEPAGE') || defined('DONOTCACHEDB') || defined('DONOTCACHEOBJECT')){ //If you want to tell Wordfence not to cache something in another plugin, simply define one of these. 
			return false;
		}
		if(! wfConfig::get('allowHTTPSCaching')){
			if(self::isHTTPSPage()){
				return false;
			}
		}

		if(is_admin()){ return false; } //dont cache any admin pages.
		$uri = $_SERVER['REQUEST_URI'];

		if(strrpos($uri, '/') !== strlen($uri) - 1){ //must end with a '/' char.
			return false;
		}
		if($_SERVER['REQUEST_METHOD'] != 'GET'){ return false; } //Only cache GET's
		if(strlen($_SERVER['QUERY_STRING']) > 0 && (! preg_match('/^\d+=\d+$/', $_SERVER['QUERY_STRING'])) ){ //Don't cache query strings unless they are /?123132423=123123234 DDoS style.
			return false; 
		} 
		//wordpress_logged_in_[hash] cookies indicates logged in
		if(is_array($_COOKIE)){
			foreach(array_keys($_COOKIE) as $c){
				foreach(array('comment_author','wp-postpass','wf_logout','wordpress_logged_in','wptouch_switch_toggle','wpmp_switcher') as $b){
					if(strpos($c, $b) !== false){ return false; } //contains a cookie which indicates user must not be cached
				}
			}
		}
		$ex = wfConfig::get('cacheExclusions', false);
		if($ex){
			$ex = unserialize($ex);
			foreach($ex as $v){
				if($v['pt'] == 's'){ if(strpos($uri, $v['p']) === 0){ return false; } }
				if($v['pt'] == 'e'){ if(strpos($uri, $v['p']) === (strlen($uri) - strlen($v['p'])) ){ return false; } }
				if($v['pt'] == 'c'){ if(strpos($uri, $v['p']) !== false){ return false; } }
			}
		}
		return true;
	}
	public static function isHTTPSPage(){
		if( isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] && $_SERVER['HTTPS'] != 'off'){ 
			return true;
		}
		if( !empty( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && $_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https' ){ //In case we're behind a proxy and user used HTTPS.
			return true;
		}
		return false;
	}
	public static function obComplete($buffer = ''){
		if(defined('WFDONOTCACHE') || defined('DONOTCACHEPAGE') || defined('DONOTCACHEDB') || defined('DONOTCACHEOBJECT')){  
			//These constants may have been set after we did the initial isCachable check by e.g. wp_redirect filter. If they're set then just return the buffer and don't cache.
			return $buffer; 
		}

		$file = self::fileFromRequest( ($_SERVER['HTTP_HOST'] ? $_SERVER['HTTP_HOST'] : $_SERVER['SERVER_NAME']), $_SERVER['REQUEST_URI']);
		self::makeDirIfNeeded($file);
		$append = "";
		$appendGzip = "";
		if(wfConfig::get('addCacheComment', false)){
			$append = "\n<!-- Cached by Wordfence ";
			if(wfConfig::get('cacheType', false) == 'falcon'){
				$append .= "Falcon Engine. ";
			} else {
				$append .= "PHP Caching Engine. ";
			}
			$append .= "Time created on server: " . date('Y-m-d H:i:s T') . ". ";
			$append .= "Is HTTPS page: " . (self::isHTTPSPage() ? 'HTTPS' : 'no') . ". ";
			$append .= "Page size: " . strlen($buffer) . " bytes. ";
			$append .= "Host: " . ($_SERVER['HTTP_HOST'] ? $_SERVER['HTTP_HOST'] : $_SERVER['SERVER_NAME']) . ". ";
			$append .= "Request URI: " . $_SERVER['REQUEST_URI'] . " ";
			$appendGzip = $append . " Encoding: GZEncode -->\n";
			$append .= " Encoding: Uncompressed -->\n";
		}

		file_put_contents($file, $buffer . $append, LOCK_EX);
		chmod($file, 0655);
		if(self::$cacheType == 'falcon'){ //create gzipped files so we can send precompressed files
			$file .= '_gzip';
			file_put_contents($file, gzencode($buffer . $appendGzip, 9), LOCK_EX);
			chmod($file, 0655);
		}
		return $buffer;
	}
	public static function fileFromRequest($host, $URI){
		$key = $host . $URI;
		if(isset(self::$fileCache[$key])){ return self::$fileCache[$key]; }
		$host = preg_replace('/[^a-zA-Z0-9\-\.]+/', '', $host);
		$URI = preg_replace('/(?:[^a-zA-Z0-9\-\_\.\~\/]+|\.{2,})/', '', $URI); //Strip out bad chars and multiple dots
		if(preg_match('/\/*([^\/]*)\/*([^\/]*)\/*([^\/]*)\/*([^\/]*)\/*([^\/]*)(.*)$/', $URI, $matches)){
			$URI = $matches[1] . '/';
			for($i = 2; $i <= 6; $i++){
				$URI .= strlen($matches[$i]) > 0 ? $matches[$i] : '';
				$URI .= $i < 6 ? '~' : '';
			}
		}
		$file = WP_CONTENT_DIR . '/wfcache/' . $host . '_' . $URI . '_wfcache' . (self::isHTTPSPage() ? '_https' : '') . '.html';
		self::$fileCache[$key] = $file;
		return $file;
	}
	public static function makeDirIfNeeded($file){
		$file = preg_replace('/\/[^\/]*$/', '', $file);
		if(! is_dir($file)){
			mkdir($file, 0755, true);
		}
	}
	public static function logout(){
		wfUtils::setcookie('wf_logout', '1', 0, null, null, null, true);
	}
	public static function cacheDirectoryTest(){
		$cacheDir = WP_CONTENT_DIR . '/wfcache/';
		if(! is_dir($cacheDir)){
			if(! @mkdir($cacheDir, 0755, true)){
				$err = error_get_last();
				$msg = "The directory $cacheDir does not exist and we could not create it.";
				if($err){
					$msg .= ' The error we received was: ' . $err['message'];
				}
				return $msg;
			}
		}
		if(! @file_put_contents($cacheDir . 'test.php', 'test')){
			$err = error_get_last();
			$msg = "We could not write to the file $cacheDir" . "test.php when testing if the cache directory is writable.";
			if($err){
				$msg .= " The error was: " . $err['message'];
			}
			return $msg;
		}
		return false; //Everything is OK
	}
	public static function action_publishPost($id){
		$perm = get_permalink($id);
		self::deleteFileFromPermalink($perm);
		self::scheduleCacheClear();
	}
	public static function action_commentPost($commentID){
		$c = get_comment($commentID, ARRAY_A);
		$perm = get_permalink($c['comment_post_ID']);
		self::deleteFileFromPermalink($perm);
		self::scheduleCacheClear();
	}
	public static function action_clearPageCache(){ //Can safely call this as many times as we like because it'll only schedule one clear
		self::scheduleCacheClear();
	}
	public static function scheduleCacheClear(){
		if(self::$clearScheduledThisRequest){ return; }
		self::$clearScheduledThisRequest = true;
		wp_schedule_single_event(time() - 15, 'wordfence_cache_clear', array( rand(0,999999999) )); //rand makes sure this is called every time and isn't subject to the 10 minute window where the same event won't be run twice with wp_schedule_single_event
		$url = admin_url('admin-ajax.php');
		wp_remote_get($url);
	}
	public static function scheduledCacheClear($random){
		self::clearPageCacheSafe(); //Will only run if clearPageCache() has not run this request
	}
	public static function deleteFileFromPermalink($perm){
		if(preg_match('/\/\/([^\/]+)(\/.*)$/', $perm, $matches)){
			$host = $matches[1];
			$uri = $matches[2];
			$file = self::fileFromRequest($host, $uri);
			if(is_file($file)){
				@unlink($file);
			}
		}
	}
	public static function getCacheStats(){
		self::$cacheStats = array(
			'files' => 0,
			'dirs' => 0,
			'data' => 0,
			'compressedFiles' => 0,
			'compressedKBytes' => 0,
			'uncompressedFiles' => 0,
			'uncompressedKBytes' => 0,
			'oldestFile' => false,
			'newestFile' => false,
			'largestFile' => 0,
			);
		self::recursiveStats(WP_CONTENT_DIR . '/wfcache/');
		return self::$cacheStats;
	}
	private static function recursiveStats($dir){
		$files = array_diff(scandir($dir), array('.','..')); 
		foreach($files as $file){
			$fullPath = $dir . '/' . $file;
			if(is_dir($fullPath)){
				self::$cacheStats['dirs']++;
				self::recursiveStats($fullPath);
			} else {
				if($file == 'clear.lock'){ continue; }
				self::$cacheStats['files']++;
				$stat = stat($fullPath);
				if(is_array($stat)){
					$size = $stat[7];
					if($size){
						$size = round($size / 1024);
						self::$cacheStats['data'] += $size;
						if(strrpos($file, '_gzip') == strlen($file) - 6){
							self::$cacheStats['compressedFiles']++;
							self::$cacheStats['compressedKBytes'] += $size;
						} else {
							self::$cacheStats['uncompressedFiles']++;
							self::$cacheStats['uncompressedKBytes'] += $size;
						}
						if(self::$cacheStats['largestFile'] < $size){
							self::$cacheStats['largestFile'] = $size;
						}
					}

					$ctime = $stat[10];
					if(self::$cacheStats['oldestFile'] > $ctime || self::$cacheStats['oldestFile'] === false){
						self::$cacheStats['oldestFile'] = $ctime;
					}
					if(self::$cacheStats['newestFile'] === false || self::$cacheStats['newestFile'] < $ctime){
						self::$cacheStats['newestFile'] = $ctime;
					}
				}
			}
		}
	}
	public static function clearPageCacheSafe(){
		if(self::$cacheClearedThisRequest){ return; }
		self::$cacheClearedThisRequest = true;
		self::clearPageCache();
	}
	public static function clearPageCache(){ //If a clear is in progress this does nothing. 
		self::$cacheStats = array(
			'dirsDeleted' => 0,
			'filesDeleted' => 0,
			'totalData' => 0,
			'totalErrors' => 0
			);
		$cacheClearLock = WP_CONTENT_DIR . '/wfcache/clear.lock';
		if(! is_file($cacheClearLock)){
			touch($cacheClearLock);
		}
		$fp = fopen($cacheClearLock, 'w');
		if(! $fp){ return; }
		if(flock($fp, LOCK_EX | LOCK_NB)){ //non blocking exclusive flock attempt. If we get a lock then it continues and returns true. If we don't lock, then return false, don't block and don't clear the cache. 
					// This logic means that if a cache clear is currently in progress we don't try to clear the cache.
					// This prevents web server children from being queued up waiting to be able to also clear the cache. 
			self::recursiveDelete(WP_CONTENT_DIR . '/wfcache/');
			flock($fp, LOCK_UN);
		}
		fclose($fp);

		return self::$cacheStats;
	}
	public static function recursiveDelete($dir){
		$files = array_diff(scandir($dir), array('.','..')); 
		foreach ($files as $file) { 
			if(is_dir($dir . '/' . $file)){
				self::recursiveDelete($dir . '/' . $file);
			} else {
				if($file == 'clear.lock'){ continue; } //Don't delete our lock file
				$size = filesize($dir . '/' . $file);
				if($size){
					self::$cacheStats['totalData'] += round($size / 1024);
				}
				if(strpos($dir, 'wfcache/') === false){
					//error_log("Tried to delete file in invalid dir in cache clear: $dir");
					return; //Safety check that we're in a subdir of the cache
				}
				if(@unlink($dir . '/' . $file)){
					self::$cacheStats['filesDeleted']++;
				} else {
					self::$cacheStats['totalErrors']++;
				}
			}
		} 
		if($dir != WP_CONTENT_DIR . '/wfcache/'){
			if(strpos($dir, 'wfcache/') === false){
				//error_log("Tried to delete invalid dir in cache clear: $dir");
				return; //Safety check that we're in a subdir of the cache
			}
			if(@rmdir($dir)){
				self::$cacheStats['dirsDeleted']++;
			} else {
				self::$cacheStats['totalErrors']++;
			}
		} else {
			return true;
		}
	}
	public static function addHtaccessCode($action){
		if($action != 'add' && $action != 'remove'){
			die("Error: addHtaccessCode must be called with 'add' or 'remove' as param");
		}
		$htaccessPath = ABSPATH . '/.htaccess';
		$fh = fopen($htaccessPath, 'r+');
		if(! $fh){
			$err = error_get_last();
			return $err['message'];
		}
		flock($fh, LOCK_EX);
		fseek($fh, 0, SEEK_SET); //start of file
		$contents = fread($fh, filesize($htaccessPath));
		if(! $contents){
			fclose($fh);
			return "Could not read from $htaccessPath";
		}
		$contents = preg_replace('/#WFCACHECODE.*WFCACHECODE[r\s\n\t]*/s', '', $contents);
		if($action == 'add'){
			$code = self::getHtaccessCode();
			$contents = $code . "\n" . $contents;
		}
		ftruncate($fh, 0);
		fseek($fh, 0, SEEK_SET);
		fwrite($fh, $contents);
		flock($fh, LOCK_UN);
		fclose($fh);
		return false;
	}
	private static function getHtaccessCode(){
		$sslString = "RewriteCond %{HTTPS} off";
		if(wfConfig::get('allowHTTPSCaching')){
			$sslString = "";
		}
		$code = <<<EOT
#WFCACHECODE - Do not remove this line. Disable Web Caching in Wordfence to remove this data.
<IfModule mod_deflate.c>
	AddOutputFilterByType DEFLATE text/css text/x-component application/x-javascript application/javascript text/javascript text/x-js text/html text/richtext image/svg+xml text/plain text/xsd text/xsl text/xml image/x-icon application/json
	<IfModule mod_headers.c>
		Header append Vary User-Agent env=!dont-vary
	</IfModule>
	<IfModule mod_mime.c>
		AddOutputFilter DEFLATE js css htm html xml
	</IfModule>
</IfModule>
<IfModule mod_mime.c>
	AddType text/html .html_gzip
	AddEncoding gzip .html_gzip
	AddType text/xml .xml_gzip
	AddEncoding gzip .xml_gzip
</IfModule>
<IfModule mod_setenvif.c>
	SetEnvIfNoCase Request_URI \.html_gzip$ no-gzip
	SetEnvIfNoCase Request_URI \.xml_gzip$ no-gzip
</IfModule>
<IfModule mod_headers.c>
	Header set Vary "Accept-Encoding, Cookie"
</IfModule>
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteBase /
	RewriteCond %{HTTPS} on
	RewriteRule .* - [E=WRDFNC_HTTPS:_https]
	RewriteCond %{HTTP:Accept-Encoding} gzip
	RewriteRule .* - [E=WRDFNC_ENC:_gzip]
	RewriteCond %{REQUEST_METHOD} !=POST
	$sslString
	RewriteCond %{QUERY_STRING} ^(?:\d+=\d+)?$
	RewriteCond %{REQUEST_URI} (?:\/|\.html)$ [NC]
	RewriteCond %{HTTP_COOKIE} !(comment_author|wp\-postpass|wf_logout|wordpress_logged_in|wptouch_switch_toggle|wpmp_switcher) [NC]

	RewriteCond %{REQUEST_URI} \/*([^\/]*)\/*([^\/]*)\/*([^\/]*)\/*([^\/]*)\/*([^\/]*)(.*)$
	RewriteCond "%{DOCUMENT_ROOT}/wp-content/wfcache/%{HTTP_HOST}_%1/%2~%3~%4~%5~%6_wfcache%{WRDFNC_HTTPS}.html%{ENV:WRDFNC_ENC}" -f
	RewriteRule \/*([^\/]*)\/*([^\/]*)\/*([^\/]*)\/*([^\/]*)\/*([^\/]*)(.*)$ "/wp-content/wfcache/%{HTTP_HOST}_$1/$2~$3~$4~$5~$6_wfcache%{WRDFNC_HTTPS}.html%{ENV:WRDFNC_ENC}" [L]
</IfModule>
#Do not remove this line. Disable Web caching in Wordfence to remove this data - WFCACHECODE
EOT;
		return $code;
	}
	public static function scheduleUpdateBlockedIPs(){
		wp_clear_scheduled_hook('wordfence_update_blocked_IPs');
		if(wfConfig::get('cacheType') != 'falcon'){ 
			self::updateBlockedIPs('remove');
			return; 
		}
		self::updateBlockedIPs('add');
		wp_schedule_single_event(time() + 300, 'wordfence_update_blocked_IPs');
	}
	public static function updateBlockedIPs($action){ //'add' or 'remove'
		if(wfConfig::get('cacheType') != 'falcon'){ return; }

		$htaccessPath = ABSPATH . '/.htaccess';
		if($action == 'remove'){
			$fh = fopen($htaccessPath, 'r+');
			if(! $fh){
				$err = error_get_last();
				return $err['message'];
			}
			flock($fh, LOCK_EX);
			fseek($fh, 0, SEEK_SET); //start of file
			$contents = fread($fh, filesize($htaccessPath));
			if(! $contents){
				fclose($fh);
				return "Could not read from $htaccessPath";
			}

			$contents = preg_replace('/#WFIPBLOCKS.*WFIPBLOCKS[r\s\n\t]*/s', '', $contents);

			ftruncate($fh, 0);
			fseek($fh, 0, SEEK_SET);
			fwrite($fh, $contents);
			flock($fh, LOCK_UN);
			fclose($fh);
			return false;
		} else if($action == 'add'){
			$lines = array();
			$wfLog = new wfLog(wfConfig::get('apiKey'), wfUtils::getWPVersion());
			$IPs = $wfLog->getBlockedIPsAddrOnly();
			if(sizeof($IPs) > 0){
				foreach($IPs as $IP){
					$lines[] = "Deny from $IP\n";
				}
			}
			$ranges = $wfLog->getRangesBasic();
			$browserAdded = false;
			$browserLines = array();
			if($ranges){
				foreach($ranges as $r){
					$arr = explode('|', $r);
					$range = isset($arr[0]) ? $arr[0] : false;
					$browser = isset($arr[1]) ? $arr[1] : false;

					if($range && $browser){
						continue; //Don't process browser and range combos
					} else if($range){
						$ips = explode('-', $range);
						$cidrs = wfUtils::rangeToCIDRs($ips[0], $ips[1]);
						$hIPs = wfUtils::inet_ntoa($ips[0]) . ' - ' . wfUtils::inet_ntoa($ips[1]);
						if(sizeof($cidrs) > 0){
							$lines[] = '#Start of blocking code for IP range: ' . $hIPs . "\n";
							foreach($cidrs as $c){
								$lines[] = "Deny from $c\n";
							}
							$lines[] = '#End of blocking code for IP range: ' . $hIPs . "\n";
						}
					} else if($browser){
						$browserLines[] = "\t#Blocking code for browser pattern: $browser\n";
						$browser = preg_replace('/([\-\_\.\+\!\@\#\$\%\^\&\(\)\[\]\{\}\/])/', "\\\\$1", $browser);
						$browser = preg_replace('/\*/', '.*', $browser);
						$browserLines[] = "\tSetEnvIf User-Agent " . $browser . " WordfenceBadBrowser=1\n";
						$browserAdded = true;
					}
				}
			}
			if($browserAdded){
				$lines[] = "<IfModule mod_setenvif.c>\n";
				foreach($browserLines as $l){
					$lines[] = $l;
				}
				$lines[] = "\tDeny from env=WordfenceBadBrowser\n";
				$lines[] = "</IfModule>\n";
			}
		}
		$blockCode = "#WFIPBLOCKS - Do not remove this line. Disable Web Caching in Wordfence to remove this data.\nOrder Deny,Allow\n";
		$blockCode .= implode('', $lines);
		$blockCode .= "#Do not remove this line. Disable Web Caching in Wordfence to remove this data - WFIPBLOCKS\n";

		$fh = fopen($htaccessPath, 'r+');
		if(! $fh){
			$err = error_get_last();
			return $err['message'];
		}

		//Minimize time between lock/unlock
		flock($fh, LOCK_EX);
		fseek($fh, 0, SEEK_SET); //start of file
		$contents = fread($fh, filesize($htaccessPath));
		if(! $contents){
			fclose($fh);
			return "Could not read from $htaccessPath";
		}
		$contents = preg_replace('/#WFIPBLOCKS.*WFIPBLOCKS[r\s\n\t]*/s', '', $contents);
		$contents = $blockCode . $contents;
		ftruncate($fh, 0);
		fseek($fh, 0, SEEK_SET);
		fwrite($fh, $contents);
		flock($fh, LOCK_UN);
		fclose($fh);
		return false;
	}
}
