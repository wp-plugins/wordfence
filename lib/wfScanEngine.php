<?php
require_once('wordfenceClass.php');
require_once('wordfenceHash.php');
require_once('wfAPI.php');
require_once('wordfenceScanner.php');
require_once('wfIssues.php');
require_once('wfDB.php');
require_once('wfUtils.php');
class wfScanEngine {
	private $i = false;
	private $api = false;
	private $dbh = false;
	private $wp_version = false;
	private $apiKey = false;
	private $errorStopped = false;
	private $dictWords = array();
	private $startTime = 0;
	public function __construct(){
		$this->startTime = time();
		$this->i = new wfIssues();
		$this->wp_version = wfUtils::getWPVersion();
		$this->apiKey = wfConfig::get('apiKey');
		$this->api = new wfAPI($this->apiKey, $this->wp_version);
		include('wfDict.php'); //$dictWords
		$this->dictWords = $dictWords;
	}
	public function go(){
		$this->status(1, 'info', "Initializing scan. Memory available: " . @ini_get('memory_limit') );
		$this->i->deleteNew();

		try {
			$this->doScan();
			if(! $this->errorStopped){
				wfConfig::set('lastScanCompleted', 'ok');
			}
			//updating this scan ID will trigger the scan page to load/reload the results.
			$this->i->setScanTimeNow();
			//scan ID only incremented at end of scan to make UI load new results
			$this->emailNewIssues();
		} catch(Exception $e){
			$this->errorStop($e->getMessage());
		}
		wordfence::scheduleNextScan(true);
	}
	public function emailNewIssues(){
		$this->i->emailNewIssues();
	}
	private function doScan(){
		$this->status(1, 'info', "Contacting Wordfence to initiate scan");
		$this->api->call('log_scan', array(), array());
		if($this->api->errorMsg){
			$this->errorStop($this->api->errorMsg);
			return;
		}
		$unknownFiles = $this->scanKnownFiles();
		if($this->errorStopped){ 
			return; 
		}
		if(wfConfig::get('scansEnabled_fileContents')){
			$this->scanFileContents($unknownFiles);
			if($this->errorStopped){ 
				return; 
			}
		}
		if(wfConfig::get('scansEnabled_posts')){
			$this->scanPosts();
			if($this->errorStopped){ 
				return; 
			}
		}
		if(wfConfig::get('scansEnabled_comments')){
			$this->scanComments();
			if($this->errorStopped){ return; }
		}
		if(wfConfig::get('scansEnabled_passwds')){
			$this->scanAllPasswords();
			if($this->errorStopped){ return; }
		}
		if(wfConfig::get('scansEnabled_diskSpace')){
			$this->scanDiskSpace();
			if($this->errorStopped){ return; }
		}
		if(wfConfig::get('scansEnabled_dns')){
			$this->scanDNSChanges();
			if($this->errorStopped){ return; }
		}
		if(wfConfig::get('scansEnabled_oldVersions')){
			$this->scanOldVersions();
			if($this->errorStopped){ return; }
		}
		$summary = $this->i->getSummaryItems();
		$this->status(1, 'info', "Scan Complete. Scanned " . $summary['totalFiles'] . " files, " . $summary['totalPlugins'] . " plugins, " . $summary['totalThemes'] . " themes, " . ($summary['totalPages'] + $summary['totalPosts']) . " pages, " . $summary['totalComments'] . " comments and " . $summary['totalRows'] . " records in " . (time() - $this->startTime) . " seconds.");
		if($this->i->totalIssues > 0){
			$this->status(10, 'info', "SUM_FINAL:Scan complete. You have " . $this->i->totalIssues . " new issues to fix. See below for details.");
		} else {
			$this->status(10, 'info', "SUM_FINAL:Scan complete. Congratulations, there were no problems found.");
		}
		return;
	}
	private function scanKnownFiles(){
		$malwareScanEnabled = $coreScanEnabled = $pluginScanEnabled = $themeScanEnabled = false;
		$statusIDX = array(
			'core' => false,
			'plugin' => false,
			'theme' => false,
			'unknown' => false
			);
		if(wfConfig::get('scansEnabled_core')){
			$coreScanEnabled = true;
			$statusIDX['core'] = wordfence::statusStart("Comparing core WordPress files against originals in repository");
		} else {
			wordfence::statusDisabled("Skipping core scan");
		}
		if(wfConfig::get('isPaid')){
			if(wfConfig::get('scansEnabled_plugins')){
				$pluginScanEnabled = true;
				$statusIDX['plugin'] = wordfence::statusStart("Premium: Comparing plugin files against originals in repository");
			} else {
				wordfence::statusDisabled("Skipping comparing plugin files against originals in repository");
			}
		} else {
			wordfence::statusPaidOnly("Skipping comparing plugin files against originals in repository");
		}
		if(wfConfig::get('isPaid')){
			if(wfConfig::get('scansEnabled_themes')){
				$themeScanEnabled = true;
				$statusIDX['theme'] = wordfence::statusStart("Premium: Comparing theme files against originals in repository");
			} else {
				wordfence::statusDisabled("Skipping comparing theme files against originals in repository");
			}
		} else {
			wordfence::statusPaidOnly("Skipping comparing theme files against originals in repository");
		}
	
		if(wfConfig::get('scansEnabled_malware')){
			$statusIDX['unknown'] = wordfence::statusStart("Scanning for known malware files");
			$malwareScanEnabled = true;
		} else {
			wordfence::statusDisabled("Skipping malware scan");
			$this->status(2, 'info', "Skipping malware scan because it's disabled.");
		}
		$summaryUpdateRequired = $this->i->summaryUpdateRequired();
		if((! $summaryUpdateRequired) && (! ($coreScanEnabled || $pluginScanEnabled || $themeScanEnabled || $malwareScanEnabled))){
			$this->status(2, 'info', "Finishing this stage because we don't have to do a summary update and we don't need to do a core, plugin, theme or malware scan.");
			return array();
		}
			
		//CORE SCAN
		$hasher = new wordfenceHash(strlen(ABSPATH));
		$baseWPStuff = array( '.htaccess', 'index.php', 'license.txt', 'readme.html', 'wp-activate.php', 'wp-admin', 'wp-app.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-content', 'wp-cron.php', 'wp-includes', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-pass.php', 'wp-register.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php');
		$baseContents = scandir(ABSPATH);
		$scanOutside = wfConfig::get('other_scanOutside');
		if($scanOutside){
			wordfence::status(2, 'info', "Including files that are outside the WordPress installation in the scan.");
		}
		foreach($baseContents as $file){ //Only include base files less than a meg that are files.
			$fullFile = rtrim(ABSPATH, '/') . '/' . $file;
			if($scanOutside){
				$includeInScan[] = $file;
			} else if(in_array($file, $baseWPStuff) || (is_file($fullFile) && is_readable($fullFile) && filesize($fullFile) < 1000000) ){
				$includeInScan[] = $file;
			}
		}
		$this->status(2, 'info', "Hashing your WordPress files for comparison against originals.");
		$hashes = $hasher->hashPaths(ABSPATH, $includeInScan);
		$this->status(2, 'info', "Done hash. Updating summary items.");
		$this->i->updateSummaryItem('totalData', wfUtils::formatBytes($hasher->totalData));
		$this->i->updateSummaryItem('totalFiles', $hasher->totalFiles);
		$this->i->updateSummaryItem('totalDirs', $hasher->totalDirs);
		$this->i->updateSummaryItem('linesOfPHP', $hasher->linesOfPHP);
		$this->i->updateSummaryItem('linesOfJCH', $hasher->linesOfJCH);

		if(! function_exists( 'get_plugins')){
			require_once ABSPATH . '/wp-admin/includes/plugin.php';
		}
		$this->status(2, 'info', "Getting plugin list from WordPress");
		$plugins = get_plugins();
		$this->status(2, 'info', "Found " . sizeof($plugins) . " plugins");
		$this->i->updateSummaryItem('totalPlugins', sizeof($plugins));
		if(! function_exists( 'get_themes')){
			require_once ABSPATH . '/wp-includes/theme.php';
		}
		$this->status(2, 'info', "Getting theme list from WordPress");
		$themes = get_themes();
		$this->status(2, 'info', "Found " . sizeof($themes) . " themes");
		$this->i->updateSummaryItem('totalThemes', sizeof($themes));
		//Return now because we needed to do a summary update but don't have any other work to do.
		if(! ($coreScanEnabled || $pluginScanEnabled || $themeScanEnabled || $malwareScanEnabled)){
			$this->status(2, 'info', "Finishing up because we have done our required summary update and don't need to do a core, plugin, theme or malware scan.");
			return array();
		}
		$this->status(2, 'info', "Reading theme information from each theme's style.css file");
		foreach($themes as $themeName => $themeData){
			$cssFile = $themeData['Stylesheet Dir'] . '/style.css';
			$cssData = @file_get_contents($cssFile);
			if($cssData){
				if(preg_match('/Theme URI:\s*([^\r\n]+)/', $cssData, $matches)){ $themes[$themeName]['Theme URI'] = $matches[1]; }
				if(preg_match('/License:\s*([^\r\n]+)/', $cssData, $matches)){ $themes[$themeName]['License'] = $matches[1]; }
				if(preg_match('/License URI:\s*([^\r\n]+)/', $cssData, $matches)){ $themes[$themeName]['License URI'] = $matches[1]; }
			}
		}
		$this->status(2, 'info', "Sending request to Wordfence servers to do main scan.");
		$scanData = array(
			'pluginScanEnabled' => $pluginScanEnabled,
			'themeScanEnabled' => $themeScanEnabled,
			'coreScanEnabled' => $coreScanEnabled,
			'malwareScanEnabled' => $malwareScanEnabled,
			'plugins' => $plugins,
			'themes' => $themes,
			'hashes' => wordfenceHash::bin2hex($hashes) 
			);
		$result1 = $this->api->call('main_scan', array(), array(
			'data' => json_encode($scanData)
			));
		if($this->api->errorMsg){
			$this->errorStop($this->api->errorMsg);
			wordfence::statusEndErr();
			return;
		}
		if(empty($result1['errorMsg']) === false){
			$this->errorStop($result['errorMsg']);
			wordfence::statusEndErr();
			return;
		}
		if(! $result1){
			$this->errorStop("We received an empty response from the Wordfence server when scanning core, plugin and theme files.");
			wordfence::statusEndErr();
			return;
		}
		$this->status(2, 'info', "Processing scan results");
		$haveIssues = array(
			'core' => false,
			'plugin' => false,
			'theme' => false,
			'unknown' => false
			);
		foreach($result1['results'] as $issue){
			$this->status(2, 'info', "Adding issue: " . $issue['shortMsg']);
			if($this->addIssue($issue['type'], $issue['severity'], $issue['ignoreP'], $issue['ignoreC'], $issue['shortMsg'], $issue['longMsg'], $issue['data'])){
				$haveIssues[$issue['data']['cType']] = true;
			}
		}
		foreach($haveIssues as $type => $have){
			if($statusIDX[$type] !== false){
				wordfence::statusEnd($statusIDX[$type], $have);
			}
		}
		return $result1['unknownFiles'];
	}
	private function scanFileContents($unknownFiles){
		$statusIDX = wordfence::statusStart('Scanning file contents for infections and vulnerabilities');
		$statusIDX2 = wordfence::statusStart('Scanning files for URLs in Google\'s Safe Browsing List');
		if(! is_array($unknownFiles)){
			$unknownFiles = array();
		}
		$this->status(2, 'info', "Getting list of changed files since last scan.");
		$scanner = new wordfenceScanner($this->apiKey, $this->wp_version);
		$this->status(2, 'info', "Starting scan of file contents");
		$result2 = $scanner->scan(ABSPATH, $unknownFiles);
		$this->status(2, 'info', "Done file contents scan");
		if($scanner->errorMsg){
			$this->errorStop($scanner->errorMsg);
		}
		$haveIssues = false;
		$haveIssuesGSB = false;
		foreach($result2 as $issue){
			$this->status(2, 'info', "Adding issue: " . $issue['shortMsg']);
			if($this->addIssue($issue['type'], $issue['severity'], $issue['ignoreP'], $issue['ignoreC'], $issue['shortMsg'], $issue['longMsg'], $issue['data'])){
				if(empty($issue['data']['gsb']) === false){
					$haveIssuesGSB = true;
				} else {
					$haveIssues = true;
				}
			}
		}
		wordfence::statusEnd($statusIDX, $haveIssues);
		wordfence::statusEnd($statusIDX2, $haveIssuesGSB);
	}
	private function scanPosts(){
		$statusIDX = wordfence::statusStart('Scanning posts for URL\'s in Google\'s Safe Browsing List');
		$blogsToScan = $this->getBlogsToScan('posts');
		$wfdb = new wfDB();
		$h = new wordfenceURLHoover($this->apiKey, $this->wp_version);
		$postDat = array();
		foreach($blogsToScan as $blog){
			$q1 = $wfdb->query("select ID from " . $blog['table'] . " where post_type IN ('page', 'post') and post_status = 'publish'");
			while($idRow = mysql_fetch_assoc($q1)){
				$row = $wfdb->querySingleRec("select ID, post_title, post_type, post_date, post_content from " . $blog['table'] . " where ID=%d", $idRow['ID']);
				$h->hoover($blog['blog_id'] . '-' . $row['ID'], $row['post_title'] . ' ' . $row['post_content']);
				$postDat[$blog['blog_id'] . '-' . $row['ID']] = array(
					'contentMD5' => md5($row['post_content']),
					'title' => $row['post_title'],
					'type' => $row['post_type'],
					'postDate' => $row['post_date'],
					'isMultisite' => $blog['isMultisite'],
					'domain' => $blog['domain'],
					'path' => $blog['path'],
					'blog_id' => $blog['blog_id']
					);

			}
		}
		$this->status(2, 'info', "Examining URLs found in posts we scanned for dangerous websites");
		$hooverResults = $h->getBaddies();
		$this->status(2, 'info', "Done examining URls");
		if($h->errorMsg){
			$this->errorStop($h->errorMsg);
			wordfence::statusEndErr();
			return;
		
		}
		$haveIssues = false;
		foreach($hooverResults as $idString => $hresults){
			$arr = explode('-', $idString);
			$blogID = $arr[0];
			$postID = $arr[1];
			$uctype = ucfirst($postDat[$idString]['type']);
			$type = $postDat[$idString]['type'];
			foreach($hresults as $result){
				if($result['badList'] == 'goog-malware-shavar'){
					$shortMsg = "$uctype contains a suspected malware URL.";
					$longMsg = "This $type contains a suspected malware URL listed on Google's list of malware sites. The URL is: " . $result['URL'] . " - More info available at <a href=\"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=" . urlencode($result['URL']) . "&client=googlechrome&hl=en-US\" target=\"_blank\">Google Safe Browsing diagnostic page</a>.";
				} else if($result['badList'] == 'googpub-phish-shavar'){
					$shortMsg = "$uctype contains a suspected phishing site URL.";
					$longMsg = "This $type contains a URL that is a suspected phishing site that is currently listed on Google's list of known phishing sites. The URL is: " . $result['URL'];
				} else {
					//A list type that may be new and the plugin has not been upgraded yet.
					continue;
				}
				$this->status(2, 'info', "Adding issue: $shortMsg");
				if(is_multisite()){
					switch_to_blog($blogID);
				}
				$ignoreP = $idString;
				$ignoreC = $idString . $postDat[$idString]['contentMD5'];
				if($this->addIssue('postBadURL', 1, $ignoreP, $ignoreC, $shortMsg, $longMsg, array(
					'postID' => $postID,
					'badURL' => $result['URL'],
					'postTitle' => $postDat[$idString]['title'],
					'type' => $postDat[$idString]['type'],
					'uctype' => $uctype,
					'permalink' => get_permalink($postID),
					'editPostLink' => get_edit_post_link($postID),
					'postDate' => $postDat[$idString]['postDate'],
					'isMultisite' => $postDat[$idString]['isMultisite'],
					'domain' => $postDat[$idString]['domain'],
					'path' => $postDat[$idString]['path'],
					'blog_id' => $blogID
					))){
					$haveIssues = true;
				}
				if(is_multisite()){
					restore_current_blog();
				}
			}
		}
		wordfence::statusEnd($statusIDX, $haveIssues);
	}
	public function isBadComment($author, $email, $url, $IP, $content){
		$content = $author . ' ' . $email . ' ' . $url . ' ' . $IP . ' ' . $content;
		$cDesc = '';
		if($author){
			$cDesc = "Author: $author ";
		}
		if($email){
			$cDesc .= "Email: $email ";
		}
		$cDesc = "Source IP: $IP ";
		$this->status(2, 'info', "Scanning comment with $cDesc");

		$h = new wordfenceURLHoover($this->apiKey, $this->wp_version);
		$h->hoover(1, $content);
		$hooverResults = $h->getBaddies();
		if($h->errorMsg){
			return false;
		}
		if(sizeof($hooverResults) > 0 && isset($hooverResults[1])){
			$hresults = $hooverResults[1];	
			foreach($hresults as $result){
				if($result['badList'] == 'goog-malware-shavar'){
					$this->status(2, 'info', "Marking comment as spam for containing a malware URL. Comment has $cDesc");
					return true;
				} else if($result['badList'] == 'googpub-phish-shavar'){
					$this->status(2, 'info', "Marking comment as spam for containing a phishing URL. Comment has $cDesc");
					return true;
				} else {
					//A list type that may be new and the plugin has not been upgraded yet.
					continue;
				}
			}
		}
		$this->status(2, 'info', "Scanned comment with $cDesc");
		return false;
	}
	private function scanComments(){
		$statusIDX = wordfence::statusStart('Scanning comments for URL\'s in Google\'s Safe Browsing List');
		global $wpdb;
		$wfdb = new wfDB();
		$commentDat = array();
		$h = new wordfenceURLHoover($this->apiKey, $this->wp_version);
		$blogsToScan = $this->getBlogsToScan('comments');
		foreach($blogsToScan as $blog){
			$q1 = $wfdb->query("select comment_ID from " . $blog['table'] . " where comment_approved=1");
			if( ! $q1){
				wordfence::statusEndErr();
				return;
			}
			if(! (mysql_num_rows($q1) > 0)){
				continue;
			}
			
			while($idRow = mysql_fetch_assoc($q1)){
				$row = $wfdb->querySingleRec("select comment_ID, comment_date, comment_type, comment_author, comment_author_url, comment_content from " . $blog['table'] . " where comment_ID=%d", $idRow['comment_ID']);
				$h->hoover($blog['blog_id'] . '-' . $row['comment_ID'], $row['comment_author_url'] . ' ' . $row['comment_author'] . ' ' . $row['comment_content']);
				$commentDat[$blog['blog_id'] . '-' . $row['comment_ID']] = array(
					'contentMD5' => md5($row['comment_content'] . $row['comment_author'] . $row['comment_author_url']),
					'author' => $row['comment_author'],
					'type' => ($row['comment_type'] ? $row['comment_type'] : 'comment'),
					'date' => $row['comment_date'],
					'isMultisite' => $blog['isMultisite'],
					'domain' => $blog['domain'],
					'path' => $blog['path'],
					'blog_id' => $blog['blog_id']
					);
			}
		}
		$hooverResults = $h->getBaddies();
		if($h->errorMsg){
			$this->errorStop($h->errorMsg);
			wordfence::statusEndErr();
			return;
		}
		$haveIssues = false;
		foreach($hooverResults as $idString => $hresults){
			$arr = explode('-', $idString);
			$blogID = $arr[0];
			$commentID = $arr[1];
			$uctype = ucfirst($commentDat[$idString]['type']);
			$type = $commentDat[$idString]['type'];
			foreach($hresults as $result){
				if($result['badList'] == 'goog-malware-shavar'){
					$shortMsg = "$uctype contains a suspected malware URL.";
					$longMsg = "This $type contains a suspected malware URL listed on Google's list of malware sites. The URL is: " . $result['URL'] . " - More info available at <a href=\"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=" . urlencode($result['URL']) . "&client=googlechrome&hl=en-US\" target=\"_blank\">Google Safe Browsing diagnostic page</a>.";
				} else if($result['badList'] == 'googpub-phish-shavar'){
					$shortMsg = "$uctype contains a suspected phishing site URL.";
					$longMsg = "This $type contains a URL that is a suspected phishing site that is currently listed on Google's list of known phishing sites. The URL is: " . $result['URL'];
				} else {
					//A list type that may be new and the plugin has not been upgraded yet.
					continue;
				}
				if(is_multisite()){
					switch_to_blog($blogID);
				}
				$ignoreP = $idString;
				$ignoreC = $idString . '-' . $commentDat[$idString]['contentMD5'];
				if($this->addIssue('commentBadURL', 1, $ignoreP, $ignoreC, $shortMsg, $longMsg, array(
					'commentID' => $commentID,
					'badURL' => $result['URL'],
					'author' => $commentDat[$idString]['author'],
					'type' => $type,
					'uctype' => $uctype,
					'editCommentLink' => get_edit_comment_link($commentID),
					'commentDate' => $commentDat[$idString]['date'],
					'isMultisite' => $commentDat[$idString]['isMultisite'],
					'domain' => $commentDat[$idString]['domain'],
					'path' => $commentDat[$idString]['path'],
					'blog_id' => $blogID
					))){
					$haveIssues = true;
				}
				if(is_multisite()){
					restore_current_blog();
				}
			}
		}
		wordfence::statusEnd($statusIDX, $haveIssues);
	}
	public function getBlogsToScan($table){
		$wfdb = new wfDB();
		global $wpdb;
		$prefix = $wpdb->base_prefix;
		$blogsToScan = array();
		if(is_multisite()){
			$q1 = $wfdb->query("select blog_id, domain, path from $prefix"."blogs where deleted=0 order by blog_id asc");
			while($row = mysql_fetch_assoc($q1)){
				$row['isMultisite'] = true;
				if($row['blog_id'] == 1){
					$row['table'] = $prefix . $table;
				} else {
					$row['table'] = $prefix . $row['blog_id'] . '_' . $table;
				}
				array_push($blogsToScan, $row); 
			}
		} else {
			array_push($blogsToScan, array(
				'isMultisite' => false,
				'table' => $prefix . $table,
				'blog_id' => '1',
				'domain' => '',
				'path' => '',
				));
		}
		return $blogsToScan;
	}
	private function highestCap($caps){
		foreach(array('administrator', 'editor', 'author', 'contributor', 'subscriber') as $cap){
			if(empty($caps[$cap]) === false && $caps[$cap]){
				return $cap;
			}
		}
		return '';
	}
	private function isEditor($caps){
		foreach(array('contributor', 'author', 'editor', 'administrator') as $cap){
			if(empty($caps[$cap]) === false && $caps[$cap]){
				return true;
			}
		}
		return false;
	}
	private function scanAllPasswords(){
		$statusIDX = wordfence::statusStart('Scanning for weak passwords');
		global $wpdb;
		$ws = $wpdb->get_results("SELECT ID, user_login FROM $wpdb->users");
		$haveIssues = false;
		foreach($ws as $user){
			$this->status(2, 'info', "Checking password strength for: " . $user->user_login);
			$isWeak = $this->scanUserPassword($user->ID);
			if($isWeak){ $haveIssues = true; }
		}
		wordfence::statusEnd($statusIDX, $haveIssues);
	}
	public function scanUserPassword($userID){
		require_once( ABSPATH . 'wp-includes/class-phpass.php');
		$hasher = new PasswordHash(8, TRUE);
		$userDat = get_userdata($userID);
		$this->status(2, 'info', "Checking password strength of user '" . $userDat->user_login . "'");
		$shortMsg = "";
		$longMsg = "";
		$level = 1;
		$highCap = $this->highestCap($userDat->wp_capabilities);
		if($this->isEditor($userDat->wp_capabilities)){ 
			$shortMsg = "A user with '" . $highCap . "' access has an easy password.";
			$longMsg = "A user with the a role of '" . $highCap . "' has a password that is easy to guess. Please change this password yourself or ask the user to change it.";
			$level = 1;
			$words = $this->dictWords;
		} else {
			$shortMsg = "A user with 'subscriber' access has a very easy password.";
			$longMsg = "A user with 'subscriber' access has a password that is very easy to guess. Please either change it or ask the user to change their password.";
			$level = 2;
			$words = array($userDat->user_login);
		}
		$haveIssue = false;
		for($i = 0; $i < sizeof($words); $i++){
			if($hasher->CheckPassword($words[$i], $userDat->user_pass)){
				$this->status(2, 'info', "Adding issue " . $shortMsg);
				if($this->addIssue('easyPassword', $level, $userDat->ID, $userDat->ID . '-' . $userDat->user_pass, $shortMsg, $longMsg, array(
					'ID' => $userDat->ID,
					'user_login' => $userDat->user_login,
					'user_email' => $userDat->user_email,
					'first_name' => $userDat->first_name,
					'last_name' => $userDat->last_name,
					'editUserLink' => wfUtils::editUserLink($userDat->ID)
					))){
					$haveIssue = true;
				}
				break;
			}
		}
		$this->status(2, 'info', "Completed checking password strength of user '" . $userDat->user_login . "'");
		return $haveIssue;
	}
	private function scanDiskSpace(){
		$statusIDX = wordfence::statusStart("Scanning to check available disk space");
		$total = disk_total_space('.');
		$free = disk_free_space('.');
		$this->status(2, 'info', "Total space: $total Free space: $free");
		if( (! $total) || (! $free )){ //If we get zeros it's probably not reading right. If free is zero then we're out of space and already in trouble.
			wordfence::statusEnd($statusIDX, false);
			return;
		}
		$level = false;
		$spaceLeft = sprintf('%.2f', ($free / $total * 100));
		$this->status(2, 'info', "The disk has $spaceLeft percent space available");
		if($spaceLeft < 3){
			$level = 1;
		} else if($spaceLeft < 5){
			$level = 2;
		} else {
			wordfence::statusEnd($statusIDX, false);
			return;
		}
		if($this->addIssue('diskSpace', $level, 'diskSpace' . $level, 'diskSpace' . $level, "You have $spaceLeft" . "% disk space remaining", "You only have $spaceLeft" . "% of your disk space remaining. Please free up disk space or your website may stop serving requests.", array(
			'spaceLeft' => $spaceLeft ))){
			wordfence::statusEnd($statusIDX, true);
		} else {
			wordfence::statusEnd($statusIDX, true);
		}
	}
	private function scanDNSChanges(){
		if(! function_exists('dns_get_record')){
			$this->status(1, 'info', "Skipping DNS scan because this system does not support dns_get_record()");
			return;
		}
		$statusIDX = wordfence::statusStart("Scanning DNS for unauthorized changes");
		$haveIssues = false;
		$home = get_home_url();
		if(preg_match('/https?:\/\/([^\/]+)/i', $home, $matches)){
			$host = strtolower($matches[1]);
			$this->status(2, 'info', "Starting DNS scan for $host");

			$cnameArrRec = dns_get_record($host, DNS_CNAME);
			$cnameArr = array(); 
			$cnamesWeMustTrack = array();
			foreach($cnameArrRec as $elem){ 
				$this->status(2, 'info', "Scanning CNAME DNS record for " . $elem['host']);
				if($elem['host'] == $host){ 
					array_push($cnameArr, $elem); 
					$cnamesWeMustTrack[] = $elem['target'];
				} 
			}
			function wfAnonFunc1($a){ return $a['host'] . ' points to ' . $a['target']; }
			$cnameArr = array_map('wfAnonFunc1', $cnameArr);
			sort($cnameArr, SORT_STRING);
			$currentCNAME = implode(', ', $cnameArr);
			$loggedCNAME = wfConfig::get('wf_dnsCNAME');
			$dnsLogged = wfConfig::get('wf_dnsLogged', false);
			$msg = "A change in your DNS records may indicate that a hacker has hacked into your DNS administration system and has pointed your email or website to their own server for malicious purposes. It could also indicate that your domain has expired. If you made this change yourself you can mark it 'resolved' and safely ignore it.";
			if($dnsLogged && $loggedCNAME != $currentCNAME){
				if($this->addIssue('dnsChange', 2, 'dnsChanges', 'dnsChanges', "Your DNS records have changed", "We have detected a change in the CNAME records of your DNS configuration for the domain $host. A CNAME record is an alias that is used to point a domain name to another domain name. For example foo.example.com can point to bar.example.com which then points to an IP address of 10.1.1.1. $msg", array( 
					'type' => 'CNAME',
					'host' => $host,
					'oldDNS' => $loggedCNAME,
					'newDNS' => $currentCNAME
					))){
					$haveIssues = true;
				}
			}
			wfConfig::set('wf_dnsCNAME', $currentCNAME);

			$aArrRec = dns_get_record($host, DNS_A); 
			$aArr = array();
			foreach($aArrRec as $elem){ 
				$this->status(2, 'info', "Scanning DNS A record for " . $elem['host']);
				if($elem['host'] == $host || in_array($elem['host'], $cnamesWeMustTrack) ){ 
					array_push($aArr, $elem); 
				} 
			}
			function wfAnonFunc2($a){ return $a['host'] . ' points to ' . $a['ip']; }
			$aArr = array_map('wfAnonFunc2', $aArr);
			sort($aArr, SORT_STRING);
			$currentA = implode(', ', $aArr);
			$loggedA = wfConfig::get('wf_dnsA');
			$dnsLogged = wfConfig::get('wf_dnsLogged', false);
			if($dnsLogged && $loggedA != $currentA){
				if($this->addIssue('dnsChange', 2, 'dnsChanges', 'dnsChanges', "Your DNS records have changed", "We have detected a change in the A records of your DNS configuration that may affect the domain $host. An A record is a record in DNS that points a domain name to an IP address. $msg", array( 
					'type' => 'A',
					'host' => $host,
					'oldDNS' => $loggedA,
					'newDNS' => $currentA
					))){
					$haveIssues = true;
				}
			}
			wfConfig::set('wf_dnsA', $currentA);



			$mxArrRec = dns_get_record($host, DNS_MX); 
			$mxArr = array();
			foreach($mxArrRec as $elem){
				$this->status(2, 'info', "Scanning DNS MX record for " . $elem['host']); 
				if($elem['host'] == $host){ 
					array_push($mxArr, $elem); 
				} 
			}
			function wfAnonFunc3($a){ return $a['target']; }
			$mxArr = array_map('wfAnonFunc3', $mxArr);
			sort($mxArr, SORT_STRING);
			$currentMX = implode(', ', $mxArr);
			$loggedMX = wfConfig::get('wf_dnsMX');
			if($dnsLogged && $loggedMX != $currentMX){
				if($this->addIssue('dnsChange', 2, 'dnsChanges', 'dnsChanges', "Your DNS records have changed", "We have detected a change in the email server (MX) records of your DNS configuration for the domain $host. $msg", array( 
					'type' => 'MX',
					'host' => $host,
					'oldDNS' => $loggedMX,
					'newDNS' => $currentMX
					))){
					$haveIssues = true;
				}
			
			}
			wfConfig::set('wf_dnsMX', $currentMX);
				
			wfConfig::set('wf_dnsLogged', 1);
		}
		wordfence::statusEnd($statusIDX, $haveIssues);
	}
	private function scanOldVersions(){
		$statusIDX = wordfence::statusStart("Scanning for old themes, plugins and core files");
		if(! function_exists( 'get_preferred_from_update_core')){
			require_once(ABSPATH . 'wp-admin/includes/update.php');
		}
		$cur = get_preferred_from_update_core();
		$haveIssues = false;
		if(isset( $cur->response ) && $cur->response == 'upgrade'){
			if($this->addIssue('wfUpgrade', 1, 'wfUpgrade' . $cur->current, 'wfUpgrade' . $cur->current, "Your WordPress version is out of date", "WordPress version " . $cur->current . " is now available. Please upgrade immediately to get the latest security updates from WordPress.", array(
				'currentVersion' => $this->wp_version,
				'newVersion' => $cur->current
				))){
				$haveIssues = true;
			}
		}
		$update_plugins = get_site_transient( 'update_plugins' );
		if(isset($update_plugins) && (! empty($update_plugins->response))){
			if(isset($update_plugins) && $update_plugins->response){
				foreach($update_plugins->response as $plugin => $vals){
					if(! function_exists( 'get_plugin_data')){
						require_once ABSPATH . '/wp-admin/includes/plugin.php';
					}
					$pluginFile = wfUtils::getPluginBaseDir() . $plugin;
					$data = get_plugin_data($pluginFile);
					$data['newVersion'] = $vals->new_version;
					$key = 'wfPluginUpgrade' . ' ' . $plugin . ' ' . $data['newVersion'] . ' ' . $data['Version'];
					if($this->addIssue('wfPluginUpgrade', 1, $key, $key, "The Plugin \"" . $data['Name'] . "\" needs an upgrade.", "You need to upgrade \"" . $data['Name'] . "\" to the newest version to ensure you have any security fixes the developer has released.", $data)){
						$haveIssues = true;
					}
				}
			}
		}
		$update_themes = get_site_transient( 'update_themes' );
		if(isset($update_themes) && (! empty($update_themes->response))){
			if(! function_exists( 'get_themes')){
				require_once ABSPATH . '/wp-includes/theme.php';
			}
			$themes = get_themes();
			foreach($update_themes->response as $theme => $vals){
				foreach($themes as $name => $themeData){
					if(strtolower($name) == $theme){
						$tData = array(
							'newVersion' => $vals['new_version'],
							'package' => $vals['package'],
							'URL' => $vals['url'],
							'name' => $themeData['Name'],
							'version' => $themeData['Version']
							);
						$key = 'wfThemeUpgrade' . ' ' . $theme . ' ' . $tData['version'] . ' ' . $tData['newVersion'];
						if($this->addIssue('wfThemeUpgrade', 1, $key, $key, "The Theme \"" . $themeData['Name'] . "\" needs an upgrade.", "You need to upgrade \"" . $themeData['Name'] . "\" to the newest version to ensure you have any security fixes the developer has released.", $tData)){
							$haveIssues = true;
						}
					}
				}

			}
		}
		wordfence::statusEnd($statusIDX, $haveIssues);
	}
	private function errorStop($msg){
		$this->errorStopped = true;
		$this->status(1, 'error', $msg);
		wfConfig::set('lastScanCompleted', $msg);
	}
	public function status($level, $type, $msg){
		wordfence::status($level, $type, $msg);
	}
	private function addIssue($type, $severity, $ignoreP, $ignoreC, $shortMsg, $longMsg, $templateData){
		return $this->i->addIssue($type, $severity, $ignoreP, $ignoreC, $shortMsg, $longMsg, $templateData);
	}
}

?>
