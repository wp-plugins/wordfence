<?php
require_once('wordfenceClass.php');
require_once('wordfenceHash.php');
require_once('wfAPI.php');
require_once('wordfenceScanner.php');
require_once('wfIssues.php');
require_once('wfDB.php');
require_once('wfUtils.php');
class wfScanEngine {
	private $api = false;
	private $dictWords = array();

	//Beginning of serialized properties on sleep
	private $hasher = false;
	private $hashes = false;
	private $jobList = array();
	private $i = false;
	private $wp_version = false;
	private $apiKey = false;
	private $errorStopped = false;
	private $startTime = 0;
	private $scanStep = 0;
	private $maxExecTime = 10; //If more than $maxExecTime has elapsed since last check, fork a new scan process and continue
	private $malwareScanEnabled = false;
	private $pluginScanEnabled = false;
	private $coreScanEnabled = false;
	private $themeScanEnabled = false;
	private $unknownFiles = array();
	private $fileContentsResults = false;
	private $scanner = false;
	private $scanQueue = array();
	private $hoover = false;
	private $scanData = array();
	private $statusIDX = array(
			'core' => false,
			'plugin' => false,
			'theme' => false,
			'unknown' => false
			);
	public function __sleep(){ //Same order here as above for properties that are included in serialization
		return array('hasher', 'hashes', 'jobList', 'i', 'wp_version', 'apiKey', 'errorStopped', 'startTime', 'scanStep', 'maxExecTime', 'malwareScanEnabled', 'pluginScanEnabled', 'coreScanEnabled', 'themeScanEnabled', 'unknownFiles', 'fileContentsResults', 'scanner', 'scanQueue', 'hoover', 'scanData', 'statusIDX');
	}
	public function __construct(){
		$this->startTime = time();
		$this->i = new wfIssues();
		$this->i->deleteNew();
		$this->cycleStartTime = time();
		$this->wp_version = wfUtils::getWPVersion();
		$this->apiKey = wfConfig::get('apiKey');
		$this->api = new wfAPI($this->apiKey, $this->wp_version);
		include('wfDict.php'); //$dictWords
		$this->dictWords = $dictWords;
		foreach(array('init', 'main', 'finish') as $op){ $this->jobList[] = 'knownFiles_' . $op; };
		foreach(array('fileContents', 'posts', 'comments', 'passwds', 'dns', 'diskSpace', 'oldVersions') as $scanType){
			if(wfConfig::get('scansEnabled_' . $scanType)){
				if(method_exists($this, 'scan_' . $scanType . '_init')){
					foreach(array('init', 'main', 'finish') as $op){ $this->jobList[] = $scanType . '_' . $op; };
				} else {
					$this->jobList[] = $scanType;
				}
			}
		}
	}
	public function __wakeup(){
		$this->cycleStartTime = time();
		$this->api = new wfAPI($this->apiKey, $this->wp_version);
		include('wfDict.php'); //$dictWords
		$this->dictWords = $dictWords;
	}
	public function go(){
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
	public function forkIfNeeded(){
		if(time() - $this->cycleStartTime > $this->maxExecTime){
			wordfence::status(2, 'info', "Forking during hash scan to ensure continuity.");
			$this->fork();
		}
	}
	public function fork(){
		wfConfig::set_ser('wfsd_engine', $this, true);
		wfUtils::clearScanLock();
		self::startScan(true);
		exit(0);
	}
	public function emailNewIssues(){
		$this->i->emailNewIssues();
	}
	private function doScan(){
		while(sizeof($this->jobList) > 0){
			$jobName = $this->jobList[0];
			call_user_func(array($this, 'scan_' . $jobName));
			array_shift($this->jobList); //only shift once we're done because we may pause halfway through a job and need to pick up where we left off
			if($this->errorStopped){
				return;
			}
			$this->fork();
		}
		$summary = $this->i->getSummaryItems();
		$this->status(1, 'info', "Scan Complete. Scanned " . $summary['totalFiles'] . " files, " . $summary['totalPlugins'] . " plugins, " . $summary['totalThemes'] . " themes, " . ($summary['totalPages'] + $summary['totalPosts']) . " pages, " . $summary['totalComments'] . " comments and " . $summary['totalRows'] . " records in " . (time() - $this->startTime) . " seconds.");
		if($this->i->totalIssues  > 0){
			$this->status(10, 'info', "SUM_FINAL:Scan complete. You have " . $this->i->totalIssues . " new issues to fix. See below for details.");
		} else {
			$this->status(10, 'info', "SUM_FINAL:Scan complete. Congratulations, there were no problems found.");
		}
		return;
	}
	public function getCurrentJob(){
		return $this->jobList[0];
	}
	private function scan_knownFiles_init(){
		$this->status(1, 'info', "Contacting Wordfence to initiate scan");
		$this->api->call('log_scan', array(), array());
		if($this->api->errorMsg){
			$this->errorStop($this->api->errorMsg);
			return;
		}
		if(wfConfig::get('scansEnabled_core')){
			$this->coreScanEnabled = true;
			$this->statusIDX['core'] = wordfence::statusStart("Comparing core WordPress files against originals in repository");
		} else {
			wordfence::statusDisabled("Skipping core scan");
		}
		if(wfConfig::get('isPaid')){
			if(wfConfig::get('scansEnabled_plugins')){
				$this->pluginScanEnabled = true;
				$this->statusIDX['plugin'] = wordfence::statusStart("Premium: Comparing plugin files against originals in repository");
			} else {
				wordfence::statusDisabled("Skipping comparing plugin files against originals in repository");
			}
		} else {
			wordfence::statusPaidOnly("Skipping comparing plugin files against originals in repository");
		}
		if(wfConfig::get('isPaid')){
			if(wfConfig::get('scansEnabled_themes')){
				$this->themeScanEnabled = true;
				$this->statusIDX['theme'] = wordfence::statusStart("Premium: Comparing theme files against originals in repository");
			} else {
				wordfence::statusDisabled("Skipping comparing theme files against originals in repository");
			}
		} else {
			wordfence::statusPaidOnly("Skipping comparing theme files against originals in repository");
		}
	
		if(wfConfig::get('scansEnabled_malware')){
			$this->statusIDX['unknown'] = wordfence::statusStart("Scanning for known malware files");
			$this->malwareScanEnabled = true;
		} else {
			wordfence::statusDisabled("Skipping malware scan");
			$this->status(2, 'info', "Skipping malware scan because it's disabled.");
		}
		if((! $this->i->summaryUpdateRequired()) && (! ($this->coreScanEnabled || $this->pluginScanEnabled || $this->themeScanEnabled || $this->malwareScanEnabled))){
			$this->status(2, 'info', "Finishing this stage because we don't have to do a summary update and we don't need to do a core, plugin, theme or malware scan.");
			return array();
		}
			
		//CORE SCAN
		$this->hasher = new wordfenceHash(strlen(ABSPATH));
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
		$this->hasher->buildFileQueue(ABSPATH, $includeInScan);
	}
	private function scan_knownFiles_main(){
		$this->hashes = $this->hasher->genHashes($this);
	}
	private function scan_knownFiles_finish(){
		$this->status(2, 'info', "Done hash. Updating summary items.");
		$this->i->updateSummaryItem('totalData', wfUtils::formatBytes($this->hasher->totalData));
		$this->i->updateSummaryItem('totalFiles', $this->hasher->totalFiles);
		$this->i->updateSummaryItem('totalDirs', $this->hasher->totalDirs);
		$this->i->updateSummaryItem('linesOfPHP', $this->hasher->linesOfPHP);
		$this->i->updateSummaryItem('linesOfJCH', $this->hasher->linesOfJCH);

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
		if(! ($this->coreScanEnabled || $this->pluginScanEnabled || $this->themeScanEnabled || $this->malwareScanEnabled)){
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
			'pluginScanEnabled' => $this->pluginScanEnabled,
			'themeScanEnabled' => $this->themeScanEnabled,
			'coreScanEnabled' => $this->coreScanEnabled,
			'malwareScanEnabled' => $this->malwareScanEnabled,
			'plugins' => $plugins,
			'themes' => $themes,
			'hashes' => wordfenceHash::bin2hex($this->hashes) 
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
			if($this->statusIDX[$type] !== false){
				wordfence::statusEnd($this->statusIDX[$type], $have);
			}
		}

		$this->unknownFiles = $result1['unknownFiles'];
	}
	private function scan_fileContents_init(){
		$this->statusIDX['infect'] = wordfence::statusStart('Scanning file contents for infections and vulnerabilities');
		$this->statusIDX['GSB'] = wordfence::statusStart('Scanning files for URLs in Google\'s Safe Browsing List');
		if(! is_array($this->unknownFiles)){
			$this->unknownFiles = array();
		}
		$this->scanner = new wordfenceScanner($this->apiKey, $this->wp_version, $this->unknownFiles, ABSPATH);
		$this->unknownFiles = false;
		$this->status(2, 'info', "Starting scan of file contents");
	}
	private function scan_fileContents_main(){
		$this->fileContentsResults = $this->scanner->scan($this);
	}
	private function scan_fileContents_finish(){
		$this->status(2, 'info', "Done file contents scan");
		if($this->scanner->errorMsg){
			$this->errorStop($this->scanner->errorMsg);
		}
		$this->scanner = null;
		$haveIssues = false;
		$haveIssuesGSB = false;
		foreach($this->fileContentsResults as $issue){
			$this->status(2, 'info', "Adding issue: " . $issue['shortMsg']);
			if($this->addIssue($issue['type'], $issue['severity'], $issue['ignoreP'], $issue['ignoreC'], $issue['shortMsg'], $issue['longMsg'], $issue['data'])){
				if(empty($issue['data']['gsb']) === false){
					$haveIssuesGSB = true;
				} else {
					$haveIssues = true;
				}
			}
		}
		$this->fileContentsResults = null;
		wordfence::statusEnd($this->statusIDX['infect'], $haveIssues);
		wordfence::statusEnd($this->statusIDX['GSB'], $haveIssuesGSB);
	}
	private function scan_posts_init(){
		$this->statusIDX['posts'] = wordfence::statusStart('Scanning posts for URL\'s in Google\'s Safe Browsing List');
		$blogsToScan = $this->getBlogsToScan('posts');
		$wfdb = new wfDB();
		$this->hoover = new wordfenceURLHoover($this->apiKey, $this->wp_version);
		foreach($blogsToScan as $blog){
			$q1 = $wfdb->query("select ID from " . $blog['table'] . " where post_type IN ('page', 'post') and post_status = 'publish'");
			while($idRow = mysql_fetch_assoc($q1)){
				$this->scanQueue[] = array($blog, $idRow['ID']);
			}
		}
	}
	private function scan_posts_main(){
		$wfdb = new wfDB();
		while($elem = array_shift($this->scanQueue)){
			$blog = $elem[0];
			$postID = $elem[1];
			$row = $wfdb->querySingleRec("select ID, post_title, post_type, post_date, post_content from " . $blog['table'] . " where ID=%d", $postID);
			$this->hoover->hoover($blog['blog_id'] . '-' . $row['ID'], $row['post_title'] . ' ' . $row['post_content']);
			$this->scanData[$blog['blog_id'] . '-' . $row['ID']] = array(
				'contentMD5' => md5($row['post_content']),
				'title' => $row['post_title'],
				'type' => $row['post_type'],
				'postDate' => $row['post_date'],
				'isMultisite' => $blog['isMultisite'],
				'domain' => $blog['domain'],
				'path' => $blog['path'],
				'blog_id' => $blog['blog_id']
				);
			$this->forkIfNeeded();
		}
	}
	private function scan_posts_finish(){
		$this->status(2, 'info', "Examining URLs found in posts we scanned for dangerous websites");
		$hooverResults = $this->hoover->getBaddies();
		$this->status(2, 'info', "Done examining URls");
		if($this->hoover->errorMsg){
			$this->errorStop($this->hoover->errorMsg);
			wordfence::statusEndErr();
			return;
		
		}
		$haveIssues = false;
		foreach($hooverResults as $idString => $hresults){
			$arr = explode('-', $idString);
			$blogID = $arr[0];
			$postID = $arr[1];
			$uctype = ucfirst($this->scanData[$idString]['type']);
			$type = $this->scanData[$idString]['type'];
			foreach($hresults as $result){
				if($result['badList'] == 'goog-malware-shavar'){
					$shortMsg = "$uctype contains a suspected malware URL: " . $this->scanData[$idString]['title'];
					$longMsg = "This $type contains a suspected malware URL listed on Google's list of malware sites. The URL is: " . $result['URL'] . " - More info available at <a href=\"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=" . urlencode($result['URL']) . "&client=googlechrome&hl=en-US\" target=\"_blank\">Google Safe Browsing diagnostic page</a>.";
				} else if($result['badList'] == 'googpub-phish-shavar'){
					$shortMsg = "$uctype contains a suspected phishing site URL: " . $this->scanData[$idString]['title'];
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
				$ignoreC = $idString . $this->scanData[$idString]['contentMD5'];
				if($this->addIssue('postBadURL', 1, $ignoreP, $ignoreC, $shortMsg, $longMsg, array(
					'postID' => $postID,
					'badURL' => $result['URL'],
					'postTitle' => $this->scanData[$idString]['title'],
					'type' => $this->scanData[$idString]['type'],
					'uctype' => $uctype,
					'permalink' => get_permalink($postID),
					'editPostLink' => get_edit_post_link($postID),
					'postDate' => $this->scanData[$idString]['postDate'],
					'isMultisite' => $this->scanData[$idString]['isMultisite'],
					'domain' => $this->scanData[$idString]['domain'],
					'path' => $this->scanData[$idString]['path'],
					'blog_id' => $blogID
					))){
					$haveIssues = true;
				}
				if(is_multisite()){
					restore_current_blog();
				}
			}
		}
		$this->scanData = array();
		wordfence::statusEnd($this->statusIDX['posts'], $haveIssues);
	}
	private function scan_comments_init(){
		$this->statusIDX['comments'] = wordfence::statusStart('Scanning comments for URL\'s in Google\'s Safe Browsing List');
		$this->scanData = array();
		$this->scanQueue = array();
		$this->hoover = new wordfenceURLHoover($this->apiKey, $this->wp_version);
		$blogsToScan = $this->getBlogsToScan('comments');
		$wfdb = new wfDB();
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
				$this->scanQueue[] = array($blog, $idRow['comment_ID']);
			}
		}
	}
	private function scan_comments_main(){
		$wfdb = new wfDB();
		while($elem = array_shift($this->scanQueue)){
			$blog = $elem[0];
			$commentID = $elem[1];
			$row = $wfdb->querySingleRec("select comment_ID, comment_date, comment_type, comment_author, comment_author_url, comment_content from " . $blog['table'] . " where comment_ID=%d", $commentID);
			$this->hoover->hoover($blog['blog_id'] . '-' . $row['comment_ID'], $row['comment_author_url'] . ' ' . $row['comment_author'] . ' ' . $row['comment_content']);
			$this->scanData[$blog['blog_id'] . '-' . $row['comment_ID']] = array(
				'contentMD5' => md5($row['comment_content'] . $row['comment_author'] . $row['comment_author_url']),
				'author' => $row['comment_author'],
				'type' => ($row['comment_type'] ? $row['comment_type'] : 'comment'),
				'date' => $row['comment_date'],
				'isMultisite' => $blog['isMultisite'],
				'domain' => $blog['domain'],
				'path' => $blog['path'],
				'blog_id' => $blog['blog_id']
				);
			$this->forkIfNeeded();
		}
	}
	private function scan_comments_finish(){
		$hooverResults = $this->hoover->getBaddies();
		if($this->hoover->errorMsg){
			$this->errorStop($this->hoover->errorMsg);
			wordfence::statusEndErr();
			return;
		}
		$haveIssues = false;
		foreach($hooverResults as $idString => $hresults){
			$arr = explode('-', $idString);
			$blogID = $arr[0];
			$commentID = $arr[1];
			$uctype = ucfirst($this->scanData[$idString]['type']);
			$type = $this->scanData[$idString]['type'];
			foreach($hresults as $result){
				if($result['badList'] == 'goog-malware-shavar'){
					$shortMsg = "$uctype with author " . $this->scanData[$idString]['author'] . " contains a suspected malware URL.";
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
				$ignoreC = $idString . '-' . $this->scanData[$idString]['contentMD5'];
				if($this->addIssue('commentBadURL', 1, $ignoreP, $ignoreC, $shortMsg, $longMsg, array(
					'commentID' => $commentID,
					'badURL' => $result['URL'],
					'author' => $this->scanData[$idString]['author'],
					'type' => $type,
					'uctype' => $uctype,
					'editCommentLink' => get_edit_comment_link($commentID),
					'commentDate' => $this->scanData[$idString]['date'],
					'isMultisite' => $this->scanData[$idString]['isMultisite'],
					'domain' => $this->scanData[$idString]['domain'],
					'path' => $this->scanData[$idString]['path'],
					'blog_id' => $blogID
					))){
					$haveIssues = true;
				}
				if(is_multisite()){
					restore_current_blog();
				}
			}
		}
		wordfence::statusEnd($this->statusIDX['comments'], $haveIssues);
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
	private function scan_passwds(){
		$this->statusIDX['passwds'] = wordfence::statusStart('Scanning for weak passwords');
		global $wpdb;
		$ws = $wpdb->get_results("SELECT ID, user_login FROM $wpdb->users");
		$haveIssues = false;
		foreach($ws as $user){
			$this->status(2, 'info', "Checking password strength for: " . $user->user_login);
			$isWeak = $this->scanUserPassword($user->ID);
			if($isWeak){ $haveIssues = true; }
		}
		wordfence::statusEnd($this->statusIDX['passwds'], $haveIssues);
	}
	public function scanUserPassword($userID){
		require_once( ABSPATH . 'wp-includes/class-phpass.php');
		$passwdHasher = new PasswordHash(8, TRUE);
		$userDat = get_userdata($userID);
		$this->status(2, 'info', "Checking password strength of user '" . $userDat->user_login . "'");
		$shortMsg = "";
		$longMsg = "";
		$level = 1;
		$highCap = $this->highestCap($userDat->wp_capabilities);
		if($this->isEditor($userDat->wp_capabilities)){ 
			$shortMsg = "User \"" . $userDat->user_login . "\" with \"" . $highCap . "\" access has an easy password.";
			$longMsg = "A user with the a role of '" . $highCap . "' has a password that is easy to guess. Please change this password yourself or ask the user to change it.";
			$level = 1;
			$words = $this->dictWords;
		} else {
			$shortMsg = "User \"" . $userDat->user_login . "\" with 'subscriber' access has a very easy password.";
			$longMsg = "A user with 'subscriber' access has a password that is very easy to guess. Please either change it or ask the user to change their password.";
			$level = 2;
			$words = array($userDat->user_login);
		}
		$haveIssue = false;
		for($i = 0; $i < sizeof($words); $i++){
			if($passwdHasher->CheckPassword($words[$i], $userDat->user_pass)){
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
	private function scan_diskSpace(){
		$this->statusIDX['diskSpace'] = wordfence::statusStart("Scanning to check available disk space");
		$total = disk_total_space('.');
		$free = disk_free_space('.');
		$this->status(2, 'info', "Total space: $total Free space: $free");
		if( (! $total) || (! $free )){ //If we get zeros it's probably not reading right. If free is zero then we're out of space and already in trouble.
			wordfence::statusEnd($this->statusIDX['diskSpace'], false);
			return;
		}
		$level = false;
		$spaceLeft = sprintf('%.2f', ($free / $total * 100));
		$this->status(2, 'info', "The disk has $spaceLeft percent space available");
		if($spaceLeft < 1){
			$level = 1;
		} else if($spaceLeft < 1.5){
			$level = 2;
		} else {
			wordfence::statusEnd($this->statusIDX['diskSpace'], false);
			return;
		}
		if($this->addIssue('diskSpace', $level, 'diskSpace' . $level, 'diskSpace' . $level, "You have $spaceLeft" . "% disk space remaining", "You only have $spaceLeft" . "% of your disk space remaining. Please free up disk space or your website may stop serving requests.", array(
			'spaceLeft' => $spaceLeft ))){
			wordfence::statusEnd($this->statusIDX['diskSpace'], true);
		} else {
			wordfence::statusEnd($this->statusIDX['diskSpace'], false);
		}
	}
	private function scan_dns(){
		if(! function_exists('dns_get_record')){
			$this->status(1, 'info', "Skipping DNS scan because this system does not support dns_get_record()");
			return;
		}
		$this->statusIDX['dns'] = wordfence::statusStart("Scanning DNS for unauthorized changes");
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
		wordfence::statusEnd($this->statusIDX['dns'], $haveIssues);
	}
	private function scan_oldVersions(){
		$this->statusIDX['oldVersions'] = wordfence::statusStart("Scanning for old themes, plugins and core files");
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
		wordfence::statusEnd($this->statusIDX['oldVersions'], $haveIssues);
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
	public static function startScan($isFork = false){
		wordfence::status(4, 'info', "Entering start scan routine");
		if(wfUtils::isScanRunning()){
			return "A scan is already running.";
		}

		$cron_url = plugins_url('wordfence/wfscan.php?isFork=' . ($isFork ? '1' : '0'));
		wordfence::status(4, 'info', "Cron URL is: " . $cron_url);
		$cronKey = wfUtils::bigRandomHex();
		wordfence::status(4, 'info', "cronKey is: " . $cronKey);
		wfConfig::set('currentCronKey', time() . ',' . $cronKey);
		wordfence::status(4, 'info', "cronKey is set");
		$result = wp_remote_post( $cron_url, array(
			'timeout' => 0.5, 
			'blocking' => true, 
			'sslverify' => false,
			'headers' => array(
				'x-wordfence-cronkey' => $cronKey
				)
			) );
		$procResp = self::processResponse($result);				
		if($procResp){ return $procResp; }
		//If the currentCronKey was eaten, then cron executed so return
		wfConfig::clearCache(); if(! wfConfig::get('currentCronKey')){ 
			wordfence::status(4, 'info', "cronkey is empty so cron executed. Returning.");
			return false; 
		}


		//This request is for hosts that don't know their own name. i.e. they don't have example.com in their hosts file or DNS pointing to their own IP address or loopback address. So we throw a hail mary to loopback.
		wordfence::status(4, 'info', "cronkey is still set so sleeping for 0.2 seconds and checking again before trying another approach");
		usleep(200000);
		wfConfig::clearCache();
		if(wfConfig::get('currentCronKey')){ //cron key is still set, so cron hasn't executed yet. Maybe the request didn't go through
			wordfence::status(4, 'info', "cronkey is still set so about to manually set host header and try again");
			$cron_url2 = preg_replace('/^(https?):\/\/[^\/]+/', '$1://127.0.0.1', $cron_url);
			wordfence::status(4, 'info', "cron url is: $cron_url2");
			$siteURL = site_url();
			wordfence::status(4, 'info', "siteURL is: $siteURL");
			if(preg_match('/^https?:\/\/([^\/]+)/i', site_url(), $matches)){
				$host = $matches[1];
				wordfence::status(4, 'info', "Extracted host $host from siteURL and trying remote post with manual host header set.");
				$result = wp_remote_post( $cron_url2, array(
					'timeout' => 0.5, 
					'blocking' => true, 
					'sslverify' => false,
					'headers' => array(
						'x-wordfence-cronkey' => $cronKey,
						'Host' => $host
						)
					) );
				$procResp = self::processResponse($result);				
				if($procResp){ return $procResp; }
			}
		} else {
			return false;
		}

		//Try again with longer timeout. Dreamhost was giving DNS lookup timeouts
		usleep(200000);
		wfConfig::clearCache();
		if(wfConfig::get('currentCronKey')){
			wordfence::status(4, "info", "cronkey is still set. Trying hostname again with longer timeout.");
			$result = wp_remote_post( $cron_url, array(
				'timeout' => 10, 
				'blocking' => true, 
				'sslverify' => false,
				'headers' => array(
					'x-wordfence-cronkey' => $cronKey
					)
				) );
			$procResp = self::processResponse($result);				
			if($procResp){ return $procResp; }
			//If the currentCronKey was eaten, then cron executed so return
			wfConfig::clearCache(); if(! wfConfig::get('currentCronKey')){ 
				wordfence::status(4, 'info', "cronkey is empty so cron executed. Returning.");
				return false; 
			}
		}
		return false;
	}
	public function processResponse($result){
		if(is_wp_error($result)){
			wordfence::status(4, 'info', "Debug output of WP_Error: " . implode('; ', $result->get_error_messages()) );
		} else {
			if(is_array($result)){
				if(is_array($result['response'])){
					wordfence::status(4, 'info', "POST response: " . $result['response']['code'] . ' ' . $result['response']['message']);
				}
				wordfence::status(4, 'info', "POST response body: " . $result['body']);
			}
		}
		if((! is_wp_error($result)) && is_array($result) && empty($result['body']) === false){
			if(strpos($result['body'], 'WFSOURCEVISIBLE') !== false){
				wordfence::status(4, 'info', "wfscan.php source is visible.");
				$msg = "Wordfence can't run because the source code of your WordPress plugin files is visible from the Internet. This is a serious security risk which you need to fix. Please look for .htaccess files in your WordPress root directory and your wp-content/ and wp-content/plugins/ directories that may contain malicious code designed to reveal your site source code to a hacker.";
				$htfiles = array();
				if(file_exists(ABSPATH . 'wp-content/.htaccess')){
					array_push($htfiles, '<a href="' . wfUtils::getSiteBaseURL() . '?_wfsf=view&nonce=' . wp_create_nonce('wp-ajax') . '&file=wp-content/.htaccess" target="_blank">wp-content/.htaccess</a>');
				}
				if(file_exists(ABSPATH . 'wp-content/plugins/.htaccess')){
					array_push($htfiles, '<a href="' . wfUtils::getSiteBaseURL() . '?_wfsf=view&nonce=' . wp_create_nonce('wp-ajax') . '&file=wp-content/plugins/.htaccess" target="_blank">wp-content/plugins/.htaccess</a>');
				}
				if(sizeof($htfiles) > 0){
					$msg .= "<br /><br />Click to view the .htaccess files below that may be the cause of this problem:<br />" . implode('<br />', $htfiles);
				}
				return $msg;	
					
			} else if(strpos($result['body'], '{') !== false && strpos($result['body'], 'errorMsg') !== false){
				wordfence::status(4, 'info', "Got response from cron containing json");
				$resp = json_decode($result['body'], true);
				if(empty($resp['errorMsg']) === false){
					wordfence::status(4, 'info', "Got an error message from cron: " . $resp['errorMsg']);
					return $resp['errorMsg'];
				}
			}
		}
		return false;
	}
}

?>
