<?php
require_once('wordfenceConstants.php');
require_once('wordfenceClass.php');
require_once('wordfenceURLHoover.php');
class wordfenceScanner {
	//serialized:
	protected $path = '';
	protected $results = array(); 
	public $errorMsg = false;
	private $apiKey = false;
	private $wordpressVersion = '';
	private $totalFilesScanned = 0;
	private $startTime = false;
	private $lastStatusTime = false;
	private $patterns = "";
	public function __sleep(){
		return array('path', 'results', 'errorMsg', 'apiKey', 'wordpressVersion', 'urlHoover', 'totalFilesScanned', 'startTime', 'lastStatusTime', 'patterns');
	}
	public function __wakeup(){
	}
	public function __construct($apiKey, $wordpressVersion, $path){
		$this->apiKey = $apiKey;
		$this->wordpressVersion = $wordpressVersion;
		$this->api = new wfAPI($this->apiKey, $this->wordpressVersion);
		if($path[strlen($path) - 1] != '/'){
			$path .= '/';
		}
		$this->path = $path;
		
		
		$this->results = array();
		$this->errorMsg = false;
		//First extract hosts or IP's and their URL's into $this->hostsFound and URL's into $this->urlsFound
		$this->urlHoover = new wordfenceURLHoover($this->apiKey, $this->wordpressVersion);
		$this->setupSigs();
	}
	private function setupSigs(){
		$this->api = new wfAPI($this->apiKey, $this->wordpressVersion);
		$sigData = $this->api->call('get_patterns', array(), array());	
		if(! (is_array($sigData) && isset($sigData['sigPattern'])) ){
			throw new Exception("Wordfence could not get the attack signature patterns from the scanning server.");
		}
		$this->patterns = $sigData;
	}
	public function scan($forkObj){
		if(! $this->startTime){
			$this->startTime = microtime(true);
		}
		if(! $this->lastStatusTime){
			$this->lastStatusTime = microtime(true);
		}
		$db = new wfDB();
		$keepGoing = true;
		$limitOffset = 0;
		$queryChunkSize = 1000;
		while($keepGoing){
			$keepGoing = false;
			$res1 = $db->querySelect("select filename, filenameMD5, hex(newMD5) as newMD5 from " . $db->prefix() . "wfFileMods where oldMD5 != newMD5 and knownFile=0 limit $limitOffset , $queryChunkSize");
			if(sizeof($res1) > 0){
				$keepGoing = true;
				$limitOffset += $queryChunkSize;
			}

			foreach($res1 as $rec1){
				$db->queryWrite("update " . $db->prefix() . "wfFileMods set oldMD5 = newMD5 where filenameMD5='%s'", $rec1['filenameMD5']); //A way to mark as scanned so that if we come back from a sleep we don't rescan this one.
				$file = $rec1['filename'];
				$fileSum = $rec1['newMD5'];

				if(! file_exists($this->path . $file)){
					continue;
				}
				$fileExt = '';
				if(preg_match('/\.([a-zA-Z\d\-]{1,7})$/', $file, $matches)){
					$fileExt = strtolower($matches[1]);
				}
				$isPHP = false;
				if(preg_match('/^(?:php|phtml|php\d+)$/', $fileExt)){ 
					$isPHP = true;
				}

				if(preg_match('/^(?:jpg|jpeg|mp3|avi|m4v|gif|png)$/', $fileExt)){
					continue;
				}
				if(wfUtils::fileTooBig($this->path . $file)){ //We can't use filesize on 32 bit systems for files > 2 gigs
					//We should not need this check because files > 2 gigs are not hashed and therefore won't be received back as unknowns from the API server
					//But we do it anyway to be safe.
					wordfence::status(2, 'error', "Encountered file that is too large: $file - Skipping.");
					continue;
				}
				$fsize = filesize($this->path . $file); //Checked if too big above
				if($fsize > 1000000){
					$fsize = sprintf('%.2f', ($fsize / 1000000)) . "M";
				} else {
					$fsize = $fsize . "B";
				}
			       if(function_exists('memory_get_usage')){
				       wordfence::status(4, 'info', "Scanning contents: $file (Size:$fsize Mem:" . sprintf('%.1f', memory_get_usage(true) / (1024 * 1024)) . "M)");
			       } else {
				       wordfence::status(4, 'info', "Scanning contents: $file (Size: $fsize)");
			       }

				$stime = microtime(true);
				$fh = @fopen($this->path . $file, 'r');
				if(! $fh){
					continue;
				}
				$totalRead = 0;
				while(! feof($fh)){
					$data = fread($fh, 1 * 1024 * 1024); //read 1 megs max per chunk
					$totalRead += strlen($data);
					if($totalRead < 1){
						break;
					}
					if($isPHP){
						if(strpos($data, '$allowed'.'Sites') !== false && strpos($data, "define ('VER"."SION', '1.") !== false && strpos($data, "TimThum"."b script created by") !== false){
							$this->addResult(array(
								'type' => 'file',
								'severity' => 1,
								'ignoreP' => $this->path . $file,
								'ignoreC' => $fileSum,
								'shortMsg' => "File is an old version of TimThumb which is vulnerable.",
								'longMsg' => "This file appears to be an old version of the TimThumb script which makes your system vulnerable to attackers. Please upgrade the theme or plugin that uses this or remove it.",
								'data' => array(
									'file' => $file,
									'canDiff' => false,
									'canFix' => false,
									'canDelete' => true
								)
								));
							break;
						} else if(strpos($file, 'lib/wordfenceScanner.php') === false && preg_match($this->patterns['sigPattern'], $data, $matches)){
							$this->addResult(array(
								'type' => 'file',
								'severity' => 1,
								'ignoreP' => $this->path . $file,
								'ignoreC' => $fileSum,
								'shortMsg' => "This file appears to be an attack shell",
								'longMsg' => "This file appears to be an executable shell that allows hackers entry to your site via a backdoor. If you know about this file you can choose to ignore it to exclude it from future scans. The text we found in this file that matches a known malicious file is: <strong style=\"color: #F00;\">\"" . $matches[1] . "\"</strong>.",
								'data' => array(
									'file' => $file,
									'canDiff' => false,
									'canFix' => false,
									'canDelete' => true
								)
								));
							break;

						}
						/*
						$longestNospace = wfUtils::longestNospace($data);
						if($longestNospace > 1000 && (strpos($data, $this->patterns['pat1']) !== false || preg_match('/preg_replace\([^\(]+\/[a-z]*e/', $data)) ){
							$this->addResult(array(
								'type' => 'file',
								'severity' => 1,
								'ignoreP' => $this->path . $file,
								'ignoreC' => $fileSum,
								'shortMsg' => "This file may contain malicious executable code",
								'longMsg' => "This file is a PHP executable file and contains a line $longestNospace characters long without spaces that may be encoded data along with functions that may be used to execute that code. If you know about this file you can choose to ignore it to exclude it from future scans.",
								'data' => array(
									'file' => $file,
									'canDiff' => false,
									'canFix' => false,
									'canDelete' => true
								)
								));
							break;
						}
						*/
						if(preg_match($this->patterns['pat2'], $data)){
							$this->addResult(array(
								'type' => 'file',
								'severity' => 1,
								'ignoreP' => $this->path . $file,
								'ignoreC' => $fileSum,
								'shortMsg' => "This file may contain malicious executable code",
								'longMsg' => "This file is a PHP executable file and contains an " . $this->patterns['word1'] . " function and " . $this->patterns['word2'] . " decoding function on the same line. This is a common technique used by hackers to hide and execute code. If you know about this file you can choose to ignore it to exclude it from future scans.",
								'data' => array(
									'file' => $file,
									'canDiff' => false,
									'canFix' => false,
									'canDelete' => true
								)
								));
							break;
						}
						$this->urlHoover->hoover($file, $data);
					} else {
						$this->urlHoover->hoover($file, $data);
					}

					if($totalRead > 2 * 1024 * 1024){
						break;
					}
				}
				fclose($fh);
				$mtime = sprintf("%.5f", microtime(true) - $stime);
				$this->totalFilesScanned++;
				if(microtime(true) - $this->lastStatusTime > 1){
					$this->lastStatusTime = microtime(true);
					$this->writeScanningStatus();
				}
				$forkObj->forkIfNeeded();
			}
		}
		$this->writeScanningStatus();
		wordfence::status(2, 'info', "Asking Wordfence to check URL's against malware list.");
		$hooverResults = $this->urlHoover->getBaddies();
		if($this->urlHoover->errorMsg){
			$this->errorMsg = $this->urlHoover->errorMsg;
			return false;
		}
		foreach($hooverResults as $file => $hresults){
			foreach($hresults as $result){
				if($result['badList'] == 'goog-malware-shavar'){
					$this->addResult(array(
						'type' => 'file',
						'severity' => 1,
						'ignoreP' => $this->path . $file,
						'ignoreC' => md5_file($this->path . $file),
						'shortMsg' => "File contains suspected malware URL: " . $this->path . $file,
						'longMsg' => "This file contains a suspected malware URL listed on Google's list of malware sites. Wordfence decodes " . $this->patterns['word3'] . " when scanning files so the URL may not be visible if you view this file. The URL is: " . $result['URL'] . " - More info available at <a href=\"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=" . urlencode($result['URL']) . "&client=googlechrome&hl=en-US\" target=\"_blank\">Google Safe Browsing diagnostic page</a>.",
						'data' => array(
							'file' => $file,
							'badURL' => $result['URL'],
							'canDiff' => false,
							'canFix' => false,
							'canDelete' => true,
							'gsb' => 'goog-malware-shavar'
							)
						));
				} else if($result['badList'] == 'googpub-phish-shavar'){
					$this->addResult(array(
						'type' => 'file',
						'severity' => 1,
						'ignoreP' => $this->path . $file,
						'ignoreC' => md5_file($this->path . $file),
						'shortMsg' => "File contains suspected phishing URL: " . $this->path . $file,
						'longMsg' => "This file contains a URL that is a suspected phishing site that is currently listed on Google's list of known phishing sites. The URL is: " . $result['URL'],
						'data' => array(
							'file' => $file,
							'badURL' => $result['URL'],
							'canDiff' => false,
							'canFix' => false,
							'canDelete' => true,
							'gsb' => 'googpub-phish-shavar'
							)
						));
				}
			}
		}

		return $this->results;
	}
	private function writeScanningStatus(){
		wordfence::status(2, 'info', "Scanned contents of " . $this->totalFilesScanned . " additional files at " . sprintf('%.2f', ($this->totalFilesScanned / (microtime(true) - $this->startTime))) . " per second");
	}
	private function addEncIssue($ignoreP, $ignoreC, $encoding, $file){
		$this->addResult(array(
			'type' => 'file',
			'severity' => 1,
			'ignoreP' => $ignoreP,
			'ignoreC' => $ignoreC,
			'shortMsg' => "File contains $encoding encoded programming language: " . $file,
			'longMsg' => "This file contains programming language code that has been encoded using $encoding. This is often used by hackers to hide their tracks.",
			'data' => array(
				'file' => $file,
				'canDiff' => false,
				'canFix' => false,
				'canDelete' => true
				)
			));

	}
	public static function containsCode($arr){
		foreach($arr as $elem){
			if(preg_match($this->patterns['pat3'], $elem)){
				return true;
			}
		}
		return false;
	}

	private static function hostInURL($host, $url){
		$host = str_replace('.', '\\.', $host);
		return preg_match('/(?:^|^http:\/\/|^https:\/\/|^ftp:\/\/)' . $host . '(?:$|\/)/i', $url);
	}
	private function addResult($result){
		for($i = 0; $i < sizeof($this->results); $i++){
			if($this->results[$i]['type'] == 'file' && $this->results[$i]['data']['file'] == $result['data']['file']){
				if($this->results[$i]['severity'] > $result['severity']){
					$this->results[$i] = $result; //Overwrite with more severe results
				}
				return;
			}
		}
		//We don't have a results for this file so append
		$this->results[] = $result;
	}
}

?>
