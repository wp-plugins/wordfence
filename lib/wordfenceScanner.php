<?php
require_once('wordfenceConstants.php');
require_once('wordfenceClass.php');
require_once('wordfenceURLHoover.php');
class wordfenceScanner {
	protected $path = '';
	protected $fileList = array();
	protected $hostFileList = array();
	protected $urlFileList = array();
	protected $results = array(); 
	public $errorMsg = false;
	private $apiKey = false;
	private $wordpressVersion = '';
	public function __construct($apiKey, $wordpressVersion){
		$this->apiKey = $apiKey;
		$this->wordpressVersion = $wordpressVersion;
	}
	public function scan($path, $fileList, $userfunc = false){
		$this->errorMsg = false;
		if($path[strlen($path) - 1] != '/'){
			$path .= '/';
		}
		$this->hostFileList = array();
		$this->path = $path;
		$this->fileList = $fileList;
		$this->results = array();
		//First extract hosts or IP's and their URL's into $this->hostsFound and URL's into $this->urlsFound
		$urlHoover = new wordfenceURLHoover($this->apiKey, $this->wordpressVersion);
		foreach($this->fileList as $file){
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
			if($userfunc){
				$fsize = filesize($this->path . $file);
				if($fsize > 1000000){
					$fsize = sprintf('%.2f', ($fsize / 1000000)) . " Megs";
				} else {
					$fsize = $fsize . " bytes";
				}
				call_user_func($userfunc, 2, 'info', "Currently scanning: $file ($fsize)");
			}
			$stime = microtime(true);
			$fileSum = @md5_file($this->path . $file);
			if(! $fileSum){
				//usually permission denied
				continue;
			}
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
					if(strpos($data, '\$allowed'.'Sites') !== false && strpos($data, "define ('VER"."SION', '1.") !== false && strpos($data, "TimThum"."b script created by") !== false){
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
					}
					if(strpos($data, 'eval') !== false && strpos($data, 'base64_decode') !== false && preg_match('/[a-zA-Z0-9\+\/\=]{200,}/', $data) ){
						$this->addResult(array(
							'type' => 'file',
							'severity' => 1,
							'ignoreP' => $this->path . $file,
							'ignoreC' => $fileSum,
							'shortMsg' => "This file may contain hidden executable code",
							'longMsg' => "This file is a PHP executable file and contains the 'eval' and 'base64_decode' functions which are very common in backdoor programs and other malicious files. If you know about this file you can choose to ignore it to exclude it from future scans.",
							'data' => array(
								'file' => $file,
								'canDiff' => false,
								'canFix' => false,
								'canDelete' => true
							)
							));
						break;
					}
					
					$decoded = array();
					preg_replace("/([a-zA-Z0-9\+\/\=]{10,})/e", "self::array_pushRet(\$decoded, base64_decode(\"$1\"))", $data);
					$urlHoover->hoover($file, $data . ' ' . implode(' ', $decoded));
				} else {
					$urlHoover->hoover($file, $data);
				}

				if($totalRead > 2 * 1024 * 1024){
					break;
				}
			}
			fclose($fh);
			$mtime = sprintf("%.5f", microtime(true) - $stime);
		}
		$hooverResults = $urlHoover->getBaddies();
		if($urlHoover->errorMsg){
			$this->errorMsg = $urlHoover->errorMsg;
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
						'shortMsg' => "File contains suspected malware URL.",
						'longMsg' => "This file contains a suspected malware URL listed on Google's list of malware sites. Wordfence decodes base64 when scanning files so the URL may not be visible if you view this file. The URL is: " . $result['URL'] . " - More info available at <a href=\"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=" . urlencode($result['URL']) . "&client=googlechrome&hl=en-US\" target=\"_blank\">Google Safe Browsing diagnostic page</a>.",
						'data' => array(
							'file' => $file,
							'canDiff' => false,
							'canFix' => false,
							'canDelete' => true
							)
						));
				} else if($result['badList'] == 'googpub-phish-shavar'){
					$this->addResult(array(
						'type' => 'file',
						'severity' => 1,
						'ignoreP' => $this->path . $file,
						'ignoreC' => md5_file($this->path . $file),
						'shortMsg' => "File contains suspected phishing URL.",
						'longMsg' => "This file contains a URL that is a suspected phishing site that is currently listed on Google's list of known phishing sites. The URL is: " . $result['URL'],
						'data' => array(
							'file' => $file,
							'canDiff' => false,
							'canFix' => false,
							'canDelete' => true
							)
						));
				}
			}
		}

		return $this->results;
	}
	private function array_pushRet(&$arr, $elem){ array_push($arr, $elem); return $elem; }
	private function addEncIssue($ignoreP, $ignoreC, $encoding, $file){
		$this->addResult(array(
			'type' => 'file',
			'severity' => 1,
			'ignoreP' => $ignoreP,
			'ignoreC' => $ignoreC,
			'shortMsg' => "File contains $encoding encoded programming language.",
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
			if(preg_match('/(?:base64_decode|base64_encode|eval|if|exists|isset|close|file|implode|fopen|while|feof|fread|fclose|fsockopen|fwrite|explode|chr|gethostbyname|strstr|filemtime|time|count|trim|rand|stristr|dir|mkdir|urlencode|ord|substr|unpack|strpos|sprintf)[\r\n\s\t]*\(/i', $elem)){
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
