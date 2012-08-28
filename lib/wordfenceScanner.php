<?php
require_once('wordfenceConstants.php');
require_once('wordfenceClass.php');
require_once('wordfenceURLHoover.php');
class wordfenceScanner {
	protected $sigs = array();
	protected $sigPattern = "";
	//serialized:
	protected $path = '';
	protected $fileList = array();
	protected $results = array(); 
	public $errorMsg = false;
	private $apiKey = false;
	private $wordpressVersion = '';
	private $totalFilesScanned = 0;
	private $startTime = false;
	private $lastStatusTime = false;
	public function __sleep(){
		return array('path', 'fileList', 'results', 'errorMsg', 'apiKey', 'wordpressVersion', 'urlHoover', 'totalFilesScanned', 'startTime', 'lastStatusTime');
	}
	public function __wakeup(){
		$this->setupSigs();
	}
	public function __construct($apiKey, $wordpressVersion, $fileList, $path){
		$this->apiKey = $apiKey;
		$this->wordpressVersion = $wordpressVersion;
		$this->fileList = $fileList; //A long string of <2 byte network order short showing filename length><filename>
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
		//Set up sigs
		$this->sigs = array(
array('\$QBDB51E25BF9A7F3D2475072803D1C36D', "antichat.php, cgi.php and possibly others, this is the var they assign the code to"),
array('\$login\s*=\s*"c99"|\$pass\s*=\s*"c99"|\$sess_cookie\s*=\s*"c9'.'9shvars"', "several lines of c99 decoded"),
array('C9'.'9Shell v\.', "c99.php"),
array('passthru\s*\(\s*getenv\s*\(\s*"HTTP_ACCEPT_LANGUAGE', "accept_language HTTP header backdoor"),
array('runcommand\s*\([\'"]etcpasswdfile', "Ajax_PHP Command Shell"),
array('exesysform', "AK-74 Security Team Web Shell"),
array('\$password\s*=\s*[\'"]antichat', "Antichat shell"),
array('if\s*\(\s*\$action\s*==\s*["\']phpeval', "Antichat shell"),
array('Can\'t open file, permission denide', "Antichat spelling error"),
array('tmp[\'"],\s*["\']phpshell', "Ayyildiz Tim  -AYT- Shell v 2.1 Biz"),
array('\$this_file\?op=phpinfo', "aZRaiLPhp v1.0"),
array('\.\s*\$server_ip\s*=\s*gethostbyname\s*\(\$SERVER_NAME', "c0derz shell [csh] v. 0.1.1"),
array('dosyayicek', "c99_locus7s and c99_PSych0"),
array('c99_sess_put', "c99_locus7s, c99_PSych0, c99_w4cking, RedhatC99 "),
array('PHP Safe\-Mode Bypass', "c99_w4cking"),
array('fonksiyonlary_kapat', "CasuS"),
array('Dim szCMD, szTempFile', "CmdAsp.asp"),
array('Open base dir: \$hopenbasedir', "Crystal shell"),
array('find config.inc.php files', "Many c99 variants including NFM, Perl, Predator, CTT, r57, Redhatc99"),
array('find all .htpasswd files', "Many c99 variants including NFM, Perl, Predator, CTT, r57, Redhatc9"),
array('function anonim_mail', "Cybershell"),
array('\$_SESSION\[aupass\]=md5\(\$aupassword', "Cybershell"),
array('echo\s+htmlspecialchars\(\s*crypt\(\s*fread', "dC3 Security Crew Shell PRiV"),
array('proc_open\(\s*\$_REQUEST', "Dive Shell"),
array('file_exists\([\'"]\/usr\/bin\/gcc', "DTool Pro"),
array('find all \*\.php files with word [\'"]password', "Dx"),
array('WebShell::Configuration', "Gamma Web Shell (perl)"),
array('base64_decode\(\$prx', "GFS shell"),
array('icq, command\-n\-conquer and shell nfm', "Various GFS variants"),
array('open\(FILEHANDLE,\s*[\'"]cd\s+\$param\{dir\}', "go-shell (perl)"),
array('document.PostActForm\$', "GRP Webshell"),
array('\$cmd 1> \/tmp\/cmdtemp 2>\&1\; cat', "h4ntu shell"),
array('\$Düzenlecols, \$Düzenlerows', "iMHaBiRLiGi PHP FTP"),
array('get_execution_method\s*\(', "ironshell and many others"),
array('proc\s*=\s*runtime\.exec\(\s*cmd\s*\)', "JSP Web Shell"),
array('eval>PHP Eval Code', "KAdot Universal Shell"),
array('if\(\(\$_POST\[\'exe\'\]\) == "Execute"', "Lamashell"),
array('cat \/etc\/passwd', "Liz0ziM and many other malicious apps"),
array('exec\(\$com,\$arr\)', "Loaderz WEB Shell"),
array('\$SFileName=\$PHP_SELF', "Macker's Private PHPShell"),
array('if\s*\(isset\s*\(\$_POST\)\)\s*walkArray\(\s*\$_POST', "Macker's and some c99 variantes"),
array('define\(\s*["\']PHPSHELL_VERSION[\'"]\s*,\s*[\'"]\d+', "Matamu and others"),
array('If\s*\(\$file_name\)\s*\$header\s*\.=\s*"Content\-Transfer\-Encoding:\s*base64', "Moroccan Spamers Ma-EditioN By GhOsT"),
array('\$MyShellVersion', "MyShell"),
array('function viewSchema', "Mysql interface"),
array('global \$HTTP_GET_VARS, \$HTTP_COOKIE_VARS, \$password', "mysql_tool"),
array('\$file\s*=\s*[\'"]\/etc\/passwd[\'"];', "mysql.php"),
array('move_uploaded_file\(\$_FILES\[\'probe\'\]\[\'tmp_name\'\]', "NCC-Shell"),
array('["\']find all suid files[\'"]', "NetworkFileManager.php and variants"),
array('["\']find all sgid files[\'"]', "NetworkFileManager.php and variants"),
array('["\']find all config\.inc\.php files[\'"]', "NetworkFileManager.php and variants"),
array('["\']find writeable directories and files[\'"]', "NetworkFileManager.php and variants"),
array('xargs grep \-li password', "NetworkFileManager.php and variants"),
array('\$filename\s*=\s*[\'"]\/etc\/passwd["\']', 'NFM 1.8, NIX Remote Web Shell and others'),
array('function mvcp\(\$from', 'NGH, Webcommander'),
array('find \/ \-type f \-name \.ht', 'NIX Remote Web Shell, nsTView and other variants'),
array('passthru\(\$comd', 'NShell'),
array('find \/ \-type f \-perm \-04000', 'nsTView and others'),
array('bind\(S,sockaddr_in\(\$LISTEN_PORT,INADDR_ANY', 'Perl Web Shell by RST-GHC'),
array('jmp_buf jmp;', 'PHANTASMA'),
array('\b(?:system|exec|passthru|shell_exec|proc_open)[\r\n\s\t]*\([\r\n\s\t]*\$_(?:POST|GET|REQUEST|SERVER)', 'PHP Backdoor, many malicious apps and any badly written app')


); //End sigs
		$sigArr = array();
		foreach($this->sigs as $elem){
			$sigArr[] = $elem[0];
		}
		$this->sigPattern = '/(' . implode('|', $sigArr) . ')/i';
	}
	public function scan($forkObj){
		if(! $this->startTime){
			$this->startTime = microtime(true);
		}
		if(! $this->lastStatusTime){
			$this->lastStatusTime = microtime(true);
		}
		while(strlen($this->fileList) > 0){
			$filenameLen = unpack('n', substr($this->fileList, 0, 2));
			$filenameLen = $filenameLen[1];
			if($filenameLen > 1000 || $filenameLen < 1){
				wordfence::status(1, 'error', "wordfenceScanner got bad data from the Wordfence API with a filename length of: " . $filenameLen);
				exit();
			}
				
			$file = substr($this->fileList, 2, $filenameLen);
			$this->fileList = substr($this->fileList, 2 + $filenameLen);

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
					} else if(strpos($file, 'lib/wordfenceScanner.php') === false && preg_match($this->sigPattern, $data, $matches)){
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
					$longestNospace = wfUtils::longestNospace($data);
					if($longestNospace > 1000 && (strpos($data, 'eval') !== false || preg_match('/preg_replace\([^\(]+\/[a-z]*e/', $data)) ){
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
					if(preg_match('/eval.*base'.'64_decode/i', $data)){
						$this->addResult(array(
							'type' => 'file',
							'severity' => 1,
							'ignoreP' => $this->path . $file,
							'ignoreC' => $fileSum,
							'shortMsg' => "This file may contain malicious executable code",
							'longMsg' => "This file is a PHP executable file and contains an evaluation function and base"."64 decoding function on the same line. This is a common technique used by hackers to hide and execute code. If you know about this file you can choose to ignore it to exclude it from future scans.",
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
						'longMsg' => "This file contains a suspected malware URL listed on Google's list of malware sites. Wordfence decodes base"."64 when scanning files so the URL may not be visible if you view this file. The URL is: " . $result['URL'] . " - More info available at <a href=\"http://safebrowsing.clients.google.com/safebrowsing/diagnostic?site=" . urlencode($result['URL']) . "&client=googlechrome&hl=en-US\" target=\"_blank\">Google Safe Browsing diagnostic page</a>.",
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
		wordfence::status(2, 'info', "Scanned contents of " . $this->totalFilesScanned . " files at a rate of " . sprintf('%.2f', ($this->totalFilesScanned / (microtime(true) - $this->startTime))) . " files per second");
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
			if(preg_match('/(?:base'.'64_decode|base'.'64_encode|eval|if|exists|isset|close|file|implode|fopen|while|feof|fread|fclose|fsockopen|fwrite|explode|chr|gethostbyname|strstr|filemtime|time|count|trim|rand|stristr|dir|mkdir|urlencode|ord|substr|unpack|strpos|sprintf)[\r\n\s\t]*\(/i', $elem)){
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
