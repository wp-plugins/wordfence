<?php
require_once('wordfenceClass.php');
class wordfenceHash {

	//Begin serialized vars
	private $whitespace = array("\n","\r","\t"," ");
	private $fileQ = array();
	public $totalData = 0; //To do a sanity check, don't use 'du' because it gets sparse files wrong and reports blocks used on disk. Use : find . -type f -ls | awk '{total += $7} END {print total}'
	public $totalFiles = 0;
	public $totalDirs = 0;
	public $linesOfPHP = 0;
	public $linesOfJCH = 0; //lines of HTML, CSS and javascript
	public $striplen = 0;
	private $hashes = array();
	public function __sleep(){ //same order as above
		return array('whitespace', 'fileQ', 'totalData', 'totalFiles', 'totalDirs', 'linesOfPHP', 'linesOfJCH', 'striplen', 'hashes');
	}
	public function __construct($striplen){
		$this->striplen = $striplen;
	}
	public function __wakeup(){
		
	}
	public function buildFileQueue($path, $only = array()){ //base path and 'only' is a list of files and dirs in the bast that are the only ones that should be processed. Everything else in base is ignored. If only is empty then everything is processed.
		if($path[strlen($path) - 1] != '/'){
			$path .= '/';
		}
		if(! is_readable($path)){
			wordfence::status(1, 'error', "Could not read directory $path to do sacn.");
			exit();
		}
		$files = scandir($path);
		foreach($files as $file){
			if(sizeof($only) > 0 && (! in_array($file, $only))){
				continue;
			}
			$file = $path . $file;
			wordfence::status(2, 'info', "Hashing item in base dir: $file");
			$this->_dirHash($file);
		}	

	}
	public function genHashes($forkObj){
		while($file = array_shift($this->fileQ)){
			$this->processFile($file);
			$forkObj->forkIfNeeded();	
		}
		return $this->hashes;
	}
	private function _dirHash($path){
		if(substr($path, -3, 3) == '/..' || substr($path, -2, 2) == '/.'){
			return;
		}
		if(! is_readable($path)){ return; } //Applies to files and dirs
		if(is_dir($path)){
			$this->totalDirs++;
			if($path[strlen($path) - 1] != '/'){
				$path .= '/';
			}
			$cont = scandir($path);
			for($i = 0; $i < sizeof($cont); $i++){
				if($cont[$i] == '.' || $cont[$i] == '..'){ continue; }
				$file = $path . $cont[$i];
				if(is_file($file)){
					$this->qFile($file);
				} else if(is_dir($file)) {
					$this->_dirHash($file);
				}
			}
		} else {
			if(is_file($path)){
				$this->qFile($path);
			}
		}
	}
	private function qFile($file){
		$this->fileQ[] = $file;
	}
	private function processFile($file){
		if(@filesize($file) > WORDFENCE_MAX_FILE_SIZE_TO_PROCESS){
			wordfence::status(2, 'info', "Skipping file larger than 50 megs: $file");
			return;
		}
		if(function_exists('memory_get_usage')){
			wordfence::status(2, 'info', "Scanning: $file (Mem:" . sprintf('%.1f', memory_get_usage(true) / (1024 * 1024)) . "M)");
		} else {
			wordfence::status(2, 'info', "Scanning: $file");
		}
		$wfHash = $this->wfHash($file, true); 
		if($wfHash){
			$this->hashes[substr($file, $this->striplen)] = $wfHash;
			//Now that we know we can open the file, lets update stats
			if(preg_match('/\.(?:js|html|htm|css)$/i', $file)){
				$this->linesOfJCH += sizeof(file($file));
			} else if(preg_match('/\.php$/i', $file)){
				$this->linesOfPHP += sizeof(file($file));
			}
			$this->totalFiles++;
			$this->totalData += filesize($file);
		} else {
			wordfence::status(2, 'error', "Could not gen hash for file: $file");
		}
	}
	public function wfHash($file, $binary = true){
		$md5 = @md5_file($file, $binary);
		if(! $md5){ return false; }
		//$sha = @hash_file('sha256', $file, $binary);
		//if(! $sha){ return false; }
		$fp = @fopen($file, "rb");
		if(! $fp){
			return false;
		}
		$ctx = hash_init('sha256');
		while (!feof($fp)) {
			hash_update($ctx, str_replace($this->whitespace,"",fread($fp, 65536)));
		}
		$shac = hash_final($ctx, $binary);
		//Taking out $sha for now because we don't use it on the scanning server side
		return array($md5, '', $shac, filesize($file) );
	}
	public static function bin2hex($hashes){
		function wf_func1($elem){ 
				return array(  
					bin2hex($elem[0]), 
					bin2hex($elem[1]),
					bin2hex($elem[2])
					); 
		}
		return array_map('wf_func1', $hashes);
	}
	public static function hex2bin($hashes){
		function wf_func2($elem){ 
			return array( 
				pack('H*', $elem[0]), 
				pack('H*', $elem[1]), 
				pack('H*', $elem[2]) 
				); 
		} 
		return array_map('wf_func2', $hashes); 
	}
}
?>
