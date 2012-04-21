<?php
class wordfenceHash {
	private $whitespace = array("\n","\r","\t"," ");
	public $totalData = 0; //To do a sanity check, don't use 'du' because it gets sparse files wrong and reports blocks used on disk. Use : find . -type f -ls | awk '{total += $7} END {print total}'
	public $totalFiles = 0;
	public $totalDirs = 0;
	public $linesOfPHP = 0;
	public $linesOfJCH = 0; //lines of HTML, CSS and javascript
	public function dirHash($path, $striplen, $filter = array(), $userfunc = false){
		$hashes = $this->_dirHash($path, $striplen, $filter, $userfunc);
		$hashes['.'] = $this->hashOfHashes($hashes);
		return $hashes;
	}
	private function _dirHash($path, $striplen, $filter, $userfunc = false){
		if($path[strlen($path) - 1] != '/'){
			$path .= '/';
		}
		$cont = scandir($path);
			
		$ret = array();
		for($i = 0; $i < sizeof($cont); $i++){
			if($cont[$i] == '.' || $cont[$i] == '..'){ continue; }
			if(in_array($cont[$i], $filter)){ continue; }
			$file = $path . $cont[$i];
			if($userfunc){ call_user_func($userfunc, "Scanning: $file"); }
			if(is_file($file)){
				$wfHash = $this->wfHash($file, true); 
				if($wfHash){
					$ret[substr($file, $striplen)] = $wfHash;
					//Now that we know we can open the file, lets update stats
					if(preg_match('/\.(?:js|html|htm|css)$/i', $file)){
						$this->linesOfJCH += sizeof(file($file));
					} else if(preg_match('/\.php$/i', $file)){
						$this->linesOfPHP += sizeof(file($file));
					}
					$this->totalFiles++;
					$this->totalData += filesize($file);
				}

			} else if(is_dir($file)) {
				$this->totalDirs++;
				$dirHashes = $this->_dirHash($file, $striplen, $filter);
				$dirHashes[substr($file, $striplen) . '/'] = $this->hashOfHashes($dirHashes);
				$ret = array_merge($ret, $dirHashes);
			}
		}
		return $ret;
	}
	public function hashOfHashes($dirHashes){
		ksort($dirHashes);
		$all_md5 = "";
		$all_sha = "";
		$all_shac = "";
		foreach($dirHashes as $key => $val){
			$all_md5 .= $val[0];
			$all_sha .= $val[1];
			$all_shac .= $val[2];
		}
		return array( md5($all_md5, true), hash('sha256', $all_sha, true), hash('sha256', $all_shac, true) ); 
	}
	public function wfHash($file, $binary = true){
		$md5 = @md5_file($file, $binary);
		if(! $md5){ return false; }
		$sha = @hash_file('sha256', $file, $binary);
		if(! $sha){ return false; }
		$fp = @fopen($file, "rb");
		if(! $fp){
			return false;
		}
		$ctx = hash_init('sha256');
		while (!feof($fp)) {
			hash_update($ctx, str_replace($this->whitespace,"",fread($fp, 65536)));
		}
		$shac = hash_final($ctx, $binary);
		return array($md5, $sha, $shac, filesize($file) );
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
