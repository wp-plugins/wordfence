<?php
require_once('wordfenceClass.php');
class wordfenceHash {
	private $apiKey = false;
	private $wp_version = false;
	private $api = false;
	private $db = false;
	private $table = false;
	private $fileQ = array();

	//Begin serialized vars
	private $whitespace = array("\n","\r","\t"," ");
	public $totalData = 0; //To do a sanity check, don't use 'du' because it gets sparse files wrong and reports blocks used on disk. Use : find . -type f -ls | awk '{total += $7} END {print total}'
	public $totalFiles = 0;
	public $totalDirs = 0;
	public $linesOfPHP = 0;
	public $linesOfJCH = 0; //lines of HTML, CSS and javascript
	public $striplen = 0;
	private $hashPacket = "";
	public $hashStorageID = false;
	private $hashingStartTime = false;
	private $lastStatusTime = false;
	public function __sleep(){ //same order as above
		if(sizeof($this->fileQ) > 0){
			throw new Exception("Sanity fail. fileQ is not empty. Has: " . sizeof($this->fileQ));
		}
		return array('whitespace', 'totalData', 'totalFiles', 'totalDirs', 'linesOfPHP', 'linesOfJCH', 'striplen', 'hashPacket', 'hashStorageID', 'hashingStartTime', 'lastStatusTime');
	}
	public function __construct($striplen){
		$this->striplen = $striplen;
		$this->db = new wfDB();
		$this->table = $this->db->prefix() . 'wfFileQueue';
		$this->apiKey = wfConfig::get('apiKey');
		$this->wp_version = wfUtils::getWPVersion();
		$this->api = new wfAPI($this->apiKey, $this->wp_version);
	}
	public function __wakeup(){
		$this->db = new wfDB();
		$this->table = $this->db->prefix() . 'wfFileQueue';
		$this->apiKey = wfConfig::get('apiKey');
		$this->wp_version = wfUtils::getWPVersion();
		$this->api = new wfAPI($this->apiKey, $this->wp_version);
	}
	public function buildFileQueue($path, $only = array()){ //base path and 'only' is a list of files and dirs in the bast that are the only ones that should be processed. Everything else in base is ignored. If only is empty then everything is processed.
		$this->db->truncate($this->table);
		if($path[strlen($path) - 1] != '/'){
			$path .= '/';
		}
		if(! is_readable($path)){
			throw new Exception("Could not read directory $path to do scan.");
			exit();
		}
		$files = scandir($path);
		foreach($files as $file){
			if(sizeof($only) > 0 && (! in_array($file, $only))){
				continue;
			}
			$file = $path . $file;
			wordfence::status(4, 'info', "Hashing item in base dir: $file");
			$this->_dirHash($file);
		}	
		$this->writeFileQueue(); //Final write to DB

	}
	public function genHashes($forkObj){
		if(! $this->hashingStartTime){
			$this->hashingStartTime = microtime(true);
		}
		if(! $this->lastStatusTime){
			$this->lastStatusTime = microtime(true);
		}
		$haveMoreInDB = true;
		while($haveMoreInDB){
			$haveMoreInDB = false;
			//This limit used to be 1000, but we changed it to 5 because forkIfNeeded needs to run frequently, but
			// we still want to minimize the number of queries we do.
			// So now we select, process and delete 5 from teh queue and then check forkIfNeeded()
			// So this assumes that processing 5 files won't take longer than wfScanEngine::$maxExecTime (which was 10 at the time of writing, which is 2 secs per file)
			$res = $this->db->query("select id, filename from " . $this->table . " limit 5");
			$ids = array();
			while($rec = mysql_fetch_row($res)){
				$this->processFile($rec[1]);
				array_push($ids, $rec[0]);
				$haveMoreInDB = true;
			}
			if(sizeof($ids) > 0){
				$this->db->query("delete from " . $this->table . " where id IN (" . implode(',', $ids) . ")");
			}
			$forkObj->forkIfNeeded();	
		}
		//Will only reach here if we empty file queue. fork may cause exit
		$this->sendHashPacket();
		$this->db->truncate($this->table); //Also resets id autoincrement to 1
		$this->writeHashingStatus();
	}
	private function writeHashingStatus(){
		$this->lastStatusTime = microtime(true);
		wordfence::status(2, 'info', "Scanned " . $this->totalFiles . " files at a rate of " . sprintf('%.2f', ($this->totalFiles / (microtime(true) - $this->hashingStartTime))) . " files per second.");
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
		if(sizeof($this->fileQ) > 1000){
			$this->writeFileQueue();
		}
	}
	private function writeFileQueue(){
		$sql = "insert into " . $this->table . " (filename) values ";
		$added = false;
		foreach($this->fileQ as $val){
			$added = true;
			$sql .= "('" . mysql_real_escape_string($val) . "'),";
		}
		if($added){
			$sql = rtrim($sql, ',');
			$this->db->query($sql);
		}
		$this->fileQ = array();
	}
	private function processFile($file){
		if(wfUtils::fileTooBig($file)){
			wordfence::status(4, 'info', "Skipping file larger than max size: $file");
			return;
		}
		if(function_exists('memory_get_usage')){
                       wordfence::status(4, 'info', "Scanning: $file (Mem:" . sprintf('%.1f', memory_get_usage(true) / (1024 * 1024)) . "M)");
		} else {
                       wordfence::status(4, 'info', "Scanning: $file");
		}
		$wfHash = $this->wfHash($file); 
		if($wfHash){
			$packetFile = substr($file, $this->striplen);
			$this->hashPacket .= $wfHash[0] . $wfHash[1] . pack('n', strlen($packetFile)) . $packetFile;  
			if(strlen($this->hashPacket) > 500000){ //roughly 2 megs in string mem space
				$this->writeHashingStatus();
				$this->sendHashPacket();
			}

			//Now that we know we can open the file, lets update stats
			if(preg_match('/\.(?:js|html|htm|css)$/i', $file)){
				$this->linesOfJCH += sizeof(file($file));
			} else if(preg_match('/\.php$/i', $file)){
				$this->linesOfPHP += sizeof(file($file));
			}
			$this->totalFiles++;
			$this->totalData += filesize($file); //We already checked if file overflows int in the fileTooBig routine above
			if(microtime(true) - $this->lastStatusTime > 1){
				$this->writeHashingStatus();
			}
		} else {
			wordfence::status(2, 'error', "Could not gen hash for file (probably because we don't have permission to access the file): $file");
		}
	}
	private function sendHashPacket(){
		wordfence::status(4, 'info', "Sending packet of hash data to Wordfence scanning servers");
		if(strlen($this->hashPacket) < 1){
			return;
		}
		if($this->hashStorageID){
			$dataArr = $this->api->binCall('add_hash_chunk', "WFID:" . pack('N', $this->hashStorageID) . $this->hashPacket);
			$this->hashPacket = "";
			if(is_array($dataArr) && isset($dataArr['data']) && $dataArr['data'] == $this->hashStorageID){
				//keep going
			} else {
				throw new Exception("Could not store an additional chunk of hash data on Wordfence servers with ID: " . $this->hashStorageID);
			}
		} else {
			$dataArr = $this->api->binCall('add_hash_chunk', "WFST:" . $this->hashPacket);
			$this->hashPacket = "";
			if(is_array($dataArr) && isset($dataArr['data']) && preg_match('/^\d+$/', $dataArr['data'])){
				$this->hashStorageID = $dataArr['data'];
			} else {
				throw new Exception("Could not store hash data on Wordfence servers. Got response: " . var_export($dataArr, true));
			}
		}
	}
	public function getHashStorageID(){
		return $this->hashStorageID;
	}
	public function wfHash($file){
		wfUtils::errorsOff();
		$md5 = @md5_file($file, false);
		wfUtils::errorsOn();

		if(! $md5){ return false; }
		$fp = @fopen($file, "rb");
		if(! $fp){
			return false;
		}
		$ctx = hash_init('sha256');
		while (!feof($fp)) {
			hash_update($ctx, str_replace($this->whitespace,"",fread($fp, 65536)));
		}
		$shac = hash_final($ctx, false);
		return array($md5, $shac);
	}
}
?>
