<?php
require_once('wordfenceClass.php');
class wfModTracker {
	private $themeSum = false;
	private $pluginSum = false;
	private $coreSum = false;
	private $db = false;
	private $changesTable = false;
	private $anyFilesChangedCached = false;
	public function __construct(){
		global $wpdb;
		$this->changesTable = $wpdb->base_prefix . 'wfFileChanges';
		$this->status(2, 'info', "Getting file change DB handle");
		$this->db = new wfDB();
		$this->status(2, 'info', "Starting theme change check");
		$this->themeSum = $this->makeSum(get_theme_root());
		$this->status(2, 'info', "Starting plugin change scan");
		$this->pluginSum = $this->makeSum(WP_PLUGIN_DIR);
		$this->status(2, 'info', "Starting core file change scan");
		$this->coreSum = $this->makeCoreSum();
		$this->allFilesSum = array();
		$this->status(2, 'info', "Getting changes in all other files");
		$this->getAllFilesSum(ABSPATH);
		$this->status(2, 'info', "Done compiling file changes");
	}
	public static function resetChanges(){
		wfConfig::set('wfmdt_coreSum', '');
		wfConfig::set('wfmdt_themeSum', '');
		wfConfig::set('wfmdt_pluginSum', '');
		$db = new wfDB();
		global $wpdb;
		$db->query("delete from " . $wpdb->base_prefix . 'wfFileChanges');
	}
	public function filesModifiedInCore(){  if(wfConfig::get('wfmdt_coreSum') != $this->coreSum){ return true; } else { return false; } }
	public function filesModifiedInThemes(){  if(wfConfig::get('wfmdt_themeSum') != $this->themeSum){ return true; } else { return false; } }
	public function filesModifiedInPlugins(){  if(wfConfig::get('wfmdt_pluginSum') != $this->pluginSum){ return true; } else { return false; } }
	public function getChangedFiles($stripPath, $filterOutFiles){
		$changed = array();
		foreach($this->allFilesSum as $file => $md5){
			if(in_array($file, $filterOutFiles)){ continue; }
			$dbSig = $this->db->querySingle("select md5 from " . $this->changesTable . " where filenameHash='%s'", hash('sha256', $file));
			if($dbSig != $md5){
				$changed[] = substr($file, strlen($stripPath) - 1);
			}
		}
		return $changed;
	}
	public function anyFilesChanged(){
		if(! $this->anyFilesChangedCached){
			$changed = false;
			$q = $this->db->query("select file, md5 from " . $this->changesTable);
			$knownDBFiles = array();
			while($row = mysql_fetch_assoc($q)){
				$knownDBFiles[$row['file']] = true;
				if( (! isset($this->allFilesSum[$row['file']])) || $this->allFilesSum[$row['file']] != $row['md5']){
					$changed = true;
					//Can't break because we need to populate all of knownDBFiles
				}
			}
			foreach($this->allFilesSum as $file => $md5){
				if(! isset($knownDBFiles[$file])){
					//We have a new file the DB doesn't know about
					$changed = true;
					break;
				}
			}
			$this->anyFilesChangedCached = $changed ? 'true' : 'false';
		}
		return $this->anyFilesChangedCached == 'true' ? true : false;
	}
	public function logCurrentState(){
		wfConfig::set('wfmdt_coreSum', $this->coreSum);
		wfConfig::set('wfmdt_themeSum', $this->themeSum);
		wfConfig::set('wfmdt_pluginSum', $this->pluginSum);
		foreach($this->allFilesSum as $file => $md5){
			$this->db->query("insert into " . $this->changesTable . " (file, md5, filenameHash) values ('%s', '%s', '%s') ON DUPLICATE KEY UPDATE md5='%s'", $file, $md5, hash('sha256', $file), $md5);
		}
		$q = $this->db->query("select file from " . $this->changesTable);
		while($row = mysql_fetch_assoc($q)){
			if(! isset($this->allFilesSum[$row['file']])){
				$this->db->query("delete from " . $this->changesTable . " where filenameHash='%s'", hash('sha256', $row['file']));
			}
		}
	}
	private function getAllFilesSum($path){
		$path = rtrim($path, '/');
		$files = scandir($path);
		foreach($files as $file){
			if($file == '.' || $file == '..'){ continue; }
			$file = $path . '/' . $file;
			if(is_file($file)){
				$md5 = @md5_file($file);
				if($md5){ $this->allFilesSum[$file] = $md5; }
			} else if(is_dir($file)){
				$this->getAllFilesSum($file, $this->allFilesSum);
			}
		}
	}
	private function makeCoreSum(){
		return md5(
			$this->makeSum(ABSPATH, true) .  //norecurse
			$this->makeSum(ABSPATH . '/wp-admin/') .
			$this->makeSum(ABSPATH . '/wp-includes/')
			);
	}
	public function makeSum($dir, $norecurse = false, $str = ''){
		$dir = rtrim($dir, '/');
		$files = scandir($dir);
		foreach($files as $file){
			if($file == '.' || $file == '..'){ continue; }
			$file = $dir . '/' . $file;
			if(is_file($file)){
				$md5 =  @md5_file($file);
				if($md5){ $str .= $md5; }
			} else if((! $norecurse) && is_dir($file)){
				$str .= md5($this->makeSum($file, $norecurse, $str));
			}
		}
		return md5($str);
	}
	private function status($level, $type, $msg){
		wordfence::status($level, $type, $msg);
	}
}
?>
