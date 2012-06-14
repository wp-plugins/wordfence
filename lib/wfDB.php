<?php
class wfDB {
	private $dbh = false;
	private static $dbhCache = array();
	private $dbhost = false;
	private $dbpassword = false;
	private $dbname = false;
	private $dbuser = false;
	public $errorMsg = false;
	public function __construct($createNewHandle = false, $dbhost = false, $dbuser = false, $dbpassword = false, $dbname = false){
		if($dbhost && $dbuser && $dbpassword && $dbname){
			$this->dbhost = $dbhost;
			$this->dbuser = $dbuser;
			$this->dbpassword = $dbpassword;
			$this->dbname = $dbname;
		} else {
			global $wpdb;
			if(! $wpdb){ 
				self::criticalError("The WordPress variable wpdb is not defined. Wordfence can't function without this being defined as it is in all standard WordPress installs.");
				return;
			}
			$sources = array(
				array('dbhost', 'DB_HOST'),
				array('dbuser', 'DB_USER'),
				array('dbpassword', 'DB_PASSWORD'),
				array('dbname', 'DB_NAME')
				);
			foreach($sources as $src){
				$prop = $src[0];
				if(isset($wpdb->$prop)){ 
					$this->$prop = $wpdb->$prop; 
				} else if(defined($src[1])){ 
					$this->$prop = constant($src[1]); 
				} else { 
					self::criticalError("Wordfence DB connect error. wpdb.$prop is not set and " . $src[1] . " is not defined."); 
					return;
				}
			}
		}
		if($createNewHandle){
			$dbh = mysql_connect( $this->dbhost, $this->dbuser, $this->dbpassword, true );
			if($dbh === false){
				self::criticalError("Wordfence could not connect to your database. Error was: " . mysql_error());
				return;
			}
			mysql_select_db($this->dbname, $dbh);
			$this->dbh = $dbh;
			$this->query("SET NAMES 'utf8'");

			//Set big packets for set_ser when it serializes a scan in between forks
			$this->queryIgnoreError("SET GLOBAL max_allowed_packet=256*1024*1024");
		} else {
			$handleKey = md5($dbhost . $dbuser . $dbpassword . $dbname);
			if(isset(self::$dbhCache[$handleKey])){
				$this->dbh = self::$dbhCache[$handleKey];
			} else {
				$dbh = mysql_connect( $this->dbhost, $this->dbuser, $this->dbpassword, true );
				if($dbh === false){
					self::criticalError("Wordfence could not connect to your database. The error was: " . mysql_error());
					return;
				}

				mysql_select_db($this->dbname, $dbh);
				self::$dbhCache[$handleKey] = $dbh;
				$this->dbh = self::$dbhCache[$handleKey];
				$this->query("SET NAMES 'utf8'");

				//Set big packets for set_ser when it serializes a scan in between forks
				$this->queryIgnoreError("SET GLOBAL max_allowed_packet=256*1024*1024");
			}
		}
	}
	public function querySingleRec(){
		$this->errorMsg = false;
		$args = func_get_args();
		if(sizeof($args) == 1){
			$query = $args[0];
		} else if(sizeof($args) > 1){
			$query = call_user_func_array('sprintf', $args);
		} else {
			$this->handleError("No arguments passed to querySingle()");
		}
		$res = mysql_query($query, $this->dbh);
		$this->handleError();
		return mysql_fetch_assoc($res); //returns false if no rows found
	}
	public function handleError($err = false){
		if(! $err){
			$err = mysql_error();
		}
		if($err){ 
			$trace=debug_backtrace(); 
			$first=array_shift($trace); 
			$caller=array_shift($trace); 
			$msg = "Wordfence DB error in " . $caller['file'] . " line " . $caller['line'] . ": $err";
			global $wpdb;
			$statusTable = $wpdb->base_prefix . 'wfStatus';
			mysql_query(sprintf("insert into " . $statusTable . " (ctime, level, type, msg) values (%s, %d, '%s', '%s')", 
				mysql_real_escape_string(sprintf('%.6f', microtime(true))), 
				mysql_real_escape_string(1), 
				mysql_real_escape_string('error'), 
				mysql_real_escape_string($msg)), $this->dbh);
			error_log($msg);
			return;
		}
	}
	public function querySingle(){
		$this->errorMsg = false;
		$args = func_get_args();
		if(sizeof($args) == 1){
			$query = $args[0];
		} else if(sizeof($args) > 1){
			for($i = 1; $i < sizeof($args); $i++){
				$args[$i] = mysql_real_escape_string($args[$i]);
			}
			$query = call_user_func_array('sprintf', $args);
		} else {
			$this->handleError("No arguments passed to querySingle()");
		}
		$res = mysql_query($query, $this->dbh);
		$this->handleError();
		if(! $res){
			return false;
		}
		$row = mysql_fetch_array($res, MYSQL_NUM);
		if(! is_array($row)){ return false; }
		return $row[0];
	}
	public function query(){ //sprintfString, arguments
		$this->errorMsg = false;
		$args = func_get_args();
		$isStatusQuery = false;
		if(sizeof($args) == 1){
			if(preg_match('/Wordfence DB error/i', $args[0])){
				$isStatusQuery = true;
			}
			$res = mysql_query($args[0], $this->dbh);
		} else if(sizeof($args) > 1){
			for($i = 1; $i < sizeof($args); $i++){
				if(preg_match('/Wordfence DB error/i', $args[$i])){
					$isStatusQuery = true;
				}
				$args[$i] = mysql_real_escape_string($args[$i]);
			}
			$res = mysql_query(call_user_func_array('sprintf', $args), $this->dbh);
		} else {
			$this->handleError("No arguments passed to query()");
		}
		$this->handleError();
		return $res;
	}
	public function queryIgnoreError(){ //sprintfString, arguments
		$this->errorMsg = false;
		$args = func_get_args();
		if(sizeof($args) == 1){
			$res = mysql_query($args[0], $this->dbh);
		} else if(sizeof($args) > 1){
			for($i = 1; $i < sizeof($args); $i++){
				$args[$i] = mysql_real_escape_string($args[$i]);
			}
			$res = mysql_query(call_user_func_array('sprintf', $args), $this->dbh);
		} else {
			$this->handleError("No arguments passed to query()");
		}
		return $res;
	}

	private static function criticalError($msg){
		$msg = "Wordfence critical database error: $msg";
		error_log($msg);
		return;
	}
	public function createKeyIfNotExists($table, $col, $keyName){
		global $wpdb; $prefix = $wpdb->base_prefix;
		$table = $prefix . $table;
		$exists = $this->querySingle("show tables like '$table'");
		$keyFound = false;
		if($exists){
			$q = $this->query("show keys from $table");
			if($q){
				while($row = mysql_fetch_assoc($q)){
					if($row['Key_name'] == $keyName){
						$keyFound = true;
					}
				}
			}
		}
		if(! $keyFound){
			$this->query("alter table $table add KEY $keyName($col)");
		}
	}
	public function getDBH(){ return $this->dbh; }
	public function getMaxAllowedPacketBytes(){
		$rec = $this->querySingleRec("show variables like 'max_allowed_packet'");
		return $rec['Value'];
	}
}

?>
