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
				self::wfdie("The WordPress variable wpdb is not defined.");
			}
			if(! $wpdb->dbhost ){ self::wfdie("The WordPress variable from wpdb dbhost is not defined."); }
			if(! $wpdb->dbuser ){ self::wfdie("The WordPress variable from wpdb dbuser is not defined."); }
			if(! isset($wpdb->dbpassword) ){ self::wfdie("The WordPress variable from wpdb dbpassword is not defined."); }
			if(! $wpdb->dbname ){ self::wfdie("The WordPress variable from wpdb dbname is not defined."); }
			$this->dbhost = $wpdb->dbhost;
			$this->dbuser = $wpdb->dbuser;
			$this->dbpassword = $wpdb->dbpassword;
			$this->dbname = $wpdb->dbname;
		}
		if($createNewHandle){
			$dbh = mysql_connect( $this->dbhost, $this->dbuser, $this->dbpassword, true );
			if($dbh === false){
				self::wfdie("Could not connect to database on " . $this->dbhost . " with user " . $this->dbuser . ' : ' . mysql_error());
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
					self::wfdie("Could not connect to database on " . $this->dbhost . " with user " . $this->dbuser . ' : ' . mysql_error());
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
			wfdie("No arguments passed to querySingle()");
		}
		$res = mysql_query($query, $this->dbh);
		$err = mysql_error();
		if( (! preg_match('/Wordfence DB error/i', $query)) && $err){ //prevent loops
			$this->errorMsg = $err;
			$trace=debug_backtrace(); $caller=array_shift($trace); wordfence::status(2, 'error', "Wordfence DB error in " . $caller['file'] . " line " . $caller['line'] . ": $err");
		}
		return mysql_fetch_assoc($res); //returns false if no rows found
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
			wfdie("No arguments passed to querySingle()");
		}
		$res = mysql_query($query, $this->dbh);
		$err = mysql_error();
		if( (! preg_match('/Wordfence DB error/i', $query)) && $err){
			$this->errorMsg = $err;
			$trace=debug_backtrace(); $caller=array_shift($trace); wordfence::status(2, 'error', "Wordfence DB error in " . $caller['file'] . " line " . $caller['line'] . ": $err");
		}
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
			wfdie("No arguments passed to query()");
		}
		$err = mysql_error();
		if( (! $isStatusQuery) && $err){ //isStatusQuery prevents loops if status itself is causing error
			$this->errorMsg = $err;
			$trace=debug_backtrace(); $caller=array_shift($trace); wordfence::status(2, 'error', "Wordfence DB error in " . $caller['file'] . " line " . $caller['line'] . ": $err");
		}
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
			wfdie("No arguments passed to query()");
		}
		return $res;
	}

	private function wfdie($msg){
		error_log("Wordfence critical database error: $msg");
		exit(1);
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
