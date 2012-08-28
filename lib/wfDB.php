<?php
class wfDB {
	private $dbh = false;
	private static $dbhCache = array();
	private $dbhost = false;
	private $dbpassword = false;
	private $dbname = false;
	private $dbuser = false;
	private $createNewHandle = false;
	public $errorMsg = false;
	public function __construct($createNewHandle = false, $dbhost = false, $dbuser = false, $dbpassword = false, $dbname = false){
		$this->createNewHandle = $createNewHandle;
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
		$this->connectHandle();
	}
	private function connectHandle(){
		//We tried reusing wpdb but got disconnection errors from many users.
		$handleKey = md5($this->dbhost . $this->dbuser . $this->dbpassword . $this->dbname);
		//Use a cached handle if it exists and is still connected
		if( (! $this->createNewHandle) && isset(self::$dbhCache[$handleKey]) && mysql_ping(self::$dbhCache[$handleKey]) ){
			$this->dbh = self::$dbhCache[$handleKey];
		} else {
			//This close call is to deal with versions of mysql prior to 5.0.3 which auto-recommend when callig ping. So the conditional above may have reconnected this handle, so we disconnect it before reconnecting, if it's connected.
			if(isset(self::$dbhCache[$handleKey]) && mysql_ping(self::$dbhCache[$handleKey])){
				mysql_close(self::$dbhCache[$handleKey]);
				unset(self::$dbhCache[$handleKey]);
			}
			$dbh = mysql_connect($this->dbhost, $this->dbuser, $this->dbpassword, true );
			mysql_select_db($this->dbname, $dbh);
			if($this->createNewHandle){
				$this->dbh = $dbh;
			} else {
				self::$dbhCache[$handleKey] = $dbh;
				$this->dbh = self::$dbhCache[$handleKey];
			}
			$this->query("SET NAMES 'utf8'");
			$this->queryIgnoreError("SET GLOBAL max_allowed_packet=256*1024*1024");
			//$this->queryIgnoreError("SET GLOBAL wait_timeout=28800");
			$this->queryIgnoreError("SET @@wait_timeout=30800"); //Changing to session setting bc user may not have super privilege
		}
	}
	public function reconnect(){
		if((! $this->dbh) || (! mysql_ping($this->dbh)) ){
			$this->connectHandle();
		}
	}
	public function querySingleRec(){
		$this->reconnect();
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
			$this->reconnect(); //Putting reconnect here so it doesn't mess with the mysql_error() call
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
		$this->reconnect();
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
		$this->reconnect();
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
		$this->reconnect();
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
	public function columnExists($table, $col){
		global $wpdb; $prefix = $wpdb->base_prefix;
		$table = $prefix . $table;
		$q = $this->query("desc $table");
		while($row = mysql_fetch_assoc($q)){
			if($row['Field'] == $col){
				return true;
			}
		}
		return false;
	}
	public function dropColumn($table, $col){
		global $wpdb; $prefix = $wpdb->base_prefix;
		$table = $prefix . $table;
		$this->query("alter table $table drop column $col");
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
	public function prefix(){
		global $wpdb;
		return $wpdb->base_prefix;
	}
	public function getAffectedRows(){
		return mysql_affected_rows($this->dbh);
	}
	public function truncate($table){ //Ensures everything is deleted if user is using MySQL >= 5.1.16 and does not have "drop" privileges
		$this->query("truncate table $table");
		$this->query("delete from $table");
	}
}

?>
