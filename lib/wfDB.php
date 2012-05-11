<?php
class wfDB {
	private $dbh = false;
	private static $dbhCache = false;
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
				$this->errorMsg = "The WordPress variable wpdb is not defined.";
				return;
			}
			if(! $wpdb->dbhost ){ $this->errorMsg = "The WordPress variable from wpdb dbhost is not defined."; }
			if(! $wpdb->dbuser ){ $this->errorMsg = "The WordPress variable from wpdb dbuser is not defined."; }
			if(! $wpdb->dbpassword ){ $this->errorMsg = "The WordPress variable from wpdb dbpassword is not defined."; }
			if(! $wpdb->dbname ){ $this->errorMsg = "The WordPress variable from wpdb dbname is not defined."; }
			if($this->errorMsg){ return; }	
			$this->dbhost = $wpdb->dbhost;
			$this->dbuser = $wpdb->dbuser;
			$this->dbpassword = $wpdb->dbpassword;
			$this->dbname = $wpdb->dbname;
		}
		if($createNewHandle){
			$dbh = mysql_connect( $this->dbhost, $this->dbuser, $this->dbpassword, true );
			if($dbh === false){
				$this->errorMsg = "Could not connect to database on " . $this->dbhost . " with user " . $this->dbuser;
				return;
			}
			mysql_select_db($this->dbname, $dbh);
			$this->dbh = $dbh;
		} else {
			if(self::$dbhCache){
				$this->dbh = self::$dbhCache;
			} else {
				$dbh = mysql_connect( $this->dbhost, $this->dbuser, $this->dbpassword, true );
				if($dbh === false){
					$this->errorMsg = "Could not connect to database on " . $this->dbhost . " with user " . $this->dbuser;
					return;
				}

				mysql_select_db($this->dbname, $dbh);
				self::$dbhCache = $dbh;
				$this->dbh = self::$dbhCache;
			}
		}
	}
	public function querySingleRec(){
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
		if($err){
			$trace=debug_backtrace(); $caller=array_shift($trace); error_log("Wordfence DB error in " . $caller['file'] . " line " . $caller['line'] . ": $err");
		}
		return mysql_fetch_assoc($res); //returns false if no rows found
	}
	public function querySingle(){
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
		if($err){
			$trace=debug_backtrace(); $caller=array_shift($trace); error_log("Wordfence DB error in " . $caller['file'] . " line " . $caller['line'] . ": $err");
		}
		if(! $res){
			return false;
		}
		$row = mysql_fetch_array($res, MYSQL_NUM);
		if(! is_array($row)){ return false; }
		return $row[0];
	}
	public function query(){ //sprintfString, arguments
		$args = func_get_args();
		if(sizeof($args) == 1){
			$query = $args[0];
		} else if(sizeof($args) > 1){
			for($i = 1; $i < sizeof($args); $i++){
				$args[$i] = mysql_real_escape_string($args[$i]);
			}
			$query = call_user_func_array('sprintf', $args);
		} else {
			wfdie("No arguments passed to query()");
		}
		$res = mysql_query($query, $this->dbh);
		$err = mysql_error();
		if($err){
			$trace=debug_backtrace(); $caller=array_shift($trace); error_log("Wordfence DB error in " . $caller['file'] . " line " . $caller['line'] . ": $err");
		}
		return $res;
	}
	private function wfdie($msg){
		error_log($msg);
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
}

?>
