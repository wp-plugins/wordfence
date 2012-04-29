<?php
class wfDB {
	private $dbh = false;
	private static $dbhCache = false;
	private $dbhost = false;
	private $dbpassword = false;
	private $dbname = false;
	private $dbuser = false;
	public function __construct($createNewHandle = false, $dbhost = false, $dbuser = false, $dbpassword = false, $dbname = false){
		if($dbhost && $dbuser && $dbpassword && $dbname){
			$this->dbhost = $dbhost;
			$this->dbuser = $dbuser;
			$this->dbpassword = $dbpassword;
			$this->dbname = $dbname;
		} else {
			global $wpdb;
			if(! $wpdb){ die("Not running under wordpress. Please supply db creditials to constructor."); }
			$this->dbhost = $wpdb->dbhost;
			$this->dbuser = $wpdb->dbuser;
			$this->dbpassword = $wpdb->dbpassword;
			$this->dbname = $wpdb->dbname;
		}
		if($createNewHandle){
			$dbh = mysql_connect( $this->dbhost, $this->dbuser, $this->dbpassword, true );
			mysql_select_db($this->dbname, $dbh);
			$this->dbh = $dbh;
		} else {
			if(self::$dbhCache){
				$this->dbh = self::$dbhCache;
			} else {
				$dbh = mysql_connect( $this->dbhost, $this->dbuser, $this->dbpassword, true );
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
	public function uQuery(){ //sprintfString, arguments NOTE: Very important that there is no other DB activity between uQuery and when you call mysql_free_result on the return value of uQuery.
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
		$res = mysql_unbuffered_query($query, $this->dbh);
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
}

?>
