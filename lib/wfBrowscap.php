<?php
class wfBrowscap {
	protected $_cacheLoaded = false;
	protected $_userAgents = array();
	protected $_browsers = array();
	protected $_patterns = array();
	protected $_properties = array();
	protected $resultCache = array();
	public function getBrowser($user_agent){
		$uamd5 = md5($user_agent);
		if(isset($this->resultCache[$uamd5])){
			return $this->resultCache[$uamd5];
		}
		if (!$this->_cacheLoaded){
			$this->_loadCache('wfBrowscapCache.php');
		}

		$browser = array();
		foreach ($this->_patterns as $key => $pattern){
			if (preg_match($pattern . 'i', $user_agent)){
				$browser = array(
					$user_agent, 
					trim(strtolower($pattern), '@'),
					$this->_userAgents[$key]
					);
				$browser = $value = $browser + $this->_browsers[$key];
				while (array_key_exists(3, $value) && $value[3]){
					$value = $this->_browsers[$value[3]];
					$browser += $value;
				}
				if (!empty($browser[3])){
					$browser[3] = $this->_userAgents[$browser[3]];
				}
				break;
			}
		}
		$array = array();
		foreach ($browser as $key => $value) {
			if ($value === 'true') {
				$value = true;
			} elseif ($value === 'false') {
				$value = false;
			}
			$array[$this->_properties[$key]] = $value;
		}
		$this->resultCache[$uamd5] = $array;
		return $array;
	}
	protected function _loadCache($cache_file){
		require $cache_file;
		$this->_browsers = $browsers;
		$this->_userAgents = $userAgents;
		$this->_patterns = $patterns;
		$this->_properties = $properties;
		$this->_cacheLoaded = true;
	}
}
?>
