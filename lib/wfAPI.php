<?php
require_once('wordfenceConstants.php');
require_once('wordfenceClass.php');
class wfAPI {
	public $errorMsg = false;
	public $lastURLError = '';
	public $lastHTTPStatus = '';
	public $lastCurlErrorNo = '';
	private $curlDataWritten = 0;
	private $curlContent = 0;
	private $APIKey = '';
	private $wordpressVersion = '';
	public function __construct($apiKey, $wordpressVersion){
		$this->APIKey = $apiKey;
		$this->wordpressVersion = $wordpressVersion;
	}
	public function call($action, $getParams = array(), $postParams = array()){
		$this->errorMsg = false;
		$json = $this->getURL($this->getAPIURL() . '/v' . WORDFENCE_API_VERSION . '/?' . $this->makeAPIQueryString() . '&' . http_build_query(
			array_merge(
				array('action' => $action),
				$getParams	
				)), $postParams);
		if(! $json){
			if($this->lastHTTPStatus == '502' || $this->lastCurlErrorNo == 7){
				$this->errorMsg = "Wordfence is currently down for maintenance. Please try again later.";
			} else {
				$this->errorMsg = "We could not fetch data from the API when calling '$action': " . $this->lastURLError;
			}
			return false;
		}

		$dat = json_decode($json, true);
		if(! is_array($dat)){
			$this->errorMsg = "We could not understand the Wordfence API response when calling '$action'.";
		}
		if(empty($dat['errorMsg']) === false){
			$this->errorMsg = $dat['errorMsg'];
		}
		return $dat;
	}
	public function curlWrite($h, $d){
		$this->curlContent .= $d;
		if($this->curlDataWritten > 10000000){ //10 megs
			return 0;
		} else {
			return strlen($d);
		}
	}
	protected function getURL($url, $postParams = array()){
		$this->lastURLError = '';
		if(function_exists('curl_init')){
			$this->curlDataWritten = 0;
			$this->curlContent = "";
			$curl = curl_init($url);
			curl_setopt ($curl, CURLOPT_TIMEOUT, 300);
			curl_setopt ($curl, CURLOPT_USERAGENT, "Wordfence.com UA " . WORDFENCE_VERSION);
			curl_setopt ($curl, CURLOPT_RETURNTRANSFER, TRUE);
			curl_setopt ($curl, CURLOPT_HEADER, 0);
			curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, false);
			curl_setopt ($curl, CURLOPT_WRITEFUNCTION, array($this, 'curlWrite'));
			curl_setopt($curl, CURLOPT_POST, true);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $postParams);
			
			$curlResult = curl_exec($curl);
			$httpStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
			$this->lastCurlErrorNo = curl_errno($curl);
			if($httpStatus == 200){
				curl_close($curl);
				return $this->curlContent;
			} else {
				$this->lastURLError = "HTTP status $httpStatus from server. " . curl_error($curl);
				$this->lastHTTPStatus = $httpStatus;
				curl_close($curl);
				return false;
			}
		} else {
			$data = $this->fileGet($url, $postParams);
			if($data === false){
				$err = error_get_last();
				$this->lastURLError = $err;
				return false;
			}
			return $data;
		}

	}
	private function fileGet($url, $postParams){
		$body = "";
		if(is_array($postParams)){
			$bodyArr = array();
			foreach($postParams as $key => $val){
				$bodyArr[] = urlencode($key) . '=' . urlencode($val);
			}
			$body = implode('&', $bodyArr);
		} else {
			$body = $postParams;
		}
		$opts = array('http' =>
				array(
					'method'  => 'POST',
					'content' => $body,
					'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
					'timeout' => 60
				     )
			     );
		$context = stream_context_create($opts);
		return @file_get_contents($url, false, $context, -1);
	}
	public function binCall($func, $postData){
		$this->errorMsg = false;
		$url = $this->getAPIURL() . '/v' . WORDFENCE_API_VERSION . '/?' . $this->makeAPIQueryString() . '&action=' . $func;
		if(function_exists('curl_init')){
			$curl = curl_init($url);
			curl_setopt ($curl, CURLOPT_TIMEOUT, 300);
			//curl_setopt($curl, CURLOPT_VERBOSE, true);
			curl_setopt ($curl, CURLOPT_USERAGENT, "Wordfence");
			curl_setopt ($curl, CURLOPT_RETURNTRANSFER, TRUE);
			curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, false);
			curl_setopt($curl, CURLOPT_POST, true);
			if($postData){                  
				curl_setopt($curl, CURLOPT_POSTFIELDS, $postData);
			} else {                        
				curl_setopt($curl, CURLOPT_POSTFIELDS, array());
			}                               
			$data = curl_exec($curl);       
			$httpStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		} else {
			$data = $this->fileGet($url, $postData);
			if($data === false){
				$this->errorMsg = error_get_last();
				return false;
			}
			$httpStatus = '200';
		}
		if(preg_match('/\{.*errorMsg/', $data)){
			$jdat = @json_decode($data, true);
			if(is_array($jdat) && $jdat['errorMsg']){
				$this->errorMsg = $jdat['errorMsg'];
				return false;
			}
		}
		return array('code' => $httpStatus, 'data' => $data);
	}
	public function makeAPIQueryString(){
		$siteurl = '';
		if(function_exists('get_bloginfo')){
			$siteurl = get_bloginfo('siteurl');
		}
		return http_build_query(array(
			'v' => $this->wordpressVersion, 
			's' => $siteurl, 
			'k' => $this->APIKey
			));
	}
	private function getAPIURL(){
		$ssl_supported = false;
		if(defined('CURL_VERSION_SSL') && function_exists('curl_version')){
			$version = curl_version();
			$ssl_supported = ($version['features'] & CURL_VERSION_SSL);
		}
		return $ssl_supported ? WORDFENCE_API_URL_SEC : WORDFENCE_API_URL_NONSEC;
	}
}

?>
