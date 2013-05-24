<?php
require_once('wordfenceConstants.php');
require_once('wordfenceClass.php');
class wfAPI {
	public $lastHTTPStatus = '';
	public $lastCurlErrorNo = '';
	private $curlContent = 0;
	private $APIKey = '';
	private $wordpressVersion = '';
	private static $maintMsg = "The Wordfence scanning server could not be contacted.";
	public function __construct($apiKey, $wordpressVersion){
		$this->APIKey = $apiKey;
		$this->wordpressVersion = $wordpressVersion;
	}
	public function getStaticURL($url){ // In the form '/something.bin' without quotes
		return $this->getURL($this->getAPIURL() . $url);
	}
	public function call($action, $getParams = array(), $postParams = array()){
		$json = $this->getURL($this->getAPIURL() . '/v' . WORDFENCE_API_VERSION . '/?' . $this->makeAPIQueryString() . '&' . self::buildQuery(
			array_merge(
				array('action' => $action),
				$getParams	
				)), $postParams);
		if(! $json){
			throw new Exception("We received an empty data response from the Wordfence scanning servers when calling the '$action' function.");
		}

		$dat = json_decode($json, true);
		if(! is_array($dat)){
			throw new Exception("We received a data structure that is not the expected array when contacting the Wordfence scanning servers and calling the '$action' function.");
		}
		if(is_array($dat) && isset($dat['errorMsg'])){
			throw new Exception($dat['errorMsg']);
		}
		return $dat;
	}
	public function curlWrite($h, $d){
		$this->curlContent .= $d;
		return strlen($d);
	}
	protected function getURL($url, $postParams = array()){
		if(function_exists('curl_init')){
			$this->curlDataWritten = 0;
			$this->curlContent = "";
			$curl = curl_init($url);
			curl_setopt ($curl, CURLOPT_TIMEOUT, 900);
			curl_setopt ($curl, CURLOPT_USERAGENT, "Wordfence.com UA " . (defined('WORDFENCE_VERSION') ? WORDFENCE_VERSION : '[Unknown version]') );
			curl_setopt ($curl, CURLOPT_RETURNTRANSFER, TRUE);
			curl_setopt ($curl, CURLOPT_HEADER, 0);
			curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, false);
			curl_setopt ($curl, CURLOPT_WRITEFUNCTION, array($this, 'curlWrite'));
			curl_setopt($curl, CURLOPT_POST, true);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $postParams);
			wordfence::status(4, 'info', "CURL fetching URL: " . $url);
			$curlResult = curl_exec($curl);

			$httpStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
			$this->lastCurlErrorNo = curl_errno($curl);
			if($httpStatus == 200){
				curl_close($curl);
				return $this->curlContent;
			} else {
				$cerror = curl_error($curl);
				curl_close($curl);
				throw new Exception("We received an error response when trying to contact the Wordfence scanning servers. The HTTP status code was [$httpStatus] and the curl error number was [" . $this->lastCurlErrorNo . "] " . ($cerror ? (' and the error from CURL was: ' . $cerror) : ''));
			}
		} else {
			wordfence::status(4, 'info', "Fetching URL with file_get: " . $url);
			$data = $this->fileGet($url, $postParams);
			if($data === false){
				$err = error_get_last();
				if($err){
					throw new Exception("We received an error response when trying to contact the Wordfence scanning servers using PHP's file_get_contents function. The error was: " . $err);
				} else {
					throw new Exception("We received an empty response when trying to contact the Wordfence scanning servers using PHP's file_get_contents function.");
				}
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
		$url = $this->getAPIURL() . '/v' . WORDFENCE_API_VERSION . '/?' . $this->makeAPIQueryString() . '&action=' . $func;
		if(function_exists('curl_init')){
			$curl = curl_init($url);
			curl_setopt ($curl, CURLOPT_TIMEOUT, 900);
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
			if($httpStatus != 200){
				$cError = curl_error($curl);
				curl_close($curl);
				if($cError){
					throw new Exception("We received an error response when trying to fetch binary data from the Wordfence scanning server. The HTTP status was [$httpStatus] with error: $cError");
				} else {
					throw new Exception("We received an error HTTP response when trying to fetch binary data from the Wordfence scanning server: [$httpStatus]");
				}
			}
		} else {
			$data = $this->fileGet($url, $postData);
			if($data === false){
				$err = error_get_last();
				if($err){
					throw new Exception("We received an error response when trying to fetch binary data from the Wordfence scanning server using file_get_contents: $err");
				} else {
					throw new Exception("We received an error when trying to fetch binary data from the Wordfence scanning server using file_get_contents. There was no message explaining the error.");
				}
			}
			$httpStatus = '200';
		}
		if(preg_match('/\{.*errorMsg/', $data)){
			$jdat = @json_decode($data, true);
			if(is_array($jdat) && $jdat['errorMsg']){
				throw new Exception($jdat['errorMsg']);
			}
		}
		return array('code' => $httpStatus, 'data' => $data);
	}
	public function makeAPIQueryString(){
		$siteurl = '';
		if(function_exists('get_bloginfo')){
			if(is_multisite()){
				$siteurl = network_home_url();
				$siteurl = rtrim($siteurl, '/'); //Because previously we used get_bloginfo and it returns http://example.com without a '/' char.
			} else {
				$siteurl = home_url();
			}
		}
		return self::buildQuery(array(
			'v' => $this->wordpressVersion, 
			's' => $siteurl, 
			'k' => $this->APIKey
			));
	}
	private function buildQuery($data){
		if(version_compare(phpversion(), '5.1.2', '>=')){
			return http_build_query($data, '', '&'); //arg_separator parameter was only added in PHP 5.1.2. We do this because some PHP.ini's have arg_separator.output set to '&amp;'
		} else {
			return http_build_query($data);
		}
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
