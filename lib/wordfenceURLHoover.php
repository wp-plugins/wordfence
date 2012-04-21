<?php
require_once('wfAPI.php');
class wordfenceURLHoover {
	private $debug = false;
	private $URLsByID = array();
	private $hostKeysByID = array();
	public $errorMsg = false;
	private $hostKeyCache = array();
	private $api = false;
	private $dRegex = 'aero|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw|xn--lgbbat1ad8j|xn--fiqs8s|xn--fiqz9s|xn--wgbh1c|xn--j6w193g|xn--h2brj9c|xn--mgbbh1a71e|xn--fpcrj9c3d|xn--gecrj9c|xn--s9brj9c|xn--xkc2dl3a5ee0h|xn--45brj9c|xn--mgba3a4f16a|xn--mgbayh7gpa|xn--mgbc0a9azcg|xn--ygbi2ammx|xn--wgbl6a|xn--p1ai|xn--mgberp4a5d4ar|xn--90a3ac|xn--yfro4i67o|xn--clchc0ea0b2g2a9gcd|xn--3e0b707e|xn--fzc2c9e2c|xn--xkc2al3hye2a|xn--mgbtf8fl|xn--kprw13d|xn--kpry57d|xn--o3cw4h|xn--pgbs0dh|xn--mgbaam7a8h|xn--54b7fta0cc|xn--90ae|xn--node|xn--4dbrk0ce|xn--80ao21a|xn--mgb9awbf|xn--mgbai9azgqp6j|xn--j1amh|xn--mgb2ddes|xn--kgbechtv|xn--hgbk6aj7f53bba|xn--0zwm56d|xn--g6w251d|xn--80akhbyknj4f|xn--11b5bs3a9aj6g|xn--jxalpdlp|xn--9t4b11yi5a|xn--deba0ad|xn--zckzah|xn--hlcj6aya9esc7a';
	public function __construct($apiKey, $wordpressVersion){
		$this->api = new wfAPI($apiKey, $wordpressVersion);
	}
	public function hoover($id, $data){
		if(! strstr($data, '.') ){
			return;
		}
		if(! preg_match('/[a-zA-Z0-9\-]+\.(?:' . $this->dRegex . ')/i', $data)){
			return;
		}
		try {
			@preg_replace("/(?<=^|[^a-zA-Z0-9\-])((?:[a-zA-Z0-9\-]+\.)+)(" . $this->dRegex . ")((?:$|[^a-zA-Z0-9\-\.\'\"])[^\r\n\s\t\"\'\$\{\}<>]*)/ie", "\$this->" . "addHost(\$id, \"$1$2\", \"$3\")", $data);
		} catch(Exception $e){ error_log("Regex error 1: $e"); }
		preg_replace("/(?<=[^\d]|^)(\d{8,10}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([^\d\'\"][^\r\n\s\t\"\'\$\{\}<>]*)/e", "\$this->" . "addIP(\$id, \"$1\",\"$2\")", $data);
	}
	private function dbg($msg){ if($this->debug){ error_log("DEBUG: $msg\n"); } }
	public function addHost($id, $host, $path){
		$this->dbg("Adding host with ID $id and $host $path");
		$path = preg_replace_callback('/([^A-Za-z0-9\-\.\_\~:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,;\=]+)/', 'wordfenceURLHoover::urlenc', $path);
		$host = strtolower($host);
		$this->intAddHost($id, $host, $path);
	}
	public function addIP($id, $ipdata, $path){
		$this->dbg("Adding IP with ID $id and $ipdata $path");
		$path = preg_replace_callback('/([^A-Za-z0-9\-\.\_\~:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,;\=]+)/', 'wordfenceURLHoover::urlenc', $path);
		if(strstr($ipdata, '.') === false && $ipdata >= 16777216 && $ipdata <= 4026531840){
			$ipdata = long2ip($ipdata);
		} 
		$parts = explode('.', $ipdata);
		$isValid = true;
		if($parts[0] >= 240 || $parts[0] == '10' || $parts[0] == '172' || $parts[0] == '192' || $parts[0] == '127'){
			$isValid = false;
		}
		if($isValid){
			foreach($parts as $part){
				if($part < 1 || $part > 255){
					$isValid = false;
				}
			}
		}
		if($isValid && $ipdata){
			$this->intAddHost($id, $ipdata, $path);
		}
	}
	public static function urlenc($m){
		return urlencode($m[1]);
	}
	private function intAddHost($id, $host, $path){
		if(strpos($path, '/') !== 0){
			$path = '/';
		}
		foreach($this->URLsByID as $elem){
			if($elem[0] == $host && $elem[1] == $path){
				$this->dbg("Host/Path $host $path already in URLsByID");
				return false;
			}
		}
		$this->dbg("Adding Host/Path $host $path to URLsByID");
		$this->URLsByID[$id][] = array($host, $path);
		return true;
	}
	private function makeHostKey($host){
		if(isset($this->hostKeyCache[$host])){
			$this->dbg("Returning cached hostkey for $host");
			return $this->hostKeyCache[$host];
		}
		$hostParts = explode('.', $host);
		$hostKey = '';
		if(sizeof($hostParts) == 2){
			$hostKey = substr(hash('sha256', $hostParts[0] . '.' . $hostParts[1] . '/', true), 0, 4);
		} else if(sizeof($hostParts) > 2){
			$hostKey = substr(hash('sha256', $hostParts[sizeof($hostParts) - 3] . '.' . $hostParts[sizeof($hostParts) - 2] . '.' . $hostParts[sizeof($hostParts) - 1] . '/', true), 0, 4);
		}
		$this->hostKeyCache[$host] = $hostKey;
		$this->dbg("Returning uncached hostkey for $host");
		return $hostKey;
	}
	public function getBaddies(){
		$allHostKeys = array();
		foreach($this->URLsByID as $id => $hostPathList){
			foreach($hostPathList as $elem){
				$host = $elem[0];
				$path = $elem[1];
				$hostKey = $this->makeHostKey($host);
				if(! in_array($hostKey, $allHostKeys)){
					array_push($allHostKeys, $hostKey);
					$this->dbg("Adding hostkey for $host");
				}
				if(! isset($this->hostKeysByID[$id])){
					$this->hostKeysByID[$id] = array();
				}
				$this->hostKeysByID[$id] = $hostKey;
			}
		}
		//Now call API and check if any hostkeys are bad. 
		//This is a shortcut, because if no hostkeys are bad it saves us having to check URLs
		if(sizeof($allHostKeys) > 0){ //If we don't have any hostkeys, then we won't have any URL's to check either.
			//Hostkeys are 4 byte sha256 prefixes
			//Returned value is 2 byte shorts which are array indexes for bad keys that were passed in the original list
			$this->dbg("Checking " . sizeof($allHostKeys) . " hostkeys");
			$resp = $this->api->binCall('check_host_keys', implode('', $allHostKeys));
			$this->dbg("Done hostkey check");
			if($this->api->errorMsg){
				$this->errorMsg = $this->api->errorMsg;
				return false;
			}

			$badHostKeys = array();
			if($resp['code'] == 200){
				if(strlen($resp['data']) > 0){
					$dataLen = strlen($resp['data']);
					if($dataLen % 2 != 0){
						$this->errorMsg = "Invalid data length received from Wordfence server: " . $dataLen;
						return false;
					}
					for($i = 0; $i < $dataLen; $i += 2){
						$idxArr = unpack('n', substr($resp['data'], $i, 2));
						$idx = $idxArr[1];
						if(isset($allHostKeys[$idx]) ){
							array_push($badHostKeys, $allHostKeys[$idx]);
						} else {
							$this->errorMsg = "Bad allHostKeys index: $idx";
							return false;
						}
					}
				}
			} else {
				$this->errorMsg = "Wordfence server responded with an error. HTTP code " . $resp['code'] . " and data: " . $resp['data'];
				return false;
			}
			if(sizeof($badHostKeys) > 0){
				$urlsToCheck = array();
				//need to figure out which id's have bad hostkeys
				//need to feed in all URL's from those id's where the hostkey matches a URL
				foreach($this->URLsByID as $id => $hostPathList){
					foreach($hostPathList as $elem){
						$host = $elem[0];
						$path = $elem[1];
						$url = 'http://' . $host . $path;
						$hostKey = $this->makeHostKey($host);
						if(in_array($hostKey, $badHostKeys)){
							if(! isset($urlsToCheck[$id])){
								$urlsToCheck[$id] = array();
							}
							if(! in_array($url, $urlsToCheck[$id])){
								$urlsToCheck[$id][] = $url;
							}
						}
					}
				}
				if(sizeof($urlsToCheck) > 0){
					$this->dbg("Checking " . sizeof($urlsToCheck) . " URLs");
					$badURLs = $this->api->call('check_bad_urls', array(), array( 'toCheck' => json_encode($urlsToCheck)) );
					$this->dbg("Done URL check");
					if($this->api->errorMsg){
						$this->errorMsg = $this->api->errorMsg;
						return false;
					}
					if(is_array($badURLs) && sizeof($badURLs) > 0){
						$finalResults = array();
						foreach($badURLs as $file => $badSiteList){
							if(! isset($finalResults[$file])){
								$finalResults[$file] = array();
							}
							foreach($badSiteList as $badSite){
								array_push($finalResults[$file], array(
									'URL' => $badSite[0],
									'badList' => $badSite[1]
									));
							}
						}
						return $finalResults;
					} else {
						return array();
					}
				} else {
					return array();
				}
			} else {
				return array();
			}
		} else {
			return array();
		}
	}
}
?>
