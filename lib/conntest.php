<?php if(! wfUtils::isAdmin()){ exit(); } ?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"  dir="ltr" lang="en-US">
<head>
<title>Wordfence Connectivity Tester</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<body>
<h1>Wordfence connectivity tester</h1>
<br /><br />
DNS lookup for noc1.wordfence.com returns: <?php echo gethostbyname('noc1.wordfence.com'); ?><br /><br />
<?php
$curlContent = "";
function curlWrite($h, $d){
	global $curlContent;
	$curlContent .= $d;
	return strlen($d);
}
function doCurlTest($protocol){
	echo "<br /><b>STARTING CURL $protocol CONNECTION TEST....</b><br />\n";
	global $curlContent;
	$curlContent = "";
	$curl = curl_init($protocol . '://noc1.wordfence.com/');
	curl_setopt ($curl, CURLOPT_TIMEOUT, 900);
	curl_setopt ($curl, CURLOPT_USERAGENT, "Wordfence.com UA " . (defined('WORDFENCE_VERSION') ? WORDFENCE_VERSION : '[Unknown version]') );
	curl_setopt ($curl, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt ($curl, CURLOPT_HEADER, 0);
	curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, false);
	curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, false);
	curl_setopt ($curl, CURLOPT_WRITEFUNCTION, 'curlWrite');
	$curlResult = curl_exec($curl);
	$httpStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
	if(strpos($curlContent, 'Your site did not send an API key') !== false){
		echo "Curl connectivity test passed.<br /><br />\n";
	} else {
		$curlErrorNo = curl_errno($curl);
		$curlError = curl_error($curl);
		echo "Curl connectivity test failed with response: <pre>$curlContent</pre>";
		echo "<br />Curl HTTP status: $httpStatus<br />Curl error code: $curlErrorNo<br />Curl Error: $curlError<br /><br />\n";
	}
}
doCurlTest('http');
doCurlTest('https');
?>
</body>
</html>

