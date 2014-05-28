<?php 
$w = new wfConfig(); 
?>
<script type="text/javascript">
var WFSLevels = <?php echo json_encode(wfConfig::$securityLevels); ?>;
</script>
<div class="wordfenceModeElem" id="wordfenceMode_options"></div>
<div class="wrap">
	<?php require('menuHeader.php'); ?>
	<?php $pageTitle = "Wordfence Options"; include('pageTitle.php'); ?>
	<div class="wordfenceLive">
		<table border="0" cellpadding="0" cellspacing="0">
		<tr><td><h2>Wordfence Live Activity:</h2></td><td id="wfLiveStatus"></td></tr>
		</table>
	</div>

	<form id="wfConfigForm">
	<table class="wfConfigForm">
	<tr><td colspan="2"><h2>License</h2></td></tr>

	<tr><th>Your Wordfence API Key:</th><td><input type="text" id="apiKey" name="apiKey" value="<?php $w->f('apiKey'); ?>" size="80" /></td></tr>
	<tr><th>Key type currently active:</th><td>
		<?php if(wfConfig::get('isPaid')){ ?>
		The currently active API Key is a Premium Key. <span style="font-weight: bold; color: #0A0;">Premium scanning enabled!</span>
		<?php } else {?>
		The currently active API Key is a <span style="color: #F00; font-weight: bold;">Free Key</a>. <a href="https://www.wordfence.com/wordfence-signup/" target="_blank">Click Here to Upgrade to Wordfence Premium now.</a>
		<?php } ?>
	</td></tr>
	<tr><td colspan="2">
		<?php if(wfConfig::get('isPaid')){ ?>
		<table border="0"><tr><td><a href="https://www.wordfence.com/manage-wordfence-api-keys/" target="_blank"><input type="button" value="Renew your premium license" /></a></td><td>&nbsp;</td><td><input type="button" value="Downgrade to a free license" onclick="WFAD.downgradeLicense();" /></td></tr></table>
		<?php } ?>


	<tr><td colspan="2"><h2>Basic Options</h2></td></tr>
	<tr><th class="wfConfigEnable">Enable firewall </th><td><input type="checkbox" id="firewallEnabled" class="wfConfigElem" name="firewallEnabled" value="1" <?php $w->cb('firewallEnabled'); ?> />&nbsp;<span style="color: #F00;">NOTE:</span> This checkbox enables ALL firewall functions including IP, country and advanced blocking and the "Firewall Rules" below.</td></tr>
	<tr><td colspan="2">&nbsp;</td></tr>
	<tr><th class="wfConfigEnable">Enable login security</th><td><input type="checkbox" id="loginSecurityEnabled" class="wfConfigElem" name="loginSecurityEnabled" value="1" <?php $w->cb('loginSecurityEnabled'); ?> />&nbsp;This option enables all "Login Security" options. You can modify individual options further down this page.</td></tr>
	<tr><td colspan="2">&nbsp;</td></tr>
	<tr><th class="wfConfigEnable">Enable Live Traffic View</th><td><input type="checkbox" id="liveTrafficEnabled" class="wfConfigElem" name="liveTrafficEnabled" value="1" <?php $w->cb('liveTrafficEnabled'); ?> onclick="WFAD.reloadConfigPage = true; return true;" />&nbsp;This option enables live traffic logging.</td></tr>
	<tr><td colspan="2">&nbsp;</td></tr>
	<tr><th class="wfConfigEnable">Advanced Comment Spam Filter</th><td><input type="checkbox" id="advancedCommentScanning" class="wfConfigElem" name="advancedCommentScanning" value="1" <?php $w->cbp('advancedCommentScanning'); if(! wfConfig::get('isPaid')){ ?>onclick="alert('This is a paid feature because it places significant additional load on our servers.'); jQuery('#advancedCommentScanning').attr('checked', false); return false;" <?php } ?> />&nbsp;<span style="color: #F00;">Premium Feature</span> In addition to free comment filtering (see below) this option filters comments against several additional real-time lists of known spammers and infected hosts.</td></tr>
	<tr><th class="wfConfigEnable">Check if this website is being "Spamvertised"</th><td><input type="checkbox" id="spamvertizeCheck" class="wfConfigElem" name="spamvertizeCheck" value="1" <?php $w->cbp('spamvertizeCheck'); if(! wfConfig::get('isPaid')){ ?>onclick="alert('This is a paid feature because it places significant additional load on our servers.'); jQuery('#spamvertizeCheck').attr('checked', false); return false;" <?php } ?> />&nbsp;<span style="color: #F00;">Premium Feature</span> When doing a scan, Wordfence will check with spam services if your site domain name is appearing as a link in spam emails.</td></tr>
	<tr><th class="wfConfigEnable">Check if this website IP is generating spam</th><td><input type="checkbox" id="checkSpamIP" class="wfConfigElem" name="checkSpamIP" value="1" <?php $w->cbp('checkSpamIP'); if(! wfConfig::get('isPaid')){ ?>onclick="alert('This is a paid feature because it places significant additional load on our servers.'); jQuery('#checkSpamIP').attr('checked', false); return false;" <?php } ?> />&nbsp;<span style="color: #F00;">Premium Feature</span> When doing a scan, Wordfence will check with spam services if your website IP address is listed as a known source of spam email.</td></tr>
	<tr><td colspan="2">&nbsp;</td></tr>
	<?php /* <tr><th class="wfConfigEnable">Enable Performance Monitoring</th><td><input type="checkbox" id="perfLoggingEnabled" class="wfConfigElem" name="perfLoggingEnabled" value="1" <?php $w->cb('perfLoggingEnabled'); ?> onclick="WFAD.reloadConfigPage = true; return true;" />&nbsp;This option enables performance monitoring.</td></tr> */ ?>
	<tr><td colspan="2">&nbsp;</td></tr>
	<tr><th class="wfConfigEnable">Enable automatic scheduled scans</th><td><input type="checkbox" id="scheduledScansEnabled" class="wfConfigElem" name="scheduledScansEnabled" value="1" <?php $w->cb('scheduledScansEnabled'); ?> />&nbsp;Regular scans ensure your site stays secure.</td></tr>
	<tr><td colspan="2">&nbsp;</td></tr>

	<tr><th>Where to email alerts:</th><td><input type="text" id="alertEmails" name="alertEmails" value="<?php $w->f('alertEmails'); ?>" size="50" />&nbsp;<span class="wfTipText">Separate multiple emails with commas</span></td></tr>
	<tr><th colspan="2">&nbsp;</th></tr>
	<tr><th>Security Level:</th><td>
		<select id="securityLevel" name="securityLevel" onchange="WFAD.changeSecurityLevel(); return true;">
			<option value="0"<?php $w->sel('securityLevel', '0'); ?>>Level 0: Disable all Wordfence security measures</option>
			<option value="1"<?php $w->sel('securityLevel', '1'); ?>>Level 1: Light protection. Just the basics</option>
			<option value="2"<?php $w->sel('securityLevel', '2'); ?>>Level 2: Medium protection. Suitable for most sites</option>
			<option value="3"<?php $w->sel('securityLevel', '3'); ?>>Level 3: High security. Use this when an attack is imminent</option>
			<option value="4"<?php $w->sel('securityLevel', '4'); ?>>Level 4: Lockdown. Protect the site against an attack in progress at the cost of inconveniencing some users</option>
			<option value="CUSTOM"<?php $w->sel('securityLevel', 'CUSTOM'); ?>>Custom settings</option>
		</select>
		</td></tr>
	<tr><th>How does Wordfence get IPs:</th><td>
		<select id="howGetIPs" name="howGetIPs">
			<option value="">Set this option if you're seeing visitors from fake IP addresses or who appear to be from your internal network but aren't.</option>
			<option value="REMOTE_ADDR"<?php $w->sel('howGetIPs', 'REMOTE_ADDR'); ?>>Use PHP's built in REMOTE_ADDR. Use this if you're not using Nginx or any separate front-end proxy or firewall. Try this first.</option>
			<option value="HTTP_X_REAL_IP"<?php $w->sel('howGetIPs', 'HTTP_X_REAL_IP'); ?>>Use the X-Real-IP HTTP header which my Nginx, firewall or front-end proxy is setting. Try this next.</option>
			<option value="HTTP_X_FORWARDED_FOR"<?php $w->sel('howGetIPs', 'HTTP_X_FORWARDED_FOR'); ?>>Use the X-Forwarded-For HTTP header which my Nginx, firewall or front-end proxy is setting.</option>
			<option value="HTTP_CF_CONNECTING_IP"<?php $w->sel('howGetIPs', 'HTTP_CF_CONNECTING_IP'); ?>>I'm using Cloudflare so use the "CF-Connecting-IP" HTTP header to get a visitor IP</option>
		</select>
		</td></tr>
	</table>
	<p><table border="0" cellpadding="0" cellspacing="0"><tr><td><input type="button" id="button1" name="button1" class="button-primary" value="Save Changes" onclick="WFAD.saveConfig();" /></td><td style="height: 24px;"><div class="wfAjax24"></div><span class="wfSavedMsg">&nbsp;Your changes have been saved!</span></td></tr></table></p>
	<div class="wfMarker" id="wfMarkerBasicOptions"></div>
	<div style="margin-top: 25px;">
		<h2>Advanced Options:</h2>
		<p style="width: 600px;">
			Wordfence works great out of the box for most websites. Simply install Wordfence and your site and content is protected. For finer granularity of control, we have provided advanced options.
		</p>
	</div>
	<div id="wfConfigAdvanced">
	<table class="wfConfigForm">
	<tr><td colspan="2"><h3 class="wfConfigHeading">Alerts</h3></td></tr>
	<?php
		$emails = wfConfig::getAlertEmails();
                if(sizeof($emails) < 1){ 
			echo "<tr><th colspan=\"2\" style=\"color: #F00;\">You have not configured an email to receive alerts yet. Set this up under \"Basic Options\" above.</th></tr>\n";
		}
	?>
	<tr><th>Alert on critical problems</th><td><input type="checkbox" id="alertOn_critical" class="wfConfigElem" name="alertOn_critical" value="1" <?php $w->cb('alertOn_critical'); ?>/></td></tr>
	<tr><th>Alert on warnings</th><td><input type="checkbox" id="alertOn_warnings" class="wfConfigElem" name="alertOn_warnings" value="1" <?php $w->cb('alertOn_warnings'); ?>/></td></tr>
	<tr><th>Alert when an IP address is blocked</th><td><input type="checkbox" id="alertOn_block" class="wfConfigElem" name="alertOn_block" value="1" <?php $w->cb('alertOn_block'); ?>/></td></tr>
	<tr><th>Alert when someone is locked out from login</th><td><input type="checkbox" id="alertOn_loginLockout" class="wfConfigElem" name="alertOn_loginLockout" value="1" <?php $w->cb('alertOn_loginLockout'); ?>/></td></tr>
	<tr><th>Alert when the "lost password" form is used for a valid user</th><td><input type="checkbox" id="alertOn_lostPasswdForm" class="wfConfigElem" name="alertOn_lostPasswdForm" value="1" <?php $w->cb('alertOn_lostPasswdForm'); ?>/></td></tr>
	<tr><th>Alert me when someone with administrator access signs in</th><td><input type="checkbox" id="alertOn_adminLogin" class="wfConfigElem" name="alertOn_adminLogin" value="1" <?php $w->cb('alertOn_adminLogin'); ?>/></td></tr>
	<tr><th>Alert me when a non-admin user signs in</th><td><input type="checkbox" id="alertOn_nonAdminLogin" class="wfConfigElem" name="alertOn_nonAdminLogin" value="1" <?php $w->cb('alertOn_nonAdminLogin'); ?>/></td></tr>
	<tr><th>Maximum email alerts to send per hour</th><td>&nbsp;<input type="text" id="alert_maxHourly" name="alert_maxHourly" value="<?php $w->f('alert_maxHourly'); ?>" size="4" />0 or empty means unlimited alerts will be sent.</td></tr>
	<tr><td colspan="2">
		<div class="wfMarker" id="wfMarkerLiveTrafficOptions"></div>
		<h3 class="wfConfigHeading">Live Traffic View</h3>
	</td></tr>
	<tr><th>Don't log signed-in users with publishing access:</th><td><input type="checkbox" id="liveTraf_ignorePublishers" name="liveTraf_ignorePublishers" value="1" <?php $w->cb('liveTraf_ignorePublishers'); ?> /></td></tr>
	<tr><th>List of comma separated usernames to ignore:</th><td><input type="text" name="liveTraf_ignoreUsers" id="liveTraf_ignoreUsers" value="<?php echo $w->getHTML('liveTraf_ignoreUsers'); ?>" /></td></tr>
	<tr><th>List of comma separated IP addresses to ignore:</th><td><input type="text" name="liveTraf_ignoreIPs" id="liveTraf_ignoreIPs" value="<?php echo $w->getHTML('liveTraf_ignoreIPs'); ?>" /></td></tr>
	<tr><th>Browser user-agent to ignore:</th><td><input type="text" name="liveTraf_ignoreUA" id="liveTraf_ignoreUA" value="<?php echo $w->getHTML('liveTraf_ignoreUA'); ?>" /></td></tr>
	<tr><td colspan="2">
		<div class="wfMarker" id="wfMarkerScansToInclude"></div>
		<h3 class="wfConfigHeading">Scans to include</h3></td></tr>
	<?php if(wfConfig::get('isPaid')){ ?>
	<tr><th>Scan public facing site for vulnerabilities?</th><td><input type="checkbox" id="scansEnabled_public" class="wfConfigElem" name="scansEnabled_public" value="1" <?php $w->cb('scansEnabled_public'); ?></td></tr>
	<?php } else { ?>
	<tr><th style="color: #F00;">Scan public facing site for vulnerabilities? (<a href="https://www.wordfence.com/wordfence-signup/" target="_blank">Paid members only</a>)</th><td><input type="checkbox" id="scansEnabled_public" class="wfConfigElem" name="scansEnabled_public" value="1" DISABLED ?></td></tr>
	<?php } ?>
	<tr><th>Scan for the HeartBleed vulnerability?</th><td><input type="checkbox" id="scansEnabled_heartbleed" class="wfConfigElem" name="scansEnabled_heartbleed" value="1" <?php $w->cb('scansEnabled_heartbleed'); ?></td></tr>
	<tr><th>Scan core files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_core" class="wfConfigElem" name="scansEnabled_core" value="1" <?php $w->cb('scansEnabled_core'); ?>/></td></tr>
	
	<tr><th>Scan theme files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_themes" class="wfConfigElem" name="scansEnabled_themes" value="1" <?php $w->cb('scansEnabled_themes'); ?>/></td></tr>
	<tr><th>Scan plugin files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_plugins" class="wfConfigElem" name="scansEnabled_plugins" value="1" <?php $w->cb('scansEnabled_plugins'); ?>/></td></tr>
	<tr><th>Scan for signatures of known malicious files</th><td><input type="checkbox" id="scansEnabled_malware" class="wfConfigElem" name="scansEnabled_malware" value="1" <?php $w->cb('scansEnabled_malware'); ?>/></td></tr>
	<tr><th>Scan file contents for backdoors, trojans and suspicious code</th><td><input type="checkbox" id="scansEnabled_fileContents" class="wfConfigElem" name="scansEnabled_fileContents" value="1" <?php $w->cb('scansEnabled_fileContents'); ?>/></td></tr>
	<tr><th>Scan posts for known dangerous URLs and suspicious content</th><td><input type="checkbox" id="scansEnabled_posts" class="wfConfigElem" name="scansEnabled_posts" value="1" <?php $w->cb('scansEnabled_posts'); ?>/></td></tr>
	<tr><th>Scan comments for known dangerous URLs and suspicious content</th><td><input type="checkbox" id="scansEnabled_comments" class="wfConfigElem" name="scansEnabled_comments" value="1" <?php $w->cb('scansEnabled_comments'); ?>/></td></tr>
	<tr><th>Scan for out of date plugins, themes and WordPress versions</th><td><input type="checkbox" id="scansEnabled_oldVersions" class="wfConfigElem" name="scansEnabled_oldVersions" value="1" <?php $w->cb('scansEnabled_oldVersions'); ?>/></td></tr>
	<tr><th>Check the strength of passwords</th><td><input type="checkbox" id="scansEnabled_passwds" class="wfConfigElem" name="scansEnabled_passwds" value="1" <?php $w->cb('scansEnabled_passwds'); ?>/></td></tr>
	<tr><th>Scan options table</th><td><input type="checkbox" id="scansEnabled_options" class="wfConfigElem" name="scansEnabled_options" value="1" <?php $w->cb('scansEnabled_options'); ?>/></td></tr>
	<tr><th>Monitor disk space</th><td><input type="checkbox" id="scansEnabled_diskSpace" class="wfConfigElem" name="scansEnabled_diskSpace" value="1" <?php $w->cb('scansEnabled_diskSpace'); ?>/></td></tr>
	<tr><th>Scan for unauthorized DNS changes</th><td><input type="checkbox" id="scansEnabled_dns" class="wfConfigElem" name="scansEnabled_dns" value="1" <?php $w->cb('scansEnabled_dns'); ?>/></td></tr>
	<tr><th>Scan files outside your WordPress installation</th><td><input type="checkbox" id="other_scanOutside" class="wfConfigElem" name="other_scanOutside" value="1" <?php $w->cb('other_scanOutside'); ?> /></td></tr>
	<tr><th>Scan image files as if they were executable</th><td><input type="checkbox" id="scansEnabled_scanImages" class="wfConfigElem" name="scansEnabled_scanImages" value="1" <?php $w->cb('scansEnabled_scanImages'); ?> /></td></tr>
	<tr><th>Enable HIGH SENSITIVITY scanning. May give false positives.</th><td><input type="checkbox" id="scansEnabled_highSense" class="wfConfigElem" name="scansEnabled_highSense" value="1" <?php $w->cb('scansEnabled_highSense'); ?> /></td></tr>
	<tr><th>Exclude files from scan that match these wildcard patterns. Comma separated.</th><td><input type="text" id="scan_exclude" class="wfConfigElem" name="scan_exclude" size="20" value="<?php echo $w->getHTML('scan_exclude'); ?>" />e.g. *.sql,*.tar,backup*.zip</td></tr>
	<tr><td colspan="2">
		<div class="wfMarker" id="wfMarkerFirewallRules"></div>
		<h3 class="wfConfigHeading">Firewall Rules</h3>
	</td></tr>
	<tr><th>Immediately block fake Google crawlers:</th><td><input type="checkbox" id="blockFakeBots" class="wfConfigElem" name="blockFakeBots" value="1" <?php $w->cb('blockFakeBots'); ?>/></td></tr>
	<tr><th>How should we treat Google's crawlers</th><td>
		<select id="neverBlockBG" class="wfConfigElem" name="neverBlockBG">
			<option value="neverBlockVerified"<?php $w->sel('neverBlockBG', 'neverBlockVerified'); ?>>Verified Google crawlers have unlimited access to this site</option>
			<option value="neverBlockUA"<?php $w->sel('neverBlockBG', 'neverBlockUA'); ?>>Anyone claiming to be Google has unlimited access</option>
			<option value="treatAsOtherCrawlers"<?php $w->sel('neverBlockBG', 'treatAsOtherCrawlers'); ?>>Treat Google like any other Crawler</option>
		</select></td></tr>	
	<tr><th>If anyone's requests exceed:</th><td><?php $rateName='maxGlobalRequests'; require('wfRate.php'); ?> then <?php $throtName='maxGlobalRequests_action'; require('wfAction.php'); ?></td></tr>
	<tr><th>If a crawler's page views exceed:</th><td><?php $rateName='maxRequestsCrawlers'; require('wfRate.php'); ?> then <?php $throtName='maxRequestsCrawlers_action'; require('wfAction.php'); ?></td></tr>
	<tr><th>If a crawler's pages not found (404s) exceed:</th><td><?php $rateName='max404Crawlers'; require('wfRate.php'); ?> then <?php $throtName='max404Crawlers_action'; require('wfAction.php'); ?></td></tr>
	<tr><th>If a human's page views exceed:</th><td><?php $rateName='maxRequestsHumans'; require('wfRate.php'); ?> then <?php $throtName='maxRequestsHumans_action'; require('wfAction.php'); ?></td></tr>
	<tr><th>If a human's pages not found (404s) exceed:</th><td><?php $rateName='max404Humans'; require('wfRate.php'); ?> then <?php $throtName='max404Humans_action'; require('wfAction.php'); ?></td></tr>
	<tr><th>If 404's for known vulnerable URL's exceed:</th><td><?php $rateName='maxScanHits'; require('wfRate.php'); ?> then <?php $throtName='maxScanHits_action'; require('wfAction.php'); ?></td></tr>
	<tr><th>How long is an IP address blocked when it breaks a rule:</th><td>
		<select id="blockedTime" class="wfConfigElem" name="blockedTime">
			<option value="60"<?php $w->sel('blockedTime', '60'); ?>>1 minute</option>
			<option value="300"<?php $w->sel('blockedTime', '300'); ?>>5 minutes</option>
			<option value="1800"<?php $w->sel('blockedTime', '1800'); ?>>30 minutes</option>
			<option value="3600"<?php $w->sel('blockedTime', '3600'); ?>>1 hour</option>
			<option value="7200"<?php $w->sel('blockedTime', '7200'); ?>>2 hours</option>
			<option value="21600"<?php $w->sel('blockedTime', '21600'); ?>>6 hours</option>
			<option value="43200"<?php $w->sel('blockedTime', '43200'); ?>>12 hours</option>
			<option value="86400"<?php $w->sel('blockedTime', '86400'); ?>>1 day</option>
			<option value="172800"<?php $w->sel('blockedTime', '172800'); ?>>2 days</option>
			<option value="432000"<?php $w->sel('blockedTime', '432000'); ?>>5 days</option>
			<option value="864000"<?php $w->sel('blockedTime', '864000'); ?>>10 days</option>
			<option value="2592000"<?php $w->sel('blockedTime', '2592000'); ?>>1 month</option>
		</select></td></tr>

	<tr><td colspan="2">
		<div class="wfMarker" id="wfMarkerLoginSecurity"></div>
		<h3 class="wfConfigHeading">Login Security Options</h3>
		</td></tr>
	<tr><th>Enforce strong passwords?</th><td>
		<select class="wfConfigElem" id="loginSec_strongPasswds" name="loginSec_strongPasswds">
			<option value="">Do not force users to use strong passwords</option>
			<option value="pubs"<?php $w->sel('loginSec_strongPasswds', 'pubs'); ?>>Force admins and publishers to use strong passwords (recommended)</option>
			<option value="all"<?php $w->sel('loginSec_strongPasswds', 'all'); ?>>Force all members to use strong passwords</option>
		</select>
	<tr><th>Lock out after how many login failures</th><td>
		<select id="loginSec_maxFailures" class="wfConfigElem" name="loginSec_maxFailures">
			<option value="1"<?php $w->sel('loginSec_maxFailures', '1'); ?>>1</option>
			<option value="2"<?php $w->sel('loginSec_maxFailures', '2'); ?>>2</option>
			<option value="3"<?php $w->sel('loginSec_maxFailures', '3'); ?>>3</option>
			<option value="4"<?php $w->sel('loginSec_maxFailures', '4'); ?>>4</option>
			<option value="5"<?php $w->sel('loginSec_maxFailures', '5'); ?>>5</option>
			<option value="6"<?php $w->sel('loginSec_maxFailures', '6'); ?>>6</option>
			<option value="7"<?php $w->sel('loginSec_maxFailures', '7'); ?>>7</option>
			<option value="8"<?php $w->sel('loginSec_maxFailures', '8'); ?>>8</option>
			<option value="9"<?php $w->sel('loginSec_maxFailures', '9'); ?>>9</option>
			<option value="10"<?php $w->sel('loginSec_maxFailures', '10'); ?>>10</option>
			<option value="20"<?php $w->sel('loginSec_maxFailures', '20'); ?>>20</option>
			<option value="30"<?php $w->sel('loginSec_maxFailures', '30'); ?>>30</option>
			<option value="40"<?php $w->sel('loginSec_maxFailures', '40'); ?>>40</option>
			<option value="50"<?php $w->sel('loginSec_maxFailures', '50'); ?>>50</option>
			<option value="100"<?php $w->sel('loginSec_maxFailures', '100'); ?>>100</option>
			<option value="200"<?php $w->sel('loginSec_maxFailures', '200'); ?>>200</option>
			<option value="500"<?php $w->sel('loginSec_maxFailures', '500'); ?>>500</option>
		</select>
		</td></tr>
	<tr><th>Lock out after how many forgot password attempts</th><td>
		<select id="loginSec_maxForgotPasswd" class="wfConfigElem" name="loginSec_maxForgotPasswd">
			<option value="1"<?php $w->sel('loginSec_maxForgotPasswd', '1'); ?>>1</option>
			<option value="2"<?php $w->sel('loginSec_maxForgotPasswd', '2'); ?>>2</option>
			<option value="3"<?php $w->sel('loginSec_maxForgotPasswd', '3'); ?>>3</option>
			<option value="4"<?php $w->sel('loginSec_maxForgotPasswd', '4'); ?>>4</option>
			<option value="5"<?php $w->sel('loginSec_maxForgotPasswd', '5'); ?>>5</option>
			<option value="6"<?php $w->sel('loginSec_maxForgotPasswd', '6'); ?>>6</option>
			<option value="7"<?php $w->sel('loginSec_maxForgotPasswd', '7'); ?>>7</option>
			<option value="8"<?php $w->sel('loginSec_maxForgotPasswd', '8'); ?>>8</option>
			<option value="9"<?php $w->sel('loginSec_maxForgotPasswd', '9'); ?>>9</option>
			<option value="10"<?php $w->sel('loginSec_maxForgotPasswd', '10'); ?>>10</option>
			<option value="20"<?php $w->sel('loginSec_maxForgotPasswd', '20'); ?>>20</option>
			<option value="30"<?php $w->sel('loginSec_maxForgotPasswd', '30'); ?>>30</option>
			<option value="40"<?php $w->sel('loginSec_maxForgotPasswd', '40'); ?>>40</option>
			<option value="50"<?php $w->sel('loginSec_maxForgotPasswd', '50'); ?>>50</option>
			<option value="100"<?php $w->sel('loginSec_maxForgotPasswd', '100'); ?>>100</option>
			<option value="200"<?php $w->sel('loginSec_maxForgotPasswd', '200'); ?>>200</option>
			<option value="500"<?php $w->sel('loginSec_maxForgotPasswd', '500'); ?>>500</option>
		</select>
		</td></tr>
	<tr><th>Count failures over what time period</th><td>
		<select id="loginSec_countFailMins" class="wfConfigElem" name="loginSec_countFailMins">
			<option value="5"<?php $w->sel('loginSec_countFailMins', '5'); ?>>5 minutes</option>
			<option value="10"<?php $w->sel('loginSec_countFailMins', '10'); ?>>10 minutes</option>
			<option value="30"<?php $w->sel('loginSec_countFailMins', '30'); ?>>30 minutes</option>
			<option value="60"<?php $w->sel('loginSec_countFailMins', '60'); ?>>1 hour</option>
			<option value="120"<?php $w->sel('loginSec_countFailMins', '120'); ?>>2 hours</option>
			<option value="360"<?php $w->sel('loginSec_countFailMins', '360'); ?>>6 hours</option>
			<option value="720"<?php $w->sel('loginSec_countFailMins', '720'); ?>>12 hours</option>
			<option value="1440"<?php $w->sel('loginSec_countFailMins', '1440'); ?>>1 day</option>
		</select>	
		</td></tr>
	<tr><th>Amount of time a user is locked out</th><td>
		<select id="loginSec_lockoutMins" class="wfConfigElem" name="loginSec_lockoutMins">
			<option value="5"<?php $w->sel('loginSec_lockoutMins', '5'); ?>>5 minutes</option>
			<option value="10"<?php $w->sel('loginSec_lockoutMins', '10'); ?>>10 minutes</option>
			<option value="30"<?php $w->sel('loginSec_lockoutMins', '30'); ?>>30 minutes</option>
			<option value="60"<?php $w->sel('loginSec_lockoutMins', '60'); ?>>1 hour</option>
			<option value="120"<?php $w->sel('loginSec_lockoutMins', '120'); ?>>2 hours</option>
			<option value="360"<?php $w->sel('loginSec_lockoutMins', '360'); ?>>6 hours</option>
			<option value="720"<?php $w->sel('loginSec_lockoutMins', '720'); ?>>12 hours</option>
			<option value="1440"<?php $w->sel('loginSec_lockoutMins', '1440'); ?>>1 day</option>
			<option value="2880"<?php $w->sel('loginSec_lockoutMins', '2880'); ?>>2 days</option>
			<option value="7200"<?php $w->sel('loginSec_lockoutMins', '7200'); ?>>5 days</option>
			<option value="14400"<?php $w->sel('loginSec_lockoutMins', '14400'); ?>>10 days</option>
			<option value="28800"<?php $w->sel('loginSec_lockoutMins', '28800'); ?>>20 days</option>
			<option value="43200"<?php $w->sel('loginSec_lockoutMins', '43200'); ?>>30 days</option>
			<option value="86400"<?php $w->sel('loginSec_lockoutMins', '86400'); ?>>60 days</option>
		</select>	
		</td></tr>
	<tr><th>Immediately lock out invalid usernames</th><td><input type="checkbox" id="loginSec_lockInvalidUsers" class="wfConfigElem" name="loginSec_lockInvalidUsers" <?php $w->cb('loginSec_lockInvalidUsers'); ?> /></td></tr>
	<tr><th>Don't let WordPress reveal valid users in login errors</th><td><input type="checkbox" id="loginSec_maskLoginErrors" class="wfConfigElem" name="loginSec_maskLoginErrors" <?php $w->cb('loginSec_maskLoginErrors'); ?> /></td></tr>
	<tr><th>Prevent users registering 'admin' username if it doesn't exist</th><td><input type="checkbox" id="loginSec_blockAdminReg" class="wfConfigElem" name="loginSec_blockAdminReg" <?php $w->cb('loginSec_blockAdminReg'); ?> /></td></tr>
	<tr><th>Prevent discovery of usernames through '?/author=N' scans</th><td><input type="checkbox" id="loginSec_disableAuthorScan" class="wfConfigElem" name="loginSec_disableAuthorScan" <?php $w->cb('loginSec_disableAuthorScan'); ?> /></td></tr>
	<tr><th>Immediately block the IP of users who try to sign in as these usernames</th><td><input type="text" name="loginSec_userBlacklist" id="loginSec_userBlacklist" value="<?php echo $w->getHTML('loginSec_userBlacklist'); ?>" size="40" />&nbsp;(Comma separated. Existing users won't be blocked.)</td></tr>
	<tr><td colspan="2">
		<div class="wfMarker" id="wfMarkerOtherOptions"></div>
		<h3 class="wfConfigHeading">Other Options</h3>
		</td></tr>
	<tr><th>Whitelisted IP addresses that bypass all rules:</th><td><input type="text" name="whitelisted" id="whitelisted" value="<?php echo $w->getHTML('whitelisted'); ?>" size="40" /></td></tr>
	<tr><th colspan="2" style="color: #999;">Whitelisted IP's must be separated by commas. You can specify ranges using the following format: 123.23.34.[1-50]<br />Wordfence automatically whitelists <a href="http://en.wikipedia.org/wiki/Private_network" target="_blank">private networks</a> because these are not routable on the public Internet.<br /><br /></th></tr>
	<tr><th>Hide WordPress version</th><td><input type="checkbox" id="other_hideWPVersion" class="wfConfigElem" name="other_hideWPVersion" value="1" <?php $w->cb('other_hideWPVersion'); ?> /></td></tr>
	<tr><th>Hold anonymous comments using member emails for moderation</th><td><input type="checkbox" id="other_noAnonMemberComments" class="wfConfigElem" name="other_noAnonMemberComments" value="1" <?php $w->cb('other_noAnonMemberComments'); ?> /></td></tr>
	<tr><th>Filter comments for malware and phishing URL's</th><td><input type="checkbox" id="other_scanComments" class="wfConfigElem" name="other_scanComments" value="1" <?php $w->cb('other_scanComments'); ?> /></td></tr>
	<tr><th>Check password strength on profile update</th><td><input type="checkbox" id="other_pwStrengthOnUpdate" class="wfConfigElem" name="other_pwStrengthOnUpdate" value="1" <?php $w->cb('other_pwStrengthOnUpdate'); ?> /></td></tr>
	<tr><th>Participate in the Real-Time WordPress Security Network</th><td><input type="checkbox" id="other_WFNet" class="wfConfigElem" name="other_WFNet" value="1" <?php $w->cb('other_WFNet'); ?> /></td></tr>
	<tr><th>Maximum memory Wordfence can use</th><td><input type="text" id="maxMem" name="maxMem" value="<?php $w->f('maxMem'); ?>" size="4" />Megabytes</td></tr>
	<tr><th>Maximum execution time for each scan stage</th><td><input type="text" id="maxExecutionTime" name="maxExecutionTime" value="<?php $w->f('maxExecutionTime'); ?>" size="4" />Blank for default. Must be greater than 9.</td></tr>
	<tr><th>Update interval in seconds (2 is default)</th><td><input type="text" id="actUpdateInterval" name="actUpdateInterval" value="<?php $w->f('actUpdateInterval'); ?>" size="4" />Setting higher will reduce browser traffic but slow scan starts, live traffic &amp; status updates.</td></tr>
	<tr><th>Enable debugging mode (increases database load)</th><td><input type="checkbox" id="debugOn" class="wfConfigElem" name="debugOn" value="1" <?php $w->cb('debugOn'); ?> /></td></tr>
	<tr><th>Delete Wordfence tables and data on deactivation?</th><td><input type="checkbox" id="deleteTablesOnDeact" class="wfConfigElem" name="deleteTablesOnDeact" value="1" <?php $w->cb('deleteTablesOnDeact'); ?> /></td></tr>
	<tr><th>Disable Wordfence Cookies</th><td><input type="checkbox" id="disableCookies" class="wfConfigElem" name="disableCookies" value="1" <?php $w->cb('disableCookies'); ?> />(when enabled all visits in live traffic will appear to be new visits)</td></tr>
	<tr><th>Start all scans remotely</th><td><input type="checkbox" id="startScansRemotely" class="wfConfigElem" name="startScansRemotely" value="1" <?php $w->cb('startScansRemotely'); ?> />(Try this if your scans aren't starting and your site is publicly accessible)</td></tr>
	<tr><th>Add a debugging comment to HTML source of cached pages.</th><td><input type="checkbox" id="addCacheComment" class="wfConfigElem" name="addCacheComment" value="1" <?php $w->cb('addCacheComment'); ?> /></td></tr>
	<tr><th colspan="2"><a href="<?php echo wfUtils::siteURLRelative(); ?>?_wfsf=conntest&nonce=<?php echo wp_create_nonce('wp-ajax'); ?>" target="_blank">Click to test connectivity to the Wordfence API servers</a></th></tr>
	<tr><th colspan="2"><a href="<?php echo wfUtils::siteURLRelative(); ?>?_wfsf=sysinfo&nonce=<?php echo wp_create_nonce('wp-ajax'); ?>" target="_blank">Click to view your system's configuration in a new window</a></th></tr>
	<tr><th colspan="2"><a href="<?php echo wfUtils::siteURLRelative(); ?>?_wfsf=testmem&nonce=<?php echo wp_create_nonce('wp-ajax'); ?>" target="_blank">Test your WordPress host's available memory</a></th></tr>
	</table>
	<p><table border="0" cellpadding="0" cellspacing="0"><tr><td><input type="button" id="button1" name="button1" class="button-primary" value="Save Changes" onclick="WFAD.saveConfig();" /></td><td style="height: 24px;"><div class="wfAjax24"></div><span class="wfSavedMsg">&nbsp;Your changes have been saved!</span></td></tr></table></p>
	</div>
	</form>
</div>
<script type="text/x-jquery-template" id="wfContentBasicOptions">
<div>
<h3>Basic Options</h3>
<p>
	Using Wordfence is simple. Install Wordfence, enter an email address on this page to send alerts to, and then do your first scan and work through the security alerts we provide.
	We give you a few basic security levels to choose from, depending on your needs. Remember to hit the "Save" button to save any changes you make. 
</p>
<p>
	If you use the free edition of Wordfence, you don't need to worry about entering an API key in the "API Key" field above. One is automatically created for you. If you choose to <a href="https://www.wordfence.com/wordfence-signup/" target="_blank">upgrade to Wordfence Premium edition</a>, you will receive an API key. You will need to copy and paste that key into the "API Key"
	field above and hit "Save" to activate your key.
</p>
</div>
</script>
<script type="text/x-jquery-template" id="wfContentLiveTrafficOptions">
<div>
<h3>Live Traffic Options</h3>
<p>
	These options let you ignore certain types of visitors, based on their level of access, usernames, IP address or browser type.
	If you run a very high traffic website where it is not feasible to see your visitors in real-time, simply un-check the live traffic option and nothing will be written to the Wordfence tracking tables.
</p>
</div>
</script>
<script type="text/x-jquery-template" id="wfContentScansToInclude">
<div>
<h3>Scans to Include</h3>
<p>
	This section gives you the ability to fine-tune what we scan. 
	If you use many themes or plugins from the public WordPress directory we recommend you 
	enable theme and plugin scanning. This will verify the integrity of all these themes and plugins and alert you of any changes.
<p>
<p>
	The option to "scan files outside your WordPress installation" will cause Wordfence to do a much wider security scan
	that is not limited to your base WordPress directory and known WordPress subdirectories. This scan may take longer
	but can be very useful if you have other infected files outside this WordPress installation that you would like us to look for.
</p>
</div>
</script>
<script type="text/x-jquery-template" id="wfContentFirewallRules">
<div>
<h3>Firewall Rules</h3>
<p>
	<strong>NOTE:</strong> Before modifying these rules, make sure you have access to the email address associated with this site's administrator account. If you accidentally lock yourself out, you will be given the option
	to enter that email address and receive an "unlock email" which will allow you to regain access.
</p>
<p>
	<strong>Tips:</strong>
	<p>&#8226; If you choose to limit the rate at which your site can be accessed, you need to customize the settings for your site.</p>
	<p>&#8226; If your users usually skip quickly between pages, you should set the values for human visitors to be high.</p>
	<p>&#8226; If you are aggressively crawled by non-Google crawlers like Baidu, you should set the page view limit for crawlers to a high value.</p>
	<p>&#8226; If you are currently under attack and want to aggressively protect your site or your content, you can set low values for most options.</p>
	<p>&#8226; In general we recommend you don't block fake Google crawlers unless you have a specific problem with someone stealing your content.</p>
</p>
<p>
	Remember that as long as you have your administrator email set correctly in this site's user administration, and you are able to receive email at that address,
	you will be able to regain access if you are accidentally locked out because your rules are too strict.
</p>
</div>
</script>
<script type="text/x-jquery-template" id="wfContentLoginSecurity">
<div>
<h3>Login Security</h3>
<p>
	We have found that real brute force login attacks make hundreds or thousands of requests trying to guess passwords or user login names. 
	So in general you can leave the number of failed logins before a user is locked out as a fairly high number.
	We have found that blocking after 20 failed attempts is sufficient for most sites and it allows your real site users enough
	attempts to guess their forgotten passwords without getting locked out.
</p>
</div>
</script>
<script type="text/x-jquery-template" id="wfContentOtherOptions">
<div>
<h3>Other Options</h3>
<p>
	We have worked hard to make Wordfence memory efficient and much of the heavy lifting is done for your site by our cloud scanning servers in our Seattle data center.
	On most sites Wordfence will only use about 8 megabytes of additional memory when doing a scan, even if you have large files or a large number of files.
	You should not have to adjust the maximum memory that Wordfence can use, but we have provided the option. Remember that this does not affect the actual memory usage of Wordfence, simply the maximum Wordfence can use if it needs to.
</p>
<p>
	You may find debugging mode helpful if Wordfence is not able to start a scan on your site or
	if you are experiencing some other problem. Enable debugging by checking the box, save your options
	and then try to do a scan. You will notice a lot more output on the "Scan" page.
</p>
<p>
	If you decide to permanently remove Wordfence, you can choose the option to delete all data on deactivation.
	We also provide helpful links at the bottom of this page which lets you see your systems configuration and test how
	much memory your host really allows you to use.
</p>
<p>
	Thanks for completing this tour and I'm very happy to have you as our newest Wordfence customer. Don't forget to <a href="http://wordpress.org/extend/plugins/wordfence/" target="_blank">rate us 5 stars if you love Wordfence</a>.<br />
	<br />
	<strong>Mark Maunder</strong> - Wordfence Creator.
</p>
</div>
</script>

