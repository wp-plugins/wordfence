<?php 
$w = new wfConfig(); 
?>
<script type="text/javascript">
var WFSLevels = <?php echo json_encode(wfConfig::$securityLevels); ?>;
</script>
<div class="wordfenceModeElem" id="wordfenceMode_options"></div>
<div class="wrap">
	<div class="wordfence-lock-icon wordfence-icon32"><br /></div><h2>Wordfence Options</h2>
	<div class="wordfenceLive">
		<table border="0" cellpadding="0" cellspacing="0">
		<tr><td><h2>Wordfence Live Activity:</h2></td><td id="wfLiveStatus"></td></tr>
		</table>
	</div>

	<form id="wfConfigForm">
	<table class="wfConfigForm">
	<tr><td colspan="2"><h2>Alerts</h2></td></tr>
	<tr><th>List of emails to alert, separated by commas</th><td><input type="text" id="alertEmails" name="alertEmails" value="<?php $w->f('alertEmails'); ?>" size="50" /></td></tr>
	<tr><td colspan="2"><h2>Security Level</h2></td></tr>
	<tr><td colspan="2">
		<select id="securityLevel" name="securityLevel" onchange="WFAD.changeSecurityLevel(); return true;">
			<option value="0"<?php $w->sel('securityLevel', '0'); ?>>Level 0: Disable all Wordfence security measures</option>
			<option value="1"<?php $w->sel('securityLevel', '1'); ?>>Level 1: Light protection. Just the basics</option>
			<option value="2"<?php $w->sel('securityLevel', '2'); ?>>Level 2: Medium protection. Suitable for most sites</option>
			<option value="3"<?php $w->sel('securityLevel', '3'); ?>>Level 3: High security. Use this when an attack is imminent</option>
			<option value="4"<?php $w->sel('securityLevel', '4'); ?>>Level 4: Lockdown. Protect the site against an attack in progress at the cost of inconveniencing some users</option>
			<option value="CUSTOM"<?php $w->sel('securityLevel', 'CUSTOM'); ?>>Custom settings</option>
		</select>
		</td></tr>

	</table>
	<p><table border="0" cellpadding="0" cellspacing="0"><tr><td><input type="button" id="button1" name="button1" class="button-primary" value="Save Changes" onclick="WFAD.saveConfig();" /></td><td style="height: 24px;"><div class="wfAjax24"></div><span class="wfSavedMsg">&nbsp;Your changes have been saved!</span></td></tr></table></p>
	<div>
		<p style="width: 600px;">Wordfence works great out of the box for most websites. Simply install Wordfence and your site and content is protected. For finer granularity of control, we have provided advanced options.</p>
		<a href="#" onclick="jQuery('#wfConfigAdvanced').fadeToggle();">Show or hide advanced options that let you create a custom security profile</a>
	</div>
	<div id="wfConfigAdvanced" style="display: none;">
	<table class="wfConfigForm">
	<tr><td colspan="2"><h2>Alerts</h2></td></tr>
	<tr><th>Alert on critical problems</th><td><input type="checkbox" id="alertOn_critical" class="wfConfigElem" name="alertOn_critical" value="1" <?php $w->cb('alertOn_critical'); ?>/></td></tr>
	<tr><th>Alert on warnings</th><td><input type="checkbox" id="alertOn_warnings" class="wfConfigElem" name="alertOn_warnings" value="1" <?php $w->cb('alertOn_warnings'); ?>/></td></tr>
	<tr><th>Alert when an IP address is blocked</th><td><input type="checkbox" id="alertOn_block" class="wfConfigElem" name="alertOn_block" value="1" <?php $w->cb('alertOn_block'); ?>/></td></tr>
	<tr><th>Alert when someone is locked out from login</th><td><input type="checkbox" id="alertOn_loginLockout" class="wfConfigElem" name="alertOn_loginLockout" value="1" <?php $w->cb('alertOn_loginLockout'); ?>/></td></tr>
	<tr><th>Alert when the "lost password" form is used for a valid user</th><td><input type="checkbox" id="alertOn_lostPasswdForm" class="wfConfigElem" name="alertOn_lostPasswdForm" value="1" <?php $w->cb('alertOn_lostPasswdForm'); ?>/></td></tr>
	<tr><th>Alert me when someone with administrator access signs in</th><td><input type="checkbox" id="alertOn_adminLogin" class="wfConfigElem" name="alertOn_adminLogin" value="1" <?php $w->cb('alertOn_adminLogin'); ?>/></td></tr>
	<tr><th>Alert me when a non-admin user signs in</th><td><input type="checkbox" id="alertOn_nonAdminLogin" class="wfConfigElem" name="alertOn_nonAdminLogin" value="1" <?php $w->cb('alertOn_nonAdminLogin'); ?>/></td></tr>
	<tr><td colspan="2"><h2>Live Traffic View</h2></td></tr>
	<tr><th class="wfConfigEnable">Enable Live Traffic View</th><td><input type="checkbox" id="liveTrafficEnabled" class="wfConfigElem" name="liveTrafficEnabled" value="1" <?php $w->cb('liveTrafficEnabled'); ?> onclick="WFAD.reloadConfigPage = true; return true;" /></td></tr>
	<tr><th>Don't log signed-in users with publishing access:</th><td><input type="checkbox" id="liveTraf_ignorePublishers" name="liveTraf_ignorePublishers" value="1" <?php $w->cb('liveTraf_ignorePublishers'); ?> /></td></tr>
	<tr><th>List of comma separated usernames to ignore:</th><td><input type="text" name="liveTraf_ignoreUsers" id="liveTraf_ignoreUsers" value="<?php echo $w->getHTML('liveTraf_ignoreUsers'); ?>" /></td></tr>
	<tr><th>List of comma separated IP addresses to ignore:</th><td><input type="text" name="liveTraf_ignoreIPs" id="liveTraf_ignoreIPs" value="<?php echo $w->getHTML('liveTraf_ignoreIPs'); ?>" /></td></tr>
	<tr><th>Browser user-agent to ignore:</th><td><input type="text" name="liveTraf_ignoreUA" id="liveTraf_ignoreUA" value="<?php echo $w->getHTML('liveTraf_ignoreUA'); ?>" /></td></tr>
	<tr><th>Limit size of hits table to</th><td><input type="text" name="liveTraf_hitsMaxSize" class="wfConfigElem" name="liveTraf_hitsMaxSize" value="<?php $w->f('liveTraf_hitsMaxSize'); ?>" size="6" />Megabytes</td></tr>
	<tr><td colspan="2"><h2>Scans to include</h2></td></tr>
	<tr><th class="wfConfigEnable">Enable automatic scheduled scans</th><td><input type="checkbox" id="scheduledScansEnabled" class="wfConfigElem" name="scheduledScansEnabled" value="1" <?php $w->cb('scheduledScansEnabled'); ?> /></td></tr>
	<tr><th>Scan core files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_core" class="wfConfigElem" name="scansEnabled_core" value="1" <?php $w->cb('scansEnabled_core'); ?>/></td></tr>
	
	<?php if(wfConfig::get('isPaid') == 'paid'){ ?>
	<tr><th>Scan theme files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_themes" class="wfConfigElem" name="scansEnabled_themes" value="1" <?php $w->cb('scansEnabled_themes'); ?>/></td></tr>
	<tr><th>Scan plugin files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_plugins" class="wfConfigElem" name="scansEnabled_plugins" value="1" <?php $w->cb('scansEnabled_plugins'); ?>/></td></tr>
	<?php } else { ?>
	<tr><th style="color: #F00; padding-top: 10px;">Only available to Premium Members:</th><td></td></tr>
	<tr><th style="color: #999;">Scan theme files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_themes" class="wfConfigElem" name="scansEnabled_themes" value="1" DISABLED /></td></tr>
	<tr><th style="color: #999;">Scan plugin files against repository versions for changes</th><td><input type="checkbox" id="scansEnabled_plugins" class="wfConfigElem" name="scansEnabled_plugins" value="1" DISABLED /></td></tr>
	<tr><td colspan="2">&nbsp;</td></tr>
	<?php } ?>
	<tr><th>Scan for signatures of known malicious files</th><td><input type="checkbox" id="scansEnabled_malware" class="wfConfigElem" name="scansEnabled_malware" value="1" <?php $w->cb('scansEnabled_malware'); ?>/></td></tr>
	<tr><th>Scan file contents for backdoors, trojans and suspicious code</th><td><input type="checkbox" id="scansEnabled_fileContents" class="wfConfigElem" name="scansEnabled_fileContents" value="1" <?php $w->cb('scansEnabled_fileContents'); ?>/></td></tr>
	<tr><th>Scan posts for known dangerous URLs and suspicious content</th><td><input type="checkbox" id="scansEnabled_posts" class="wfConfigElem" name="scansEnabled_posts" value="1" <?php $w->cb('scansEnabled_posts'); ?>/></td></tr>
	<tr><th>Scan comments for known dangerous URLs and suspicious content</th><td><input type="checkbox" id="scansEnabled_comments" class="wfConfigElem" name="scansEnabled_comments" value="1" <?php $w->cb('scansEnabled_comments'); ?>/></td></tr>
	<tr><th>Scan for out of date plugins, themes and WordPress versions</th><td><input type="checkbox" id="scansEnabled_oldVersions" class="wfConfigElem" name="scansEnabled_oldVersions" value="1" <?php $w->cb('scansEnabled_oldVersions'); ?>/></td></tr>
	<tr><th>Check the strength of passwords</th><td><input type="checkbox" id="scansEnabled_passwds" class="wfConfigElem" name="scansEnabled_passwds" value="1" <?php $w->cb('scansEnabled_passwds'); ?>/></td></tr>
	<tr><th>Monitor disk space</th><td><input type="checkbox" id="scansEnabled_diskSpace" class="wfConfigElem" name="scansEnabled_diskSpace" value="1" <?php $w->cb('scansEnabled_diskSpace'); ?>/></td></tr>
	<tr><th>Scan for unauthorized DNS changes</th><td><input type="checkbox" id="scansEnabled_dns" class="wfConfigElem" name="scansEnabled_dns" value="1" <?php $w->cb('scansEnabled_dns'); ?>/></td></tr>
	<tr><td colspan="2">
		<h2>Firewall Rules</h2>
	</td></tr>

	<tr><th class="wfConfigEnable">Enable firewall rules</th><td><input type="checkbox" id="firewallEnabled" class="wfConfigElem" name="firewallEnabled" value="1" <?php $w->cb('firewallEnabled'); ?> /></td></tr>
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

	<tr><td colspan="2"><h2>Login Security Options</h2></td></tr>
	<tr><th class="wfConfigEnable">Enable login security</th><td><input type="checkbox" id="loginSecurityEnabled" class="wfConfigElem" name="loginSecurityEnabled" value="1" <?php $w->cb('loginSecurityEnabled'); ?> /></td></tr>
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
		</select>	
		</td></tr>
	<tr><th>Immediately lock out invalid usernames</th><td><input type="checkbox" id="loginSec_lockInvalidUsers" class="wfConfigElem" name="loginSec_lockInvalidUsers" <?php $w->cb('loginSec_lockInvalidUsers'); ?> /></td></tr>
	<tr><th>Don't let WordPress reveal valid users in login errors</th><td><input type="checkbox" id="loginSec_maskLoginErrors" class="wfConfigElem" name="loginSec_maskLoginErrors" <?php $w->cb('loginSec_maskLoginErrors'); ?> /></td></tr>
	<tr><td colspan="2"><h2>Other Options</h2></td></tr>
	<tr><th>Hide WordPress version</th><td><input type="checkbox" id="other_hideWPVersion" class="wfConfigElem" name="other_hideWPVersion" value="1" <?php $w->cb('other_hideWPVersion'); ?> /></td></tr>
	<tr><th>Hold anonymous comments using member emails for moderation</th><td><input type="checkbox" id="other_noAnonMemberComments" class="wfConfigElem" name="other_noAnonMemberComments" value="1" <?php $w->cb('other_noAnonMemberComments'); ?> /></td></tr>
	<tr><th>Scan comments for malware and phishing URL's</th><td><input type="checkbox" id="other_scanComments" class="wfConfigElem" name="other_scanComments" value="1" <?php $w->cb('other_scanComments'); ?> /></td></tr>
	<tr><th>Check password strength on profile update</th><td><input type="checkbox" id="other_pwStrengthOnUpdate" class="wfConfigElem" name="other_pwStrengthOnUpdate" value="1" <?php $w->cb('other_pwStrengthOnUpdate'); ?> /></td></tr>
	<tr><th>Participate in the Wordfence Security Network</th><td><input type="checkbox" id="other_WFNet" class="wfConfigElem" name="other_WFNet" value="1" <?php $w->cb('other_WFNet'); ?> /></td></tr>
	<tr><th>Your Wordfence API Key</th><td><input type="text" id="apiKey" name="apiKey" value="<?php $w->f('apiKey'); ?>" size="20" /></td></tr>
	<tr><th colspan="2"><a href="/?_wfsf=sysinfo&nonce=<?php echo wp_create_nonce('wp-ajax'); ?>" target="_blank">Click to view your system's configuration in a new window</a></th></tr>
	</table>
	<p><table border="0" cellpadding="0" cellspacing="0"><tr><td><input type="button" id="button1" name="button1" class="button-primary" value="Save Changes" onclick="WFAD.saveConfig();" /></td><td style="height: 24px;"><div class="wfAjax24"></div><span class="wfSavedMsg">&nbsp;Your changes have been saved!</span></td></tr></table></p>
	</div>
	</form>
</div>
