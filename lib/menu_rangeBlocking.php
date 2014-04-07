<div class="wordfenceModeElem" id="wordfenceMode_rangeBlocking"></div>
<div class="wrap" id="paidWrap">
	<?php require('menuHeader.php'); ?>
	<?php $pageTitle = "Advanced Blocking"; include('pageTitle.php'); ?>
	<div class="wordfenceWrap" style="margin: 20px 20px 20px 30px;">
		<p>
			<div style="width: 600px; margin-bottom: 15px;">
			<?php if(! wfConfig::get('firewallEnabled')){ ?><div style="color: #F00; font-weight: bold;">Firewall is disabled. You can enable it on the <a href="admin.php?page=WordfenceSecOpt">Wordfence Options page</a> at the top.</div><br /><?php } ?>
			This page lets you block visitors who are from a range of IP addresses or are using a certain web browser or browser pattern. 
			You can also block a certain web browser that is visiting your site from a certain range of IP addresses. This can be useful when
			blocking someone pretending to be Google and using a specific Internet Service Provider or Web Host.<br /><br /> 
			<ul style="list-style-type:circle;">
				<li>To block a range of IP addresses, enter the range and leave the User-Agent field blank.</li>
				<li>To block a certain kind of web browser, enter the browser or browser pattern in the User-Agent field and leave the IP range blank</li>
				<li>To block a certain kind of web browser that is accessing your site from a certain range of IP addresses, enter both the IP address range and the pattern to use to match the web browser</li>
			</ul>
			</div>
			<table class="wfConfigForm">
				<tr><th>Block anyone that has an IP address in this range:</th><td><input id="ipRange" type="text" size="30" maxlength="255" value="<?php if( isset( $_GET['wfBlockRange'] ) && $_GET['wfBlockRange']){ echo $_GET['wfBlockRange']; } ?>" onkeyup="WFAD.calcRangeTotal();">&nbsp;<span id="wfShowRangeTotal"></span></td></tr>
				<tr><td></td><td style="padding-bottom: 15px;"><strong>Examples:</strong> 192.168.200.200 - 192.168.200.220</td></tr>
				<tr><th>...you can also enter a User-Agent (browser) that matches:</th><td><input id="uaRange" type="text" size="30" maxlength="255" >&nbsp;(Case insensitive)</td></tr>
				<tr><td></td><td style="padding-bottom: 15px;"><strong>Examples:</strong> *badRobot*, AnotherBadRobot*, *someKindOfSuffix</td></tr>
				<tr><th>Enter a reason you're blocking this visitor pattern:</th><td><input id="wfReason" type="text" size="30" maxlength="255"></td></tr>
				<tr><td></td><td style="padding-bottom: 15px;"><strong>Why a reason:</strong> The reason you specify above is for your own record keeping.</td></tr>
				<tr><td colspan="2" style="padding-top: 15px;">
					<input type="button" name="but3" class="button-primary" value="Block Visitors Matching this Pattern" onclick="WFAD.blockIPUARange(jQuery('#ipRange').val(), jQuery('#uaRange').val(), jQuery('#wfReason').val()); return false;" />
				</td></tr>
			</table>
		</p>
		<p>
			<h2>Current list of ranges and patterns you've blocked</h2>
			<div id="currentBlocks"></div>
		</p>
	</div>
</div>
<script type="text/x-jquery-template" id="wfBlockedRangesTmpl">
<div>
<div style="border-bottom: 1px solid #CCC; padding-bottom: 10px; margin-bottom: 10px;">
<table border="0" style="width: 100%">
{{each(idx, elem) results}}
<tr><td>
	{{if patternDisabled}}
	<div style="width: 500px; margin-top: 20px;">
		<span style="color: #F00;">Pattern Below has been DISABLED:</span> Falcon engine does not support advanced blocks that include BOTH an IP address range AND a browser pattern.
	</div>
	<div style="color: #AAA;">
	{{/if}}
	<div>
		<strong>IP Range:</strong>&nbsp;${ipPattern}
	</div>
	<div>
		<strong>Browser Pattern:</strong>&nbsp;${browserPattern}
	</div>
	<div>
		<strong>Reason:</strong>&nbsp;${reason}
	</div>
	<div><a href="#" onclick="WFAD.unblockRange('${id}'); return false;">Delete this blocking pattern</a></div>
	{{if patternDisabled}}
	</div>
	{{/if}}
</td>
<td style="color: #999;">
	<ul>
	<li>${totalBlocked} blocked hits</li>
	{{if lastBlockedAgo}}
	<li>Last blocked: ${lastBlockedAgo} ago</li>
	{{/if}}
	</ul>
</td></tr>
{{/each}}
</table>
</div>
</div>
</script>
<script type="text/x-jquery-template" id="wfWelcomeContentRangeBlocking">
<div>
<h3>Block Networks &amp; Browsers</h3>
<strong><p>Easily block advanced attacks</p></strong>
<p>
	Advanced Blocking is a new feature in Wordfence that lets you block whole networks and certain types of web browsers.
	You'll sometimes find a smart attacker will change their IP address frequently to make it harder to identify and block
	the attack. Usually those attackers stick to a certain network or IP address range. 
	Wordfence lets you block entire networks using Advanced blocking to easily defeat advanced attacks.
</p>
<p>
	You may also find an attacker that is identifying themselves as a certain kind of web browser that your 
	normal visitors don't use. You can use our User-Agent or Browser ID blocking feature to easily block
	attacks like this.
</p>
<p>
	You can also block any combination of network address range and User-Agent by specifying both in Wordfence Advanced Blocking.
	As always we keep track of how many attacks have been blocked and when the last attack occured so that you know
	when it's safe to remove the blocking rule. 
</p>
</div>
</script>
