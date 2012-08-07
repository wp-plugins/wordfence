<div class="wordfenceModeElem" id="wordfenceMode_countryBlocking"></div>
<div class="wrap" id="paidWrap">
	<div class="wordfence-lock-icon wordfence-icon32"><br /></div><h2>Block specific countries from accessing your site</h2>
	<div class="wordfenceWrap" style="margin: 20px 20px 20px 30px;">
		<table class="wfConfigForm">
		<tr><td colspan="2"><h2>Country Blocking Options</h2></td></tr>
		<tr><th>What to do when we block someone:</th><td>
			<select id="wfBlockAction">
				<option value="block"<?php if(wfConfig::get('cbl_action') == 'block'){ echo ' selected'; } ?>>Show the standard Wordfence blocked message</option>
				<option value="redir"<?php if(wfConfig::get('cbl_action') == 'redir'){ echo ' selected'; } ?>>Redirect to the URL below</option>
			</select>
			</td></tr>
		<tr><th>URL to redirect blocked users to:</th><td><input type="text" id="wfRedirURL" value="<?php if(wfConfig::get('cbl_redirURL')){ echo htmlspecialchars(wfConfig::get('cbl_redirURL')); } ?>" /></td></tr>
		<tr><th>Block countries even if they are logged in:</th><td><input type="checkbox" id="wfLoggedInBlocked" value="1" <?php if(wfConfig::get('cbl_loggedInBlocked')){ echo 'checked'; } ?> /></td></tr>
		<tr><th>Block access to the login form too:</th><td><input type="checkbox" id="wfLoginFormBlocked" value="1" <?php if(wfConfig::get('cbl_loginFormBlocked')){ echo 'checked'; } ?> /></td></tr>
		<tr><td colspan="2" style="padding-top: 10px;" >
			<h2>Select which countries to block</h2>
			</td></tr>
		<tr><th>Select individual countries to block and hit "Add":</th><td><select name="country" id="wfBlockedCountry">
			<?php require('wfCountrySelect.php'); ?>
			</select><input type="button" name="but3" class="button-primary" value="Add Country" onclick="var cVal = jQuery('#wfBlockedCountry').val(); WFAD.addBlockedCountry(cVal, jQuery('#wfBlockedCountry option[value=\'' + cVal + '\']').text());" /></td></tr>
		<tr><td colspan="2">
<div id="wfCountryList" style="width: 350px; height: 200px; border: 1px solid #999; padding: 5px; margin: 5px;">
</div>
<b>Changes to the country list will only take effect once you hit the save button below.</b>
			</td></tr>
		<tr><td colspan="2">
			<table border="0" cellpadding="0" cellspacing="0"><tr>
				<td><input type="button" name="but4" class="button-primary" value="Save blocking options and country list" onclick="WFAD.saveCountryBlocking();" /></td>
				<td style="height: 24px;"><div class="wfAjax24"></div><span class="wfSavedMsg">&nbsp;Your changes have been saved!</span></td></tr></table>
		</td></tr>
		</table>
		<span style="font-size: 10px;">Note that we use an IP to country database that is 99.5% accurate to identify which country a visitor is from.</span>
	</div>
</div>
<script type="text/javascript">
WFAD.setOwnCountry('<?php echo wfUtils::IP2Country(wfUtils::getIP()); ?>');
<?php
if(wfConfig::get('cbl_countries')){
?>
WFAD.loadBlockedCountries('<?php echo wfConfig::get('cbl_countries'); ?>');
<?php
}
?>
<?php
if(! wfConfig::get('isPaid')){
	echo 'WFAD.paidUsersOnly("Country blocking is only available to paid members because we have licensed a commercial geolocation database to provide this feature.");';
}
?>
</script>

