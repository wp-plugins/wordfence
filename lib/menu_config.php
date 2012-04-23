<div class="wrap wordfence">
	<div class="wordfence-lock-icon wordfence-icon32"><br /></div><h2>Welcome to Wordfence</h2>
	<table class="form-table">
	<tr><th><nobr>Enter your Wordfence API key:</nobr></th><td><input type="text" id="wordfenceKey" size="30" value="" />&nbsp;(<a href="http://wordfence.com/signup-step2/" target="_blank">click here to get a free API key</a>)</td></tr>
	<tr><td colspan="2">
		<table border="0" cellpadding="0" cellspacing="0"><tr><td>
			<input type="button" name="submit" id="submit" class="button-primary" value="Save Changes and Activate Wordfence" onclick="wordfenceAdmin.activateWF(jQuery('#wordfenceKey').val()); return false;" />
		</td><td>
			<div class="wfAjax24"></div>
		</td></tr></table>

	</td></tr>
	</table>
		
</div>
<script type="text/x-jquery-template" id="wfActivateError">
<div>
<h3>Wordfence Activation Failed</h3>
<p>
	We could not activate your Wordfence. The error was:
	<br /><br />
	${err}
	<br /><br />
</p>
</div>
</script>
