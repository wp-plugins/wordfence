<?php if(! wfConfig::get('isPaid')){ ?> 
<table border="0">
<tr>
	<td style="padding-right: 50px;">
		<div class="wordfence-lock-icon wordfence-icon32"><br /></div><h2 id="wfHeading"><?php echo $pageTitle; ?></h2>
	</td><td style="width: 450px; padding-top: 10px;">
		You're using the Free version of Wordfence which you can support by visiting <a href="http://www.bluehost.com/track/wordfence/wfplghead" target="_blank">Bluehost.com</a>. We recommend <a href="http://www.bluehost.com/track/wordfence/wfplghead" target="_blank">Bluehost for WordPress hosting</a> and use them for our own WordPress websites. &nbsp;&nbsp;&nbsp;<a href="http://www.bluehost.com/track/wordfence/wfplghead" target="_blank">&raquo;Visit Bluehost now&raquo;</a>
	</td>
	<td style="width: 120px; padding-top: 10px;">
	<a href="http://www.bluehost.com/track/wordfence/wfplghead" target="_blank" class="bluehostBanner bluehostBanner<?php echo rand(1,5); ?>"></a>
	</td>
</tr>
</table>
<?php } else { ?>
<div class="wordfence-lock-icon wordfence-icon32"><br /></div><h2 id="wfHeading"><?php echo $pageTitle; ?></h2>
<?php } ?>
