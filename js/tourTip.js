function wfClearEmailField(){
	if(jQuery('#wfListEmail').val() == "Enter your email"){
		jQuery('#wfListEmail').val('');
	}
}

jQuery(function(){
if(WordfenceAdminVars.tourClosed != '1'){
	var formHTML = '<div style="padding: 0 5px 0 15px;"><form target="_new" style="display: inline;" method="post" class="af-form-wrapper" action="http://www.aweber.com/scripts/addlead.pl"  ><div style="display: none;"><input type="hidden" name="meta_web_form_id" value="1428034071" /><input type="hidden" name="meta_split_id" value="" /><input type="hidden" name="listname" value="wordfence" /><input type="hidden" name="redirect" value="http://www.aweber.com/thankyou-coi.htm?m=text" id="redirect_ae9f0882518768f447c80ea8f3b7afde" /><input type="hidden" name="meta_adtracking" value="widgetForm" /><input type="hidden" name="meta_message" value="1" /><input type="hidden" name="meta_required" value="email" /><input type="hidden" name="meta_tooltip" value="" /></div><input class="text" id="wfListEmail" type="text" name="email" value="Enter your email" tabindex="500" onclick="wfClearEmailField(); return false;" /><input name="submit" type="submit" value="Get Alerts" tabindex="501" /><div style="display: none;"><img src="http://forms.aweber.com/form/displays.htm?id=jCxMHAzMLAzsjA==" alt="" /></div></form></div>';

	jQuery('#toplevel_page_Wordfence').pointer({
		close: function(){},
		content: "<h3>Congratulations!</h3><p>You've just installed Wordfence! Start by joining our mailing list to get WordPress security alerts and Wordfence news:</p>" +
			formHTML +
			"<p>Then click \"Start Tour\" to get a quick introduction to how Wordfence protects your site, keeps you off Google's SEO black-list and can even help clean a hacked site.</p>",
		pointerWidth: 300,
		position: { edge: 'top', align: 'left' },
		buttons: function(event, t){
			buttonElem = jQuery('<a id="pointer-close" style="margin-left:5px" class="button-secondary">Close</a>');
			buttonElem.bind('click.pointer', function(){ t.element.pointer('close'); 
				var ajaxData = {
					action: 'wordfence_tourClosed',
					nonce: WordfenceAdminVars.firstNonce
					};
				jQuery.ajax({
					type: 'POST',
					url: WordfenceAdminVars.ajaxURL,
					dataType: "json",
					data: ajaxData,
					success: function(json){},
					error: function(){}
					});
				});
			return buttonElem;
			}
			}).pointer('open');
	jQuery('#pointer-close').after('<a id="pointer-primary" class="button-primary">Start Tour</a>');
	jQuery('#pointer-primary').click(function(){ window.location.href = 'admin.php?page=Wordfence'; });
}
});
