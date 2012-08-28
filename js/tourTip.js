jQuery(function(){
if(WordfenceAdminVars.tourClosed != '1'){
	jQuery('#toplevel_page_Wordfence').pointer({
		close: function(){},
		content: "<h3>Congratulations!</h3><p>You've just installed Wordfence! Click \"Start Tour\" to get a quick introduction to how Wordfence protects your site, keeps you off Google's SEO black-list and can even help clean a hacked site.</p>",
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
