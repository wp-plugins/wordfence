if(! window['wordfenceAdmin']){
window['wordfenceAdmin'] = {
	loading16: '<div class="wfLoading16"></div>',
	dbCheckTables: [],
	dbCheckCount_ok: 0,
	dbCheckCount_skipped: 0,
	dbCheckCount_errors: 0,
	issues: [],
	ignoreData: false,
	iconErrorMsgs: [],
	scanIDLoaded: 0,
	colorboxQueue: [],
	colorboxOpen: false,
	scanPending: false,
	mode: '',
	visibleIssuesPanel: 'new',
	preFirstScanMsgsLoaded: false,
	newestActivityTime: 0, //must be 0 to force loading of all initially
	elementGeneratorIter: 1,
	reloadConfigPage: false,
	nonce: false,
	init: function(){
		this.nonce = WordfenceAdminVars.firstNonce; 
		if(jQuery('#wordfenceMode_scan').length > 0){
			this.mode = 'scan';
			this.noScanHTML = jQuery('#wfNoScanYetTmpl').tmpl().html();
		} else if(jQuery('#wordfenceMode_activity').length > 0){
			this.mode = 'activity';
			this.activityMode = 'hit';
			this.updateTicker(true);
		} else if(jQuery('#wordfenceMode_options').length > 0){
			this.mode = 'options';
			jQuery('.wfConfigElem').change(function(){ jQuery('#securityLevel').val('CUSTOM'); });
			this.updateTicker(true);
		} else if(jQuery('#wordfenceMode_blockedIPs').length > 0){
			this.mode = 'blocked';
			this.staticTabChanged();
			this.updateTicker(true);
		} else {
			this.mode = false;
		}
		if(this.mode){ //We are in a Wordfence page
			var self = this;
			this.liveInt = setInterval(function(){ self.updateTicker(); }, 2000);
			jQuery(document).bind('cbox_closed', function(){ self.colorboxIsOpen = false; self.colorboxServiceQueue(); });
		}

	},
	updateTicker: function(forceUpdate){
		if( (! forceUpdate) && this.tickerUpdatePending){
			return;
		}
		this.tickerUpdatePending = true;
		var self = this;
		var alsoGet = '';
		var otherParams = '';
		if(this.mode == 'activity' && /^(?:404|hit|human|ruser|gCrawler|crawler|loginLogout)$/.test(this.activityMode)){
			alsoGet = 'logList_' + this.activityMode;
			otherParams = this.newestActivityTime;
		}
		this.ajax('wordfence_ticker', { 
			alsoGet: alsoGet,
			otherParams: otherParams
			}, function(res){ self.handleTickerReturn(res); }, function(){ self.tickerUpdatePending = false; });
	},
	handleTickerReturn: function(res){
		this.tickerUpdatePending = false;
		var statusMsgChanged = false;
		var newMsg = "";
		var oldMsg = jQuery('#wfLiveStatus').html();
		if( res.msg ){ 
			newMsg = res.msg;
		} else {
			newMsg = "Idle";
		}
		if(newMsg && oldMsg && newMsg != oldMsg){
			statusMsgChanged = true;
		}
		if(newMsg && newMsg != oldMsg){
			jQuery('#wfLiveStatus').hide().html(newMsg).fadeIn(200);
		}

		if(this.mode == 'scan'){
			if(res.running){
				jQuery('.wfStartScanButton').addClass('button-wf-grey').val("A scan is in progress...").unbind('click').click(function(){ wordfenceAdmin.scanRunningMsg(); }).show();
			} else {
				if(! this.scanPending){
					jQuery('.wfStartScanButton').removeClass('button-wf-grey').val("Start a Wordfence Scan").unbind('click').click(function(){ wordfenceAdmin.startScan(); }).show();
				}
			}
			if(res.currentScanID && res.currentScanID != this.scanIDLoaded){
				this.scanIDLoaded = res.currentScanID;
				this.loadIssues();
			} else if( (! res.currentScanID) && (! this.scanIDLoaded)){
				//We haven't done our first scan yet. 
				if(! this.preFirstScanMsgsLoaded){
					this.preFirstScanMsgsLoaded = true;
					jQuery('#wfSummaryTables').html(this.noScanHTML);
					this.switchIssuesTab(jQuery('#wfNewIssuesTab'), 'new');
					jQuery('#wfActivity').html('<p>No events to report yet. Please complete your first scan.</p>');
				}
			}
		} else if(this.mode == 'activity'){
			if(res.alsoGet != 'logList_' + this.activityMode){ return; } //user switched panels since ajax request started
			if(/^(?:topScanners|topLeechers)$/.test(this.activityMode)){
				if(statusMsgChanged){ this.updateTicker(true); } return;
			}
			if(res.events.length > 0){
				this.newestActivityTime = res.events[0]['ctime'];
			}
			var haveEvents = false;
			if(jQuery('#wfActivity_' + this.activityMode + ' .wfActEvent').length > 0){
				haveEvents = true;
			}
			if(res.events.length > 0){
				if(! haveEvents){
					jQuery('#wfActivity_' + this.activityMode).empty();
				}
				for(i = res.events.length - 1; i >= 0; i--){
					var elemID = '#wfActEvent_' + res.events[i].id;
					if(jQuery(elemID).length < 1){
						res.events[i]['activityMode'] = this.activityMode;
						var newElem;
						if(this.activityMode == 'loginLogout'){
							newElem = jQuery('#wfLoginLogoutEventTmpl').tmpl(res.events[i]);
						} else {
							newElem = jQuery('#wfHitsEventTmpl').tmpl(res.events[i]);
						}
						jQuery(newElem).find('.wfTimeAgo').data('wfctime', res.events[i].ctime);
						newElem.prependTo('#wfActivity_' + this.activityMode).fadeIn();
					}
				}
				this.reverseLookupIPs();
			} else {
				if(! haveEvents){
					jQuery('#wfActivity_' + this.activityMode).html('<div>No events to report yet.</div>');
				}
			}
			var self = this;
			jQuery('.wfTimeAgo').each(function(idx, elem){
				jQuery(elem).html(self.makeTimeAgo(res.serverTime - jQuery(elem).data('wfctime')) + ' ago');
				});
		}
		if(statusMsgChanged){ this.updateTicker(true); } return;
	},
	reverseLookupIPs: function(){
		var ips = [];
		jQuery('.wfReverseLookup').each(function(idx, elem){
			var txt = jQuery(elem).text();
			if(/^\d+\.\d+\.\d+\.\d+$/.test(txt) && (! jQuery(elem).data('wfReverseDone'))){
				jQuery(elem).data('wfReverseDone', true);
				ips.push(jQuery(elem).text());
			}
		});
		if(ips.length < 1){ return; }
		var uni = {};
		var uniqueIPs = [];
		for(var i = 0; i < ips.length; i++){
			if(! uni[ips[i]]){
				uni[ips[i]] = true;
				uniqueIPs.push(ips[i]);
			}
		}
		this.ajax('wordfence_reverseLookup', {
			ips: uniqueIPs.join(',')
			},
			function(res){
				if(res.ok){
					jQuery('.wfReverseLookup').each(function(idx, elem){
						var txt = jQuery(elem).text();
						for(ip in res.ips){ 
							if(txt == ip){
								if(res.ips[ip]){
									jQuery(elem).html('<strong>Hostname:</strong>&nbsp;' + res.ips[ip]);
								} else {
									jQuery(elem).html('');
								}
							}
						}
						});
					}
				}
			);
	},
	activateWF: function(key){
		jQuery('.wfAjax24').show();
		this.ajax('wordfence_activate', {
			key: key
			},
			function(res){
				jQuery('.wfAjax24').hide();
				if(res.ok){
					window.location = "admin.php?page=Wordfence&wfAct=" + Math.floor(Math.random()*999999999);
					return;
				} else if(res.errorAlert){ 
					jQuery.colorbox({ width: '400px', html:  
						"<h3>An error occured:</h3><p>" + res.errorAlert + "</p>"
						});
				} 

			});
	},
	startScan: function(){
		var self = this;
		jQuery('.wfStartScanButton').addClass('button-wf-grey').val("A scan is in progress...").unbind('click').click(function(){ wordfenceAdmin.scanRunningMsg(); }).show();
		//scanPending prevents the button from switching to grey when clicked and then quickly to blue and grey again as the ticker us updated.
		this.scanPending = true;
		var self = this;
		setTimeout(function(){ self.scanPending = false; }, 10000);
		this.ajax('wordfence_scan', {}, function(res){ } );
	},
	loadIssues: function(callback){
		if(this.mode != 'scan'){
			return;
		}
		var self = this;
		this.ajax('wordfence_loadIssues', { }, function(res){
			self.displayIssues(res, callback);
			});
	},
	sev2num: function(str){
		if(/wfProbSev1/.test(str)){
			return 1;
		} else if(/wfProbSev2/.test(str)){
			return 2;
		} else {
			return 0;
		}
	},
	displayIssues: function(res, callback){
		var self = this;
		res.summary['lastScanCompleted'] = res['lastScanCompleted'];
		jQuery('#wfSummaryTables').html( jQuery('#wfScanSummaryTmpl').tmpl(res.summary).html() );
		jQuery('.wfIssuesContainer').hide();
		for(issueStatus in res.issuesLists){ 
			var containerID = 'wfIssues_dataTable_' + issueStatus;
			var tableID = 'wfIssuesTable_' + issueStatus;
			if(jQuery('#' + containerID).length < 1){
				//Invalid issue status
				continue;
			}
			if(res.issuesLists[issueStatus].length < 1){
				if(issueStatus == 'new'){
					if(res.lastScanCompleted == 'ok'){
						jQuery('#' + containerID).html('<p style="font-size: 20px; color: #0A0;">Congratulations! You have no security issues on your site.</p>');
					} else if(res['lastScanCompleted']){
						//jQuery('#' + containerID).html('<p style="font-size: 12px; color: #A00;">The latest scan failed: ' + res.lastScanCompleted + '</p>');
					} else {
						jQuery('#' + containerID).html();
					}
						
				} else {
					jQuery('#' + containerID).html('<p>There are currently <strong>no issues</strong> being ignored on this site.</p>');
				}
				continue;
			}
			jQuery('#' + containerID).html('<table cellpadding="0" cellspacing="0" border="0" class="display" id="' + tableID + '"></table>');

			jQuery.fn.dataTableExt.oSort['severity-asc'] = function(y,x){ x = WFAD.sev2num(x); y = WFAD.sev2num(y); if(x < y){ return 1; } if(x > y){ return -1; } return 0; };
			jQuery.fn.dataTableExt.oSort['severity-desc'] = function(y,x){ x = WFAD.sev2num(x); y = WFAD.sev2num(y); if(x > y){ return 1; } if(x < y){ return -1; } return 0; };

			jQuery('#' + tableID).dataTable({
				"bFilter": false,
				"bInfo": false,
				"bPaginate": false,
				"bLengthChange": false,
				"bAutoWidth": false,
				"aaData": res.issuesLists[issueStatus],
				"aoColumns": [
					{
						"sTitle": '<div class="th_wrapp">Severity</div>',
						"sWidth": '128px',
						"sClass": "center",
						"sType": 'severity',
						"fnRender": function(obj) {
							var cls = "";
							cls = 'wfProbSev' + obj.aData.severity;
							return '<span class="' + cls + '"></span>';
						}
					},
					{ 
						"sTitle": '<div class="th_wrapp">Issue</div>', 
						"bSortable": false,
						"sWidth": '400px',
						"sType": 'html',
						fnRender: function(obj){ 
							var tmplName = 'issueTmpl_' + obj.aData.type;
							return jQuery('#' + tmplName).tmpl(obj.aData).html();
						} 
					}
				]
			});
		}
		if(callback){
			jQuery('#wfIssues_' + this.visibleIssuesPanel).fadeIn(500, function(){ callback(); });
		} else {
			jQuery('#wfIssues_' + this.visibleIssuesPanel).fadeIn(500);
		}
		return true;
	},
	ajax: function(action, data, cb, cbErr){
		if(typeof(data) == 'string'){
			if(data.length > 0){
				data += '&';
			}
			data += 'action=' + action + '&nonce=' + this.nonce;
		} else if(typeof(data) == 'object'){
			data['action'] = action;
			data['nonce'] = this.nonce;
		}
		if(! cbErr){
			cbErr = function(){};
		}
		var self = this;
		jQuery.ajax({
			type: 'POST',
			url: WordfenceAdminVars.ajaxURL,
			dataType: "json",
			data: data,
			success: function(json){ 
				if(json && json.nonce){
					self.nonce = json.nonce;
				}
				if(json && json.errorMsg){
					self.colorbox('400px', 'An error occured', json.errorMsg);
				}
				cb(json); 
			},
			error: cbErr
			});
	},
	colorbox: function(width, heading, body){ 
		this.colorboxQueue.push([width, heading, body]);
		this.colorboxServiceQueue();
	},
	colorboxServiceQueue: function(){
		if(this.colorboxIsOpen){ return; }
		if(this.colorboxQueue.length < 1){ return; }
		var elem = this.colorboxQueue.shift();
		this.colorboxOpen(elem[0], elem[1], elem[2]);
	},
	colorboxOpen: function(width, heading, body){
		this.colorboxIsOpen = true;
		jQuery.colorbox({ width: width, html: "<h3>" + heading + "</h3><p>" + body + "</p>"});
	},
	scanRunningMsg: function(){ this.colorbox('400px', "A scan is running", "A scan is currently in progress. Please wait until it finishes before starting another scan."); },
	errorMsg: function(msg){ this.colorbox('400px', "An error occured:", msg); },
	deleteFile: function(issueID){
		var self = this;
		this.ajax('wordfence_deleteFile', {
			issueID: issueID 
			}, function(res){ self.doneDeleteFile(res); });
	},
	doneDeleteFile: function(res){
		if(res.ok){
			var self = this;
			this.loadIssues(function(){ self.colorbox('400px', "Success deleting file", "The file " + res.file + " containing " + res.filesize + " bytes was successfully deleted."); });
		} else if(res.errorMsg){
			this.loadIssues();
		}
	},
	restoreFile: function(issueID){
		var self = this;
		this.ajax('wordfence_restoreFile', { 
			issueID: issueID
			}, function(res){ self.doneRestoreFile(res); });
	},
	doneRestoreFile: function(res){
		this.loadIssues();
		if(res.ok){
			this.colorbox("400px", "File restored OK", "The file " + res.file + " was restored succesfully.");
		}
	},
	deleteIssue: function(id){
		var self = this;
		this.ajax('wordfence_deleteIssue', { id: id }, function(res){ 
			self.loadIssues();
			if(res.errMsg){
				self.colorbox('400px', "An error occured", res.errMsg);
			}
			});
	},
	updateIssueStatus: function(id, st){
		var self = this;
		this.ajax('wordfence_updateIssueStatus', { id: id, 'status': st }, function(res){ 
			self.loadIssues();
			if(res.errMsg){
				self.colorbox('400px', "An error occured", res.errMsg);
			}
			});
	},
	updateAllIssues: function(op){ // deleteIgnored, deleteNew, ignoreAllNew
		var head = "Please confirm";
		if(op == 'deleteIgnored'){
			body = "You have chosen to remove all ignored issues. Once these issues are removed they will be re-scanned by Wordfence and if they have not been fixed, they will appear in the 'new issues' list. Are you sure you want to do this?";
		} else if(op == 'deleteNew'){
			body = "You have chosen to mark all new issues as fixed. If you have not really fixed these issues, they will reappear in the new issues list on the next scan. If you have not fixed them and want them excluded from scans you should choose to 'ignore' them instead. Are you sure you want to mark all new issues as fixed?";
		} else if(op == 'ignoreAllNew'){
			body = "You have chosen to ignore all new issues. That means they will be excluded from future scans. You should only do this if you're sure all new issues are not a problem. Are you sure you want to ignore all new issues?";
		} else {
			return;
		}
		this.colorbox('450px', head, body + '<br /><br /><center><input type="button" name="but1" value="Cancel" onclick="jQuery.colorbox.close();" />&nbsp;&nbsp;&nbsp;<input type="button" name="but2" value="Yes I\'m sure" onclick="jQuery.colorbox.close(); WFAD.confirmUpdateAllIssues(\'' + op + '\');" /><br />');
	},
	confirmUpdateAllIssues: function(op){
		var self = this;
		this.ajax('wordfence_updateAllIssues', { op: op }, function(res){ self.loadIssues(); });
	},
	es: function(val){
		if(val){
			return val;
		} else {
			return "";
		}
	},
	noQuotes: function(str){
		return str.replace(/"/g,'&#34;').replace(/\'/g, '&#145;');
	},
	commify: function(num){
		return ("" + num).replace(/(\d)(?=(\d\d\d)+(?!\d))/g, "$1,");
	},
	switchToLiveTab: function(elem){
		jQuery('.wfTab1').removeClass('selected'); 
		jQuery(elem).addClass('selected'); 
		jQuery('.wfDataPanel').hide(); 
		var self = this;
		jQuery('#wfActivity').fadeIn(function(){ self.completeLiveTabSwitch(); });
	},
	completeLiveTabSwitch: function(){
		this.ajax('wordfence_loadActivityLog', {}, function(res){
			var html = '<a href="#" class="wfALogMailLink" onclick="WFAD.emailActivityLog(); return false;"></a><a href="#" class="wfALogReloadLink" onclick="WFAD.reloadActivityData(); return false;"></a>';
			if(res.events && res.events.length > 0){
				jQuery('#wfActivity').empty();
				for(var i = 0; i < res.events.length; i++){
					var timeTaken = '0.0000';
					if(res.events[i + 1]){
						timeTaken =  (res.events[i].ctime - res.events[i + 1].ctime).toFixed(4);
					}
					var red = "";
					if(res.events[i].type == 'error'){
						red = ' class="wfWarn" ';
					}
					html += '<div ' + red + 'class="wfALogEntry"><span ' + red + 'class="wfALogTime">[' + res.events[i].type + '&nbsp;:&nbsp;' + timeTaken + '&nbsp;:&nbsp;' + res.events[i].timeAgo + ' ago]</span>&nbsp;' + res.events[i].msg + "</div>";
				}
				jQuery('#wfActivity').html(html);
			} else {
				jQuery('#wfActivity').html("<p>&nbsp;&nbsp;No activity to report yet. Please complete your first scan.</p>");
			}
		});
	},
	emailActivityLog: function(){
		this.colorbox('400px', 'Email Wordfence Activity Log', "Enter the email address you would like to send the Wordfence activity log to. Note that the activity log may contain thousands of lines of data. This log is usually only sent to a member of the Wordfence support team.<br /><br /><input type='text' size='20' id='wfALogRecip' /><input type='button' value='Send' onclick=\"WFAD.completeEmailActivityLog();\" /><input type='button' value='Cancel' onclick='jQuery.colorbox.close();' /><br /><br />");
	},
	completeEmailActivityLog: function(){
		jQuery.colorbox.close();
		var email = jQuery('#wfALogRecip').val();
		if(! /^[^@]+@[^@]+$/.test(email)){
			alert("Please enter a valid email address.");
			return;
		}
		var self = this;
		this.ajax('wordfence_sendActivityLog', { email: jQuery('#wfALogRecip').val() }, function(res){
			if(res.ok){
				self.colorbox('400px', 'Activity Log Sent', "Your Wordfence activity log was sent to " + email + "<br /><br /><input type='button' value='Close' onclick='jQuery.colorbox.close();' /><br /><br />");
			}
		});
	},
	reloadActivityData: function(){
		jQuery('#wfActivity').html('<div class="wfLoadingWhite32"></div>'); //&nbsp;<br />&nbsp;<br />&nbsp;<br />&nbsp;<br />&nbsp;<br />&nbsp;<br />&nbsp;<br />&nbsp;<br />&nbsp;<br />&nbsp;<br />
		this.completeLiveTabSwitch();
	},
	switchToSummaryTab: function(elem){
		jQuery('.wfTab1').removeClass('selected'); 
		jQuery(elem).addClass('selected'); 
		jQuery('.wfDataPanel').hide(); 
		jQuery('#wfSummaryTables').fadeIn();
	},
	switchIssuesTab: function(elem, type){
		jQuery('.wfTab2').removeClass('selected');
		jQuery('.wfIssuesContainer').hide();
		jQuery(elem).addClass('selected');
		this.visibleIssuesPanel = type;
		jQuery('#wfIssues_' + type).fadeIn();
	},
	switchTab: function(tabElement, tabClass, contentClass, selectedContentID, callback){
		jQuery('.' + tabClass).removeClass('selected');
		jQuery(tabElement).addClass('selected');
		jQuery('.' + contentClass).hide().html('<div class="wfLoadingWhite32"></div>');
		var func = function(){};
		if(callback){
			func = function(){ callback(); };
		}
		jQuery('#' + selectedContentID).fadeIn(func);
	},
	activityTabChanged: function(){
		var mode = jQuery('.wfDataPanel:visible')[0].id.replace('wfActivity_','');
		if(! mode){ return; }
		this.activityMode = mode;		
		this.reloadActivities();
	},
	reloadActivities: function(){
		jQuery('#wfActivity_' + this.activityMode).html('<div class="wfLoadingWhite32"></div>');
		this.newestActivityTime = 0;
		this.updateTicker(true);
	},
	staticTabChanged: function(){
		var mode = jQuery('.wfDataPanel:visible')[0].id.replace('wfActivity_','');
		if(! mode){ return; }
		this.activityMode = mode;		

		var self = this;
		this.ajax('wordfence_loadStaticPanel', {
			mode: this.activityMode
			}, function(res){ 
				self.completeLoadStaticPanel(res);
			});
	},
	completeLoadStaticPanel: function(res){
		var contentElem = '#wfActivity_' + this.activityMode;
		jQuery(contentElem).empty();
		if(res.results && res.results.length > 0){
			var tmpl;
			if(this.activityMode == 'topScanners' || this.activityMode == 'topLeechers'){
				tmpl = '#wfLeechersTmpl';
			} else if(this.activityMode == 'blockedIPs'){
				tmpl = '#wfBlockedIPsTmpl';
			} else if(this.activityMode == 'lockedOutIPs'){
				tmpl = '#wfLockedOutIPsTmpl';
			} else if(this.activityMode == 'throttledIPs'){
				tmpl = '#wfThrottledIPsTmpl';
			} else { return; }
			jQuery(tmpl).tmpl(res).prependTo(contentElem);
			this.reverseLookupIPs();
		} else {
			if(this.activityMode == 'topScanners' || this.activityMode == 'topLeechers'){
				jQuery(contentElem).html("No site hits have been logged yet. Check back soon.");
			} else if(this.activityMode == 'blockedIPs'){
				jQuery(contentElem).html("No IP addresses have been blocked yet. If you manually block an IP address or if Wordfence automatically blocks one, it will appear here.");
			} else if(this.activityMode == 'lockedOutIPs'){
				jQuery(contentElem).html("No IP addresses have been locked out from signing in or using the password recovery system.");
			} else if(this.activityMode == 'throttledIPs'){
				jQuery(contentElem).html("No IP addresses have been throttled yet. If an IP address accesses the site too quickly and breaks one of the Wordfence rules, it will appear here.");
			} else { return; }
		}
	},
	ucfirst: function(str){
		str = "" + str;
		return str.charAt(0).toUpperCase() + str.slice(1);
	},
	makeIPTrafLink: function(IP){
		return '/?_wfsf=IPTraf&nonce=' + this.nonce + '&IP=' + encodeURIComponent(IP);
	},
	makeDiffLink: function(dat){
		return '/?_wfsf=diff&nonce=' + this.nonce +
			'&file=' + encodeURIComponent(this.es(dat['file'])) +
			'&cType=' + encodeURIComponent(this.es(dat['cType'])) +
			'&cKey=' + encodeURIComponent(this.es(dat['cKey'])) +
			'&cName=' + encodeURIComponent(this.es(dat['cName'])) +
			'&cVersion=' + encodeURIComponent(this.es(dat['cVersion']));
	},
	makeTimeAgo: function(t){
		var months = Math.floor(t / (86400 * 30));
		var days = Math.floor(t / 86400);
		var hours = Math.floor(t / 3600);
		var minutes = Math.floor(t / 60);
		if(months > 0){
			days -= months * 30;
			return this.pluralize(months, 'month', days, 'day');
		} else if(days > 0){
			hours -= days * 24;
			return this.pluralize(days, 'day', hours, 'hour');
		} else if(hours > 0) {
			minutes -= hours * 60;
			return this.pluralize(hours, 'hour', minutes, 'min');
		} else if(minutes > 0) {
			//t -= minutes * 60;
			return this.pluralize(minutes, 'minute');
		} else {
			return Math.round(t) + " seconds";
		}
	},
	pluralize: function(m1, t1, m2, t2){
		if(m1 != 1) {
			t1 = t1 + 's';
		}
		if(m2 != 1) {
			t2 = t2 + 's';
		}
		if(m1 && m2){
			return m1 + ' ' + t1 + ' ' + m2 + ' ' + t2;
		} else {
			return m1 + ' ' + t1;
		}
	},
	blockIP: function(IP, reason){
		var self = this;
		this.ajax('wordfence_blockIP', {
			IP: IP,
			reason: reason
			}, function(res){ 
				if(res.errorMsg){
					return;
				} else {
					self.reloadActivities(); 
				}
			});
	},
	unlockOutIP: function(IP){
		var self = this;
		this.ajax('wordfence_unlockOutIP', {
			IP: IP
			}, function(res){ self.staticTabChanged(); });
	},
	unblockIP: function(IP){
		var self = this;
		this.ajax('wordfence_unblockIP', {
			IP: IP
			}, function(res){ self.staticTabChanged(); });
	},
	makeElemID: function(){
		return 'wfElemGen' + this.elementGeneratorIter++;
	},
	pulse: function(sel){
		jQuery(sel).fadeIn(function(){
			setTimeout(function(){ jQuery(sel).fadeOut(); }, 2000);
			});
	},
	saveConfig: function(){
		var qstr = jQuery('#wfConfigForm').serialize();
		var self = this;
		jQuery('.wfSavedMsg').hide();
		jQuery('.wfAjax24').show();
		this.ajax('wordfence_saveConfig', qstr, function(res){
			jQuery('.wfAjax24').hide();
			if(res.ok){
				if(res['reload'] == 'reload' || WFAD.reloadConfigPage){
					self.colorbox('400px', "Please reload this page", "You selected a config option that requires a page reload. Click the button below to reload this page to update the menu.<br /><br /><center><input type='button' name='wfReload' value='Reload page' onclick='window.location.reload();' /></center>");
					return;
				} else {
					self.pulse('.wfSavedMsg');
				}
			} else if(res.errorMsg){
				return;
			} else {
				self.colorbox('400px', 'An error occured', 'We encountered an error trying to save your changes.');
			}
			});
	},
	changeSecurityLevel: function(){
		var level = jQuery('#securityLevel').val();
		for(var k in WFSLevels[level].checkboxes){
			if(k != 'liveTraf_ignorePublishers'){
				jQuery('#' + k).prop("checked", WFSLevels[level].checkboxes[k]);
			}
		}
		for(var k in WFSLevels[level].otherParams){
			if(! /^(?:apiKey|securityLevel|alertEmails|liveTraf_ignoreUsers|liveTraf_ignoreIPs|liveTraf_ignoreUA|liveTraf_hitsMaxSize)$/.test(k)){
				jQuery('#' + k).val(WFSLevels[level].otherParams[k]);
			}
		}
	},
	clearAllBlocked: function(op){
		if(op == 'blocked'){
			body = "Are you sure you want to clear all blocked IP addresses and allow visitors from those addresses to access the site again?";
		} else if(op == 'locked'){
			body = "Are you sure you want to clear all locked IP addresses and allow visitors from those addresses to sign in again?";
		} else {
			return;
		}
		this.colorbox('450px', "Please confirm", body + 
			'<br /><br /><center><input type="button" name="but1" value="Cancel" onclick="jQuery.colorbox.close();" />&nbsp;&nbsp;&nbsp;' +
			'<input type="button" name="but2" value="Yes I\'m sure" onclick="jQuery.colorbox.close(); WFAD.confirmClearAllBlocked(\'' + op + '\');"><br />');
	},
	confirmClearAllBlocked: function(op){
		var self = this;
		this.ajax('wordfence_clearAllBlocked', { op: op }, function(res){ 
			self.staticTabChanged();
			});
	}
};
window['WFAD'] = window['wordfenceAdmin'];
}
jQuery(function(){
	wordfenceAdmin.init();
});
