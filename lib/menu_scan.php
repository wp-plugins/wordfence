<div class="wordfenceModeElem" id="wordfenceMode_scan"></div>
<div class="wrap wordfence">
	<div class="wordfence-lock-icon wordfence-icon32"><br /></div><h2>Wordfence Scan</h2>
	<div class="wordfenceWrap">
		<div class="wordfenceScanButton"><input type="button" value="Start a Wordfence Scan" id="wfStartScanButton1" class="wfStartScanButton button-primary" onclick="wordfenceAdmin.startScan();" />
		<a target="_blank" href="http://www.wordfence.com/forums/">You can always get help on our support forum.</a>
		</div>
		<div>
			<div class="consoleHead">
				<span class="consoleHeadText">Scan Summary</span>
			</div>
			<?php 
				$events = wordfence::getLog()->getStatusEvents(0);
			?>
			<div class="bevelDiv1 consoleOuter"><div class="bevelDiv2"><div class="bevelDiv3 consoleInner" id="consoleSummary">
			<?php if(sizeof($events) < 1){ ?>
				<div style="width: 500px;">
					Welcome to Wordfence!<br /><br />
					To get started, simply click the blue button at the top of this page to start your first scan.
				</div>
			<?php } ?>
			</div></div></div>
			<?php if(wfConfig::get('isPaid')){ ?>
			<div style="margin: 0 0 20px 5px; width: 795px; font-weight: bold; color: #0A0;">
				Premium scanning enabled.	
			</div>
			<?php } else { ?>
			<div style="margin: 0 0 20px 5px; width: 795px;">
				<strong>How to upgrade:</strong> <a href="https://www.wordfence.com/choose-a-wordfence-membership-type/?s2-ssl=yes" target="_blank">Visit www.wordfence.com</a> and sign up for a paid option. Then go to the Wordfence options page on this site and replace your free API key with your new premium key. You will then be able to activate the premium scanning options on the Wordfence options page.
			</div>

			<?php } ?>
			<div class="consoleHead" style="margin-top: 20px;">
				<span class="consoleHeadText">Scan Detailed Activity</span>
				<a href="#" class="wfALogMailLink" onclick="WFAD.emailActivityLog(); return false;">Email activity log</a>
			</div>
			<div class="bevelDiv1 consoleOuter"><div class="bevelDiv2"><div class="bevelDiv3 consoleInner" id="consoleActivity">
				<?php 
					if(sizeof($events) > 0){
						$debugOn = wfConfig::get('debugOn', false);
						$newestItem = 0;
						$sumEvents = array();
						foreach($events as $e){
							if(strpos($e['msg'], 'SUM_') !== 0){
								if( $debugOn || $e['level'] < 4){
									$typeClass = '';
									if($debugOn){
										$typeClass = ' wf' . $e['type'];
									}
									echo '<div class="wfActivityLine' . $typeClass . '">[' . date('M d H:i:s', $e['ctime']) . ']&nbsp;' . $e['msg'] . '</div>';
								}
							}
							$newestItem = $e['ctime'];
						}

						echo '<script type="text/javascript">WFAD.lastALogCtime = ' . $newestItem . '; WFAD.processActArray(' . json_encode(wordfence::getLog()->getSummaryEvents()) . ');</script>';
					} else { ?>
						A live stream of what Wordfence is busy with right now will appear in this box.

					<?php
					}
				?>
			</div></div></div>
			<div style="position: relative; width: 803px;">
				&nbsp;
				<a href="#" target="_blank" class="wfALogViewLink" id="wfALogViewLink">View activity log</a>
			</div>
		</div>
		<div style="margin-top: 20px;">
			<div id="wfTabs">
				<a href="#" id="wfNewIssuesTab" class="wfTab2 wfTabSwitch selected" onclick="wordfenceAdmin.switchIssuesTab(this, 'new'); return false;">New Issues</a>
				<a href="#" class="wfTab2 wfTabSwitch"          onclick="wordfenceAdmin.switchIssuesTab(this, 'ignored'); return false;">Ignored Issues</a>
			</div>
			<div class="wfTabsContainer">
				<div id="wfIssues_new" class="wfIssuesContainer">
					<h2>New Issues</h2>
					<p>
						The list below shows new problems or warnings that Wordfence found with your site.
						If you have fixed all the issues below, you can <a href="#" onclick="WFAD.updateAllIssues('deleteNew'); return false;">click here to mark all new issues as fixed</a>.
						You can also <a href="#" onclick="WFAD.updateAllIssues('ignoreAllNew'); return false;">ignore all new issues</a> which will exclude all issues listed below from future scans.
					</p>
					 <div id="wfIssues_dataTable_new">
					 </div>
				</div>
				<div id="wfIssues_ignored" class="wfIssuesContainer">
					<h2>Ignored Issues</h2>
					<p>
						The list below shows issues that you know about and have chosen to ignore.
						You can <a href="#" onclick="WFAD.updateAllIssues('deleteIgnored'); return false;">click here to clear all ignored issues</a>
						which will cause all issues below to be re-scanned by Wordfence in the next scan.
					</p>
					 <div id="wfIssues_dataTable_ignored"></div>
				</div>
			</div>
		</div>
	</div>
</div>
<script type="text/x-jquery-template" id="issueTmpl_wfThemeUpgrade">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Theme Name:</th><td>${data.name}</td></tr>
		<tr><th>Current Theme Version:</th><td>${data.version}</td></tr>
		<tr><th>New Theme Version:</th><td>${data.newVersion}</td></tr>
		<tr><th>Theme URL:</th><td><a href="${data.URL}" target="_blank">${data.URL}</a></td></tr>
		<tr><th>Severity:</th><td>{{if severity == '1'}}Critical{{else}}Warning{{/if}}</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreP' || status == 'ignoreC' }}Ignored{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
		<a href="<?php echo get_admin_url() . 'update-core.php'; ?>">Click here to update now</a>.
	</p>
	<div class="wfIssueOptions">
		{{if (status == 'new')}}
			<strong>Resolve:</strong>
			<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</a>
			<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore this issue</a>
		{{/if}}
		{{if status == 'ignoreC' || status == 'ignoreP'}}
			<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Stop ignoring this issue</a>
		{{/if}}
	</div>
</div>
</div>
</script>

<script type="text/x-jquery-template" id="issueTmpl_wfPluginUpgrade">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Plugin Name:</th><td>${data.Name}</td></tr>
		{{if data.PluginURI}}<tr><th>Plugin Website:</th><td><a href="${data.PluginURI}" target="_blank">${data.PluginURI}</a></td></tr>{{/if}}
		<tr><th>Current Plugin Version:</th><td>${data.Version}</td></tr>
		<tr><th>New Plugin Version:</th><td>${data.newVersion}</td></tr>
		<tr><th>Severity:</th><td>{{if severity == '1'}}Critical{{else}}Warning{{/if}}</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreP' || status == 'ignoreC' }}Ignored{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
		<a href="<?php echo get_admin_url() . 'update-core.php'; ?>">Click here to update now</a>.
	</p>
	<div class="wfIssueOptions">
	{{if status == 'new'}}
		<strong>Resolve:</strong>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</a>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore this issue</a>
	{{/if}}
	{{if status == 'ignoreC' || status == 'ignoreP'}}
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">Stop ignoring this issue</a>
	{{/if}}
	</div>
</div>
</div>
</script>

<script type="text/x-jquery-template" id="issueTmpl_wfUpgrade">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Current WordPress Version:</th><td>${data.currentVersion}</td></tr>
		<tr><th>New WordPress Version:</th><td>${data.newVersion}</td></tr>
		<tr><th>Severity:</th><td>{{if severity == '1'}}Critical{{else}}Warning{{/if}}</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreP' || status == 'ignoreC' }}Ignored{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
		<a href="<?php echo get_admin_url() . 'update-core.php'; ?>">Click here to update now</a>.
	</p>
	<div class="wfIssueOptions">
	{{if (status == 'new')}}
		<strong>Resolve:</strong>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</a>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore this issue</a>
	{{/if}}
	{{if status == 'ignoreC' || status == 'ignoreP'}}
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">Stop ignoring this issue</a>
	{{/if}}
</div>
</div>
</script>

<script type="text/x-jquery-template" id="issueTmpl_dnsChange">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Old DNS records:</th><td>${data.oldDNS}</td></tr>
		<tr><th>New DNS records:</th><td>${data.newDNS}</td></tr>
		<tr><th>Severity:</th><td>{{if severity == '1'}}Critical{{else}}Warning{{/if}}</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreP' || status == 'ignoreC' }}Ignored{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
	</p>
	<div class="wfIssueOptions">
	{{if (status == 'new')}}
		<strong>Resolve:</strong> 
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I know about this change</a>
	{{/if}}
	</div>
</div>
</div>
</script>

<script type="text/x-jquery-template" id="issueTmpl_diskSpace">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Space remaining:</th><td>${data.spaceLeft}%</td></tr>
		<tr><th>Severity:</th><td>{{if severity == '1'}}Critical{{else}}Warning{{/if}}</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreP' || status == 'ignoreC' }}Ignoring all disk space alerts{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
	</p>
	<div class="wfIssueOptions">
	{{if (status == 'new')}}
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</span>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreP'); return false;">Ignore disk space alerts</span>
	{{/if}}
	{{if status == 'ignoreP' || status == 'ignoreC'}}
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">Stop ignoring disk space alerts</a>
	{{/if}}
	</div>
</div>
</div>
</script>

<script type="text/x-jquery-template" id="issueTmpl_easyPassword">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Issue first detected:</th><td>${timeAgo} ago.</td></tr>
		<tr><th>Login name:</th><td>${data.user_login}</td></tr>
		<tr><th>User email:</th><td>${data.user_email}</td></tr>
		<tr><th>Full name:</th><td>${data.first_name} ${data.last_name}</td></tr>
		<tr><th>Severity:</th><td>{{if severity == '1'}}Critical{{else}}Warning{{/if}}</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreC' }}Ignored until user changes password{{/if}}
			{{if status == 'ignoreP' }}Ignoring this user's weak passwords{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
	</p>
	<div class="wfIssueOptions">
		<strong>Tools:</strong>
		<a target="_blank" href="${data.editUserLink}">Edit this user</a>
	</div>
	<div class="wfIssueOptions">
	{{if status == 'new'}}
		<strong>Resolve:</strong> 
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</a>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore this weak password</a>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreP'); return false;">Ignore all this user's weak passwords</a>
	{{/if}}
	{{if status == 'ignoreC' || status == 'ignoreP'}}
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">Stop ignoring this issue</a>
	{{/if}}
	</div>
</div>
</div>
</script>

<script type="text/x-jquery-template" id="issueTmpl_commentBadURL">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Author</th><td>${data.author}</td></tr>
		<tr><th>Bad URL:</th><td><strong class="wfWarn">${data.badURL}</strong></td></tr>
		<tr><th>Posted on:</th><td>${data.commentDate}</td></tr>
		{{if data.isMultisite}}
		<tr><th>Multisite Blog ID:</th><td>${data.blog_id}</td></tr>
		<tr><th>Multisite Blog Domain:</th><td>${data.domain}</td></tr>
		<tr><th>Multisite Blog Path:</th><td>${data.path}</td></tr>
		{{/if}}
		<tr><th>Severity:</th><td>Critical</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreP' || status == 'ignoreC' }}Ignored{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
	</p>
	<div class="WfIssueOptions">
		<strong>Tools:</strong>
		<a target="_blank" href="${data.editCommentLink}">Edit this ${data.type}</a>
	</div>
	<div class="wfIssueOptions">
	{{if status == 'new'}}
		<strong>Resolve:</strong> 
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</a>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore this ${data.type}</a>
	{{/if}}
	{{if status == 'ignoreC' || status == 'ignoreP'}}
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">Stop ignoring this ${data.type}</a>
	{{/if}}
</div>
</div>
</script>

<script type="text/x-jquery-template" id="issueTmpl_postBadURL">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		{{if data.isMultisite}}
		<tr><th>Title:</th><td><a href="${data.permalink}" target="_blank">${data.postTitle}</a></td></tr>
		{{else}}
		<tr><th>Title:</th><td><a href="${data.permalink}" target="_blank">${data.postTitle}</a></td></tr>
		{{/if}}
		<tr><th>Bad URL:</th><td><strong class="wfWarn">${data.badURL}</strong></td></tr>
		<tr><th>Posted on:</th><td>${data.postDate}</td></tr>
		{{if data.isMultisite}}
		<tr><th>Multisite Blog ID:</th><td>${data.blog_id}</td></tr>
		<tr><th>Multisite Blog Domain:</th><td>${data.domain}</td></tr>
		<tr><th>Multisite Blog Path:</th><td>${data.path}</td></tr>
		{{/if}}
		<tr><th>Severity:</th><td>Critical</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreC' }}This bad URL will be ignored in this ${data.type}.{{/if}}
			{{if status == 'ignoreP' }}This post won't be scanned for bad URL's.{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
	</p>
	<div class="wfIssueOptions">
		<strong>Tools:</strong> 
		<a target="_blank" href="${data.editPostLink}">Edit this ${data.type}</a>
	</div>
	<div class="wfIssueOptions">
	{{if status == 'new'}}
		<strong>Resolve:</strong> 
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</a>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore this bad URL in this ${data.type}</a>
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreP'); return false;">Ignore all bad URL's in this ${data.type}</a>
	{{/if}}
	{{if status == 'ignoreP' || status == 'ignoreC'}}
		<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">Stop ignoring this issue</a>
	{{/if}}
	</div>
</div>
</div>
</script>



<script type="text/x-jquery-template" id="issueTmpl_file">
<div>
<div class="wfIssue">
	<h2>${shortMsg}</h2>
	<p>
		<table border="0" class="wfIssue" cellspacing="0" cellpadding="0">
		<tr><th>Filename:</th><td>${data.file}</td></tr>
		{{if ((typeof data.badURL !== 'undefined') && data.badURL)}}
		<tr><th>Bad URL:</th><td><strong class="wfWarn">${data.badURL}</strong></td></tr>
		{{/if}}
		<tr><th>File type:</th><td>{{if data.cType}}${WFAD.ucfirst(data.cType)}{{else}}Not a core, theme or plugin file.{{/if}}</td></tr>
		<tr><th>Issue first detected:</th><td>${timeAgo} ago.</td></tr>
		<tr><th>Severity:</th><td>{{if severity == '1'}}Critical{{else}}Warning{{/if}}</td></tr>
		<tr><th>Status</th><td>
			{{if status == 'new' }}New{{/if}}
			{{if status == 'ignoreP' }}Permanently ignoring this file{{/if}}
			{{if status == 'ignoreC' }}Ignoring this file until it changes{{/if}}
		</td></tr>
		</table>
	</p>
	<p>
		{{html longMsg}}
	</p>
	<div class="wfIssueOptions">
		<strong>Tools:</strong> 
		{{if data.fileExists}}
		<a target="_blank" href="${WFAD.makeViewFileLink(data.file)}">View the file.</a>
		{{/if}}
		{{if data.canFix}}
		<a href="#" onclick="WFAD.restoreFile('${id}'); return false;">Restore the original version of this file.</a>
		{{/if}}
		{{if data.canDelete}}
		<a href="#" onclick="WFAD.deleteFile('${id}'); return false;">Delete this file (can't be undone).</a>
		{{/if}}
		{{if data.canDiff}}
		<a href="${WFAD.makeDiffLink(data)}" target="_blank">See how the file has changed.</a>
		{{/if}}
	</div>
	<div class="wfIssueOptions">
		{{if status == 'new'}}
			<strong>Resolve:</strong>
			<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">I have fixed this issue</a>
			{{if data.fileExists}}
				<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore until the file changes.</a>
				<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreP'); return false;">Always ignore this file.</a>
			{{else}}
				<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'ignoreC'); return false;">Ignore missing file</a>
			{{/if}}
				
		{{/if}}
		{{if status == 'ignoreC' || status == 'ignoreP'}}
			<a href="#" onclick="WFAD.updateIssueStatus('${id}', 'delete'); return false;">Stop ignoring this issue.</a>
		{{/if}}
	</div>
</div>
</div>
</script>
<script type="text/x-jquery-template" id="wfNoScanYetTmpl">
<div>
	<table class="wfSummaryParent" cellpadding="0" cellspacing="0">
	<tr><th class="wfHead">Your first scan is starting now</th></tr>
	<tr><td>
		<table class="wfSC1"  cellpadding="0" cellspacing="0">
		<tr><td>
			Your first Wordfence scan should be automatically starting now
			and you will see the scan details in the "Activity Log" above in a few seconds.
			While you're waiting, why not visit the <a href="http://www.wordfence.com/forums/" target="_blank">Wordfence Forums</a>
			where you can post your comments or questions. We would love to hear from you.
		</td></tr>
		<tr><td>
			<div class="wordfenceScanButton"><input type="button" value="Start a Wordfence Scan" id="wfStartScanButton2" class="wfStartScanButton button-primary" /></div>
		</td></tr>
		</table>
	</td>
	</tr></table>
</div>
</script>


