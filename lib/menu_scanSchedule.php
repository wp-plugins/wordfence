<div class="wordfenceModeElem" id="wordfenceMode_scanScheduling"></div>
<div class="wrap" id="paidWrap">
	<div class="wordfence-lock-icon wordfence-icon32"><br /></div><h2>Schedule Wordfence Scanning</h2>
	<div class="wordfenceWrap" style="margin: 20px 20px 20px 30px;">
		<p>
			<strong>Current time: <?php echo date('l jS \of F Y H:i:s A', current_time('timestamp')); ?></strong>
		</p>
		<p style="width: 600px;">
			Wordfence provides continuous real-time security for your site. Occasionally we run a full scan of all files, posts, pages, comments, user password and other site components. 
			The scheduler below lets you choose when those full scans will run.<br /><br />

			We have displayed the current time your WordPress site uses above.
			You can go to the Settings/General menu to change your timezone.
			Use the links provided as shortcuts to select scan times. Try clicking 
			the links several times to advance the time. You can also manually select scan start times for each day.
		</p>
		<p>
			<strong>Scan mode:</strong><select id="schedMode" onchange="WFAD.sched_modeChange();">
				<option value="auto"<?php echo (wfConfig::get('schedMode') == 'auto' ? ' selected' : ''); ?>>Let Wordfence automatically schedule scans (recommended)</option>
				<option value="manual"<?php echo (wfConfig::get('schedMode') == 'manual' ? ' selected' : ''); ?>>Manually schedule scans using calendar below</option>
				</select>
		<p>
			<strong>Shortcuts</strong>:
			<a href="#" onclick="WFAD.sched_shortcut('onceDaily'); return false;">Once a day</a>,
			<a href="#" onclick="WFAD.sched_shortcut('twiceDaily'); return false;">Twice a day</a>,
			<a href="#" onclick="WFAD.sched_shortcut('weekends'); return false;">Weekends</a>,
			<a href="#" onclick="WFAD.sched_shortcut('oddDaysWE'); return false;">Odd days and weekends</a>,
			<a href="#" onclick="WFAD.sched_shortcut('every6hours'); return false;">Every 6 hours</a>,
		</p>

		<table border="0">
		<?php
		$daysOfWeek = array(
			array(1, 'Monday'), 
			array(2, 'Tuesday'), 
			array(3, 'Wednesday'), 
			array(4, 'Thursday'), 
			array(5, 'Friday'), 
			array(6, 'Saturday'), 
			array(0, 'Sunday')
			);
		$sched = wfConfig::get_ser('scanSched', array());
		foreach($daysOfWeek as $elem){
			$dayIndex = $elem[0];
			$dayName = $elem[1];
			require('schedWeekEntry.php');
		}
		?>
		</table>
		<table border="0" cellpadding="0" cellspacing="0"><tr>
			<td>
				<input type="button" name="but3" class="button-primary" value="Save Scan Schedule" onclick="WFAD.sched_save();" />
			</td>
			<td style="height: 24px;"><div class="wfAjax24"></div><span class="wfSavedMsg">&nbsp;Your changes have been saved!</span></td>
		</tr>
		</table>
	</div>
	<br />
</div>

<script type="text/javascript">
<?php
if(! wfConfig::get('isPaid')){
	echo 'WFAD.paidUsersOnly("Scan scheduling is only available to paid members because it puts significant additional load on our cloud scanning servers. As a free customer, Wordfence will automatically schedule scans to run approximately once daily.");';
}
?>

</script>
