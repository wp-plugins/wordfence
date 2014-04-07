Wordfence found the following new issues on "<?php echo get_bloginfo('name', 'raw'); ?>".

Alert generated at <?php echo wfUtils::localHumanDate(); ?>

<?php if($totalCriticalIssues > 0){ ?>
Critical Problems:

<?php foreach($issues as $i){ if($i['severity'] == 1){ ?>
* <?php echo $i['shortMsg'] ?>

<?php } } } ?>

<?php if($level == 2 && $totalWarningIssues > 0){ ?>
Warnings:

<?php foreach($issues as $i){ if($i['severity'] == 2){  ?>
* <?php echo $i['shortMsg'] ?>

<?php } } } ?>




