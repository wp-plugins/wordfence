Wordfence found the following new issues on "<?php echo get_bloginfo('name', 'raw'); ?>".

<?php if(! $isPaid){ ?>
NOTE: Upgrading to the paid version of Wordfence gives you two factor authentication (sign-in via cellphone)
and country blocking which are both effective methods to block attacks.
You can also schedule when your scans occur with Wordfence Premium.
Click here to sign-up for the Premium version of Wordfence now.
https://www.wordfence.com/wordfence-signup/

<?php } ?>

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




