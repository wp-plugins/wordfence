This email was sent from your website "<?php echo get_bloginfo('name', 'raw'); ?>" by the Wordfence plugin.

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


<?php if(! $isPaid){ ?>
NOTE: You are using the free version of Wordfence. Upgrading to the paid version of Wordfence gives you 
two factor authentication (sign-in via cellphone) and country blocking which are both effective methods to block attacks.
A Premium Wordfence license also includes remote scanning with each scan of your site which can detect 
several additional website infections. Premium members can also schedule when website scans occur and
can scan more than once per day.

As a Premium member you also get access to our priority support system located at http://support.wordfence.com/ and can file
priority support tickets using our ticketing system. 

Click here to sign-up for the Premium version of Wordfence now.
https://www.wordfence.com/wordfence-signup/

<?php } ?>



