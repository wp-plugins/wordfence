<p>This email was sent from your website "<?php echo $blogName; ?>" by the Wordfence plugin at <?php echo $date; ?></p>

<p>The Wordfence administrative URL for this site is: <?php echo $adminURL; ?>admin.php?page=Wordfence</p>

<p><?php echo $alertMsg; ?></p>
<?php if($IPMsg){ echo "\n<p>$IPMsg</p>\n"; } ?>

<?php if(! $isPaid){ ?>
<p>NOTE: You are using the free version of Wordfence. Upgrading to the paid version of Wordfence gives you 
two factor authentication (sign-in via cellphone) and country blocking which are both effective methods to block attacks.
A Premium Wordfence license also includes remote scanning with each scan of your site which can detect 
several additional website infections. Premium members can also schedule when website scans occur and
can scan more than once per day.</p>

<p>As a Premium member you also get access to our priority support system located at http://support.wordfence.com/ and can file
priority support tickets using our ticketing system. </p>

<p>Click here to sign-up for the Premium version of Wordfence now.<br>
<a href="https://www.wordfence.com/wordfence-signup/">https://www.wordfence.com/wordfence-signup/<a></p>

<?php } ?>

--
<p>To change your alert options for Wordfence, visit:<br>
<?php echo $myOptionsURL; ?></p>

<p>To see current Wordfence alerts, visit:<br>
<?php echo $myHomeURL; ?></p>



