=== Wordfence Security ===
Contributors: mmaunder 
Tags: wordpress, security, wordpress security, security plugin, secure, anti-virus, malware, firewall, antivirus, virus, google safe browsing, phishing, scrapers, hacking, wordfence, securty, secrity, secure
Requires at least: 3.3.1
Tested up to: 3.3.2
Stable tag: 1.5.4

Wordfence Security is a free enterprise class security plugin that includes a firewall, virus scanning, real-time traffic with geolocation and more. 

== Description ==

Wordfence Security is a free enterprise class security plugin that includes a firewall and anti-virus scanning for WordPress websites.

Wordfence is now Multi-Site compatible. Support for Multi-Site is currently in Beta. Please visit our forums to report any issues.

[Remember to visit our support forums if you have questions or comments.](http://wordfence.com/forums/)

Wordfence is 100% free. You need to sign up on Wordfence.com to get a free API key.
We also offer a Premium API key that adds additional scanning capabilities. See below for details.

Wordfence:

* Scans core files against repository versions to check their integrity.
* WordPress Multi-Site (or WordPress MU in the older parlance) compatible (beta).
* Premium API key also scans themes and plugins against repository versions. This is currently the only difference between free and premium API keys.
* See how files have changed. Optionally repair changed files.
* Scans for signatures of over 44,000 known malware variants that are known security threats.
* Continuously scans for malware and phishing URL's in all your comments, posts and files that are security threats.
* Scans for heuristics of backdoors, trojans,  suspicious code and other security issues.
* Checks the strength of all user and admin passwords to enhance login security.
* Monitor for unauthorized DNS changes.
* Includes a firewall to block common security threats like fake Googlebots, malicious scans from hackers and botnets.
* Rate limit or block security threats like aggressive crawlers, scrapers and bots doing security scans for vulnerabilities in your site.
* Choose whether you want to block or throttle users and robots who break your security rules.
* Includes login security to lock out brute force hacks and to stop WordPress from revealing info that will compromise security.
* See all your traffic in real-time, including robots, humans, 404 errors, logins and logouts and who is consuming most of your content. Enhances your situational awareness of which security threats your site is facing.
* A real-time view of all traffic including automated bots that often constitute security threats that Javascript analytics packages never show you.
* Real-time traffic includes reverse DNS and city-level geolocation. Know which geographic area security threats originate from.
* Monitors disk space which is related to security because many DDoS attacks attempt to consume all disk space to create denial of service.

Wordfence Security is full-featured and constantly updated by our team to incorporate the latest security features and to hunt for the 
newest security threats to your WordPress website.

== Installation ==

To install Wordfence Security and start protecting your WordPress website:

[Remember to visit our support forums if you have questions or comments.](http://wordfence.com/forums/)

1. Install Wordfence Security automatically or by uploading the ZIP file. 
1. Activate the security plugin through the 'Plugins' menu in WordPress.
1. Visit [Wordfence.com to get an API key](http://wordfence.com/) which you need to security scans.
1. Go to the Wordfence menu option that appears on the left or your site's admin section.
1. Enter your API key and click the button.
1. Wordfence is now activated. Your first security scan will start automatically and scheduled security scanning will also be enabled.
1. Visit the Wordfence options page to enter your email address so that you can receive email security alerts.
1. Optionally change your security level or click the advanced options link to see individual security scanning and protection options.
1. Click the "Live Traffic" menu option to watch your site activity in real-time.

To install Wordfence on WordPress Multi-Site installations (support is currently in Beta):

1. Install Wordfence via the plugin directory or by uploading the ZIP file.
1. Network Activate Wordfence. This step is important because until you network activate it, your sites will see the plugin option on their plugins menu. Once activated that option dissapears. If one of your users manages to sneak in and try to activate Wordfence between you installing Wordfence and network activating it, don't worry because they won't be allowed to activate the plugin. It will generate a warning and won't activate for an individual site.
1. Now that Wordfence is network activated it will appear on your Network Admin menu. Wordfence will not appear on any individual site's menu. 
1. Enter your API key to start your first scan.
1. Wordfence will scan all files in your WordPress installation including those in the blogs.dir directory of your individual sites. 
1. Live Traffic will appear for ALL sites in your network. If you have a heavily trafficed system you may want to disable live traffic which will stop logging to the DB. 
1. Firewall rules and login rules apply to the WHOLE system. So if you fail a login on site1.example.com and site2.example.com it counts as 2 failures. Crawler traffic is counted between blogs, so if you hit three sites in the network, all the hits are totalled and that counts as the rate you're accessing the system.
1. Wordfence has been tested with subdomains, not with subdirectories yet, but it should work. Please report all bugs and we'll fix them as fast as we can.

== Frequently Asked Questions ==

[Remember to visit our support forums if you have questions or comments.](http://wordfence.com/forums/)

= Why does Wordfence Security need an API key? =

Wordfence securely contacts our servers when doing a security scan. These include: comparing the hashes of your core, theme and plugin files
against the official versions to see if security has been compromised, checking if URL's in your comments, posts and files are on any known list of dangerous URL's and checking
if any of your file signatures match a large list of known malware files that constitute a security threat.

= Does Wordfence support Multi-Site installations? =

Yes. WordPress MU or Multi-Site as it's called now is supported and support is currently in beta. See the installation tab for more info.

= Will Wordfence slow my site down? =

We have spent a lot of time making sure Wordfence runs very quickly and securely. Wordfence uses its own database
tables and advanced mysql features to ensure it runs as fast as possible. The creators of Wordfence
also run a large scale real-time analytics product and much of the technology and knowledge from
our real-time analytics products is built into Wordfence.

= How often is Wordfence updated? =

The Wordfence security plugin is frequently updated and we update the code on our security scanning servers
more frequently. Our cloud servers are continually updated with the latest known security threats and vulnerabilities so
that we can blog any security threat as soon as it emerges in the wild.

= What if I need support? =

All our paid customers receive priority support. Excellent customer service is a key part
of being a Wordfence member. You can also [visit our support forums where we provide free support for all Wordfence users](http://wordfence.com/forums/) and answer any security releated questions you may have.

= Can I disable certain security features of Wordfence? =

Yes! Simply visit the Options page, click on advanced options and enable or disable the security features you want.

= What if my site security has already been compromised by a hacker? =

Wordfence is the only security plugin that is able to repair core files, themes and plugins on sites where security is already compromised.
However, please note that site security can not be assured unless you do a full reinstall if your site has been hacked. We recommend you only
use Wordfence to get your site into a running state in order to recover the data you need to do a full reinstall. A full reinstall is the only
way to ensure site security once you have been hacked. 

= How will I be alerted that my site has a security problem? =

Wordfence sends security alerts via email. Once you install Wordfence, you will configure a list of email addresses where security alerts will be sent.
When you receive a security alert, make sure you deal with it promptly to ensure your site stays secure.

= My WordPress site is behind a firewall. Doesn't that make it secure? =

If your site is accessible from the web, it means that people you don't know can execute PHP code on your site.
They have to be able to execute PHP code, like the core WordPress code, in order for your site to work. 
Most WordPress security threats allow a hacker to execute PHP code on your website. The challenge hackers
face is how to get their malicious PHP code onto your site to compromise your security. There
are many upload mechanisms that WordPress itself, themes and plugins offer and the vast majority of these
are secure. However, every now and then a hacker discovers an upload mechanism that is not secure or 
a way of fooling your site into allowing an upload. That is usually when security is compromised. Even
though your site is behind a commercial firewall, it still accepts web requests that include uploads and executes PHP code
and as long as it does that, it may become face a security vulnerability at some point.

= Will Wordfence protect me against the Timthumb security problem? =

The timthumb security exploit occured in 2011 and all good plugins and themes now use an updated 
version of timthumb (which the creator of Wordfence wrote and donated to the timthumb author) which closes the security hole that
caused the problem. However we do scan for old version of timthumb for good measure to make sure they don't 
cause a security hole on your site. 

= People keep telling me that WordPress itself has security problems. Is that true? =

In general, no it's not. The WordPress team work very hard to keep the awesome software they have produced secure and in the
rare cases when a security hole is found, they fix it very quickly. Most responsible plugin authors also fix security holes
as soon as they are told about them. That's why Wordfence will warn you if you're running an old version of WordPress, a plugin
or a theme, because often these have been updated to fix a security hole.


== Screenshots ==

1. The home screen of Wordfence where you can see a summary, manage security issues and do a manual security scan. 
2. The Live Traffic view of Wordfence where you can see real-time activity on your site.
3. The "Blocked IPs" page where you can manage blocked IP's, locked out IP's and see recently throttled IPs that violated security rules.
4. The basic view of Wordfence options. There is very little to configure other than your alert email address and security level.
5. If you're technically minded, this is the under-the-hood view of Wordfence options where you can fine-tune your security settings.

== Changelog ==
= 1.5.4 =
* Admin can now select to scan outside the WordPress base dir and standard WordPress directories.
* Max memory size for scans is now configurable for larger installations. 256M is the default.
* Changed maximum scan time to 10 minutes. 

= 1.5.3 =
* A harmless cosmetic error was being thrown up when some security scans started. Fixed that.

= 1.5.2 =
* Changed max scan time to 30 mins.

= 1.5.1 =
* Fixed a bug that caused scans to crash when permissions don't allow a directory to be read.

= 1.4.8 =
* WP repo didn't deploy the zip file correctly so recreating the version tag.

= 1.4.7 =
* Vastly improved error logging including catching fatal PHP errors and logging them to status log.
* Fixed accidental preg_replace variable interpolation.
* Syntax fixes (various)

= 1.4.6 =
* Increased memory available to Wordfence to 256M during security scans, configurable in wordfenceConstants.php
* Improved memory logging during security scans. Current memory usage is now shown on the far right of filenames while scans occur.

= 1.4.5 =
* Bugfix - fixed bug that caused Wordfence menu to dissapear.

= 1.4.4 =
* WordPress Multi-site support added. Currently in Beta. Tested with subdomains, not subdirectories, but it should work great on both.
* Main changes are moving menus to the Network Admin area, preventing individual blogs from enabling the plugin and dealing with database prefix issues.

= 1.4.3 =
* Improved diagnistic information on binary and regular API calls for better debugging.
* Changed ticker to only show activity with level < 3

= 1.4.2 =
* Email to send security alerts to is now configured at the same time an API key is entered.
* phpinfo is emailed along with activity log when user requests to send us activity log so that we can see things like PHP max execution time and other relevant data
* Now writing individual files to activity log during security scans for better diagnostics.
* Login security message.
* Updated readme.txt FAQ and description.
* Fixed bug where sites with self signed SSL security certificate never start scan because cert fails security check.
* Increased API curl timeout to 300 for slower hosts that seem affected during URL security scans.

= 1.4.1 =
* This is a major release, please upgrade immediately.
* Only scan files in the WordPress ABSPATH root directory and known WordPress subdirectories. Prevents potentially massive scans on hosts that have large dirs off their wordpress root.
* Don't generate plain SHA hashes anymore because we don't currently use them on the server side for scanning. (Still generates md5's and SHAC)
* No longer do change tracking on files before scans because the change tracking does almost the same amount of work when generating hashes as the actual scan. So just do the scan, which is now faster.
* Updated internal version to 1.2 to use new code on the server side which sends back a list of unknown files rather than known files, which is usually smaller and more network efficient.
* Improved logging in activity log.
* Removed SSL peer verification because some hosts have bad cert config. Connection to our servers is still via SSL. 
* Fixed a few minor issues. Overall you should notice that scans are much faster now.

= 1.3.3 =
* Made real-time server polling more efficient.
* Entering your API key now automatically starts your first scan. Was causing some confusion.
* Link to forums added for free customer support.

= 1.3.2 =
* Reduced the number of database connections that Wordfence makes to one.
* Modified the memory efficient unbuffered queries we use to only use a single DB connection.
* Removed status updates during post and comment scans which prevents interference with unbuffered queries and makes the scans even faster.

= 1.3.1 =
* Fixed a bug where if you have the plugin "secure-wordpress" installed, you can't do a Wordfence scan because it says you have the wrong version. This is because secure-wordpress trashes the $wp_version global variable to hide your version rather than using the filters provided by WordPress. So coded a workaround so that your Wordfence scans will work with that plugin installed.

= 1.3 =
* Minor fix to point to the correct binary API URL on the Wordfence cloud servers.

= 1.2 =
* It is now free to get a Wordfence API key.
* Premium keys include theme and plugin file verification which consumes resources on the Wordfence servers.
* Various bugfixes and performance enhancements.

= 1.1 =
* Initial public release of Wordfence.


