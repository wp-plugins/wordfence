=== Plugin Name ===
Contributors: mmaunder 
Tags: wordpress, security, wordpress security, security plugin, secure, anti-virus, malware, firewall, antivirus, virus, google safe browsing, phishing, scrapers, hacking, wordfence, securty, secrity, secure
Requires at least: 3.3.1
Tested up to: 3.3.2
Stable tag: 1.4.1

Wordfence is a free enterprise class security plugin that includes a firewall and anti-virus scanning for WordPress websites.

== Description ==

[Remember to visit our support forums if you have questions or comments.](http://wordfence.com/forums/)

Wordfence is a free enterprise class security plugin that includes a firewall and anti-virus scanning for WordPress websites.

Wordfence is 100% free. You need to sign up on Wordfence.com to get a free API key.
We also offer a Premium API key that adds additional scanning capabilities. See below for details.

Wordfence:

* Scans core files against repository versions to check their integrity.
* Premium API key also scans themes and plugins against repository versions. This is currently the only difference between free and premium API keys.
* See how files have changed. Optionally repair changed files.
* Scans for signatures of over 44,000 known malware variants.
* Continuously scans for known dangerous malware and phishing URL's in all your comments, posts and files.
* Scans for heuristics of backdoors, trojans and suspicious code.
* Checks the strength of all user and admin passwords.
* Monitor for unauthorized DNS changes.
* Monitor disk space.
* Includes a firewall to block fake Googlebots, malicious scans from hackers and botnets.
* Configure rate limiting based on different types of traffic.
* Choose whether you want to block or throttle users and robots who break your rules.
* Includes login security to lock out brute force hacks and to stop WordPress from revealing info useful to a hacker.
* See all your traffic in real-time, including robots, humans, 404 errors, logins and logouts and who is consuming most of your content.
* A real-time view of all traffic including crawlers, scrapers and shows in depth data on each hit including city level location.

Wordfence is full-featured and constantly updated by our team to incorporate the latest security features and to hunt for the 
newest threats to your WordPress website.

== Installation ==

[Remember to visit our support forums if you have questions or comments.](http://wordfence.com/forums/)

To install Wordfence and start protecting your WordPress website:

1. Install Wordfence automatically or by uploading the ZIP file. 
1. Activate the plugin through the 'Plugins' menu in WordPress.
1. Visit [Wordfence.com to get an API key](http://wordfence.com/)
1. Go to the Wordfence menu option that appears on the left or your site's admin section.
1. Enter your API key and click the button.
1. Wordfence is now activated. Do your first scan which will enable scheduled scanning.
1. Visit the Wordfence options page to enter your email address so that you can receive email alerts.
1. Optionally change your security level or click the advanced options link to see under the hood.
1. Click the "Live Traffic" menu option to watch your site activity in real-time.

== Frequently Asked Questions ==

[Remember to visit our support forums if you have questions or comments.](http://wordfence.com/forums/)

= Why does Wordfence need an API key? =

Wordfence contacts our servers for a variety of reasons. These include: comparing the hashes of your core, theme and plugin files
against the official versions, checking if URL's in your comments, posts and files are on any known list of dangerous URL's, checking
if any of your file signatures match a large list of known malware files, and much more. 

= Will Wordfence slow my site down? =

We have spent a lot of time making sure Wordfence runs very quickly. Wordfence uses its own database
tables and advanced mysql features to ensure it runs as fast as possible. The creators of Wordfence
also run a large scale real-time analytics product and much of the technology and knowledge from
our real-time analytics products is built into Wordfence.

= How often is Wordfence updated? =

Wordfence is continually updated. That is the advantage of scanning using an API key that connects to a
web service. While we do provide updates to the Wordfence plugin frequently and it's important
that you install those updates, our web service is updated even more frequently with known 
security issues that Wordfence will scan for.

= What if I need support? =

All our paid customers receive priority support. Excellent customer service is a key part
of being a Wordfence member.

= Can I disable certain features of Wordfence? =

Yes! Simply visit the Options page, click on advanced options and enable or disable the features you want.

== Screenshots ==

1. The home screen of Wordfence where you can see a summary, manage issues and do a manual scan. 
2. The Live Traffic view of Wordfence where you can see real-time activity on your site.
3. The "Blocked IPs" page where you can manage blocked IP's, locked out IP's and see recently throttled IPs.
4. The basic view of Wordfence options. There is very little to configure other than your alert email address and security level.
5. If you're technically minded, this is the under-the-hood view of Wordfence options where you can fine-tune your security settings.

== Changelog ==
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


