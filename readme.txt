=== Wordfence Security ===
Contributors: mmaunder 
Tags: wordpress, security, performance, speed, caching, cache, caching plugin, wordpress cache, wordpress caching, wordpress security, security plugin, secure, anti-virus, malware, firewall, antivirus, virus, google safe browsing, phishing, scrapers, hacking, wordfence, securty, secrity, secure, two factor, cellphone sign-in, cellphone signin, cellphone, twofactor, security, secure, htaccess, login, log, users, login alerts, lock, chmod, maintenance, plugin, private, privacy, protection, permissions, 503, base64, injection, code, encode, script, attack, hack, hackers, block, blocked, prevent, prevention, RFI, XSS, CRLF, CSRF, SQL Injection, vulnerability, website security, WordPress security, security log, logging, HTTP log, error log, login security, personal security, infrastructure security, firewall security, front-end security, web server security, proxy security, reverse proxy security, secure website, secure login, two factor security, maximum login security, heartbleed, heart bleed, heartbleed vulnerability, openssl vulnerability, nginx, litespeed, php5-fpm
Requires at least: 3.3.1
Tested up to: 3.9.1
Stable tag: 5.0.9

Wordfence Security is a free enterprise class security and performance plugin that makes your site up to 50 times faster and more secure. 

== Description ==

Wordfence starts by checking if your site is already infected. We do a deep server-side scan of your source code comparing it to the Official WordPress repository for core, themes and plugins. Then Wordfence secures your site and makes it up to 50 times faster. 

Wordfence Security is 100% free. We also offer a Premium API key that gives you access to our premium support ticketing system at [support.wordfence.com](http://support.wordfence.com/) along with two factor authentication via SMS, country blocking and the ability to schedule scans for specific times.

This is a brief introductory video for Wordfence:

[vimeo http://vimeo.com/70908504]

The following video is an introduction to Falcon Engine, the new caching engine included in Wordfence 5 which will make your site up to 50 times faster
than a standard WordPress installation. 

[vimeo http://vimeo.com/91217997]

Wordfence Security is now Multi-Site compatible and includes Cellphone Sign-in which permanently secures your website from brute force hacks. 

Wordfence Security:

* Includes Falcon Engine, the fastest WordPress caching engine available today. Falcon is faster because it reduces your web server disk and database activity to a minimum.
* Real-time blocking of known attackers. If another site using Wordfence is attacked and blocks the attacker, your site is automatically protected.
* Sign-in using your password and your cellphone to vastly improve login security. This is called Two Factor Authentication and is used by banks, government agencies and military world-wide for highest security authentication. 
* Includes two-factor authentication, also referred to as cellphone sign-in. 
* Scans for the HeartBleed vulnerability - included in the free scan for all users. 
* Wordfence includes two caching modes for compatability and has cache management features like the ability to clear the cache and monitor cache usage. 
* Enforce strong passwords among your administrators, publishers and users. Improve login security.
* Scans core files, themes and plugins against WordPress.org repository versions to check their integrity. Verify security of your source.
* Includes a firewall to block common security threats like fake Googlebots, malicious scans from hackers and botnets.
* Block entire malicious networks. Includes advanced IP and Domain WHOIS to report malicious IP's or networks and block entire networks using the firewall. Report security threats to network owner.
* See how files have changed. Optionally repair changed files that are security threats.
* Scans for signatures of over 44,000 known malware variants that are known security threats.
* Scans for many known backdoors that create security holes including C99, R57, RootShell, Crystal Shell, Matamu, Cybershell, W4cking, Sniper, Predator, Jackal, Phantasma, GFS, Dive, Dx and many many more.
* Continuously scans for malware and phishing URL's including all URL's on the Google Safe Browsing List in all your comments, posts and files that are security threats.
* Scans for heuristics of backdoors, trojans,  suspicious code and other security issues.
* Checks the strength of all user and admin passwords to enhance login security.
* Monitor your DNS security for unauthorized DNS changes.
* Rate limit or block security threats like aggressive crawlers, scrapers and bots doing security scans for vulnerabilities in your site.
* Choose whether you want to block or throttle users and robots who break your security rules.
* Includes login security to lock out brute force hacks and to stop WordPress from revealing info that will compromise security.
* See all your traffic in real-time, including robots, humans, 404 errors, logins and logouts and who is consuming most of your content. Enhances your situational awareness of which security threats your site is facing.
* A real-time view of all traffic including automated bots that often constitute security threats that Javascript analytics packages never show you.
* Real-time traffic includes reverse DNS and city-level geolocation. Know which geographic area security threats originate from.
* Monitors disk space which is related to security because many DDoS attacks attempt to consume all disk space to create denial of service.
* Wordfence Security for multi-site also scans all posts and comments across all blogs from one admin panel.
* WordPress Multi-Site (or WordPress MU in the older parlance) compatible.
* Premium users can also block countries and schedule scans for specific times and a higher frequency.

Wordfence Security is full-featured and constantly updated by our team to incorporate the latest security features and to hunt for the 
newest security threats to your WordPress website.

== Installation ==

To install Wordfence Security and start protecting your WordPress website:

1. Install Wordfence Security automatically or by uploading the ZIP file. 
1. Activate the security plugin through the 'Plugins' menu in WordPress.
1. Wordfence Security is now activated. Go to the scan menu and start your first security scan. Scheduled security scanning will also be enabled.
1. Once your first scan has completed a list of security threats will appear. Go through them one by one to secure your site.
1. Visit the Wordfence Security options page to enter your email address so that you can receive email security alerts.
1. Optionally change your security level or adjust the advanced options to set individual security scanning and protection options for your site.
1. Click the "Live Traffic" menu option to watch your site activity in real-time. Situational awareness is an important part of website security.

To install Wordfence Security on WordPress Multi-Site installations:

1. Install Wordfence Security via the plugin directory or by uploading the ZIP file.
1. Network Activate Wordfence Security. This step is important because until you network activate it, your sites will see the plugin option on their plugins menu. Once activated that option dissapears. 
1. Now that Wordfence is network activated it will appear on your Network Admin menu. Wordfence Security will not appear on any individual site's menu. 
1. Go to the "Scan" menu and start your first security scan. 
1. Wordfence Security will do a security scan all files in your WordPress installation including those in the blogs.dir directory of your individual sites. 
1. Live Traffic will appear for ALL sites in your network. If you have a heavily trafficked system you may want to disable live traffic which will stop logging to the DB. 
1. Firewall rules and login rules apply to the WHOLE system. So if you fail a login on site1.example.com and site2.example.com it counts as 2 failures. Crawler traffic is counted between blogs, so if you hit three sites in the network, all the hits are totalled and that counts as the rate you're accessing the system.

== Frequently Asked Questions ==

[Visit our support website which contains a FAQ and knowledgebase which is more comprehensive and updated frequently.](http://support.wordfence.com/)

= What does Wordfence Security do that other WordPress security plugins don't do? =

* Wordfence Security is the only security plugin that is fully integrated with it's own high speed caching engine to avoid security and caching conflicts. 
* Wordfence Security actually verifies your website source code integrity against the official WordPress repository and shows you the changes. We are the only plugin to do this.
* Wordfence Security provides two-factor authentication (Cellphone Sign-in) for paid members. We're the only plugin to offer this.
* Wordfence Security includes comprehensive protection against DDoS attacks by giving you a performance boost up to 50X and giving you the option to disable XML-RPC among other features. 
* Wordfence Security scans check all your files, comments and posts for URL's in Google's Safe Browsing list. We are the only plugin to offer this very important security enhancement.
* Wordfence Security scans do not consume large amounts of your precious bandwidth because all security scans happen on your web server which makes them very fast.
* Wordfence Security fully supports WordPress Multi-Site which means you can security scan every blog in your Multi-Site installation with one click.
* Wordfence Security includes Two-Factor authentication, the most secure way to stop brute force attackers in their tracks. 

= Does Wordfence Security support Multi-Site installations? =

Yes. WordPress MU or Multi-Site as it's called now is fully supported. Using Wordfence Security you can security scan every blog in your network with one click. If one of your customers posts a page or post with a known malware URL that threatens your whole domain with being blacklisted by Google, we will tell you within a maximum of one hour which is how often scans occur. 

= Will Wordfence Security slow my site down? =

No. Actually it will make your site up to 50X faster when Falcon Engine is enabled, up to 30 times faster with our PHP caching engine and even
without caching Wordfence is extremely fast and uses techniques like caching it's own configuration data to avoid database lookups. Older
versions of Wordfence did incur a slight performance penalty, but we have not only fixed this issue but knocked it out of the park. Wordfence
now makes your site faster than any other caching plugin available!! 

= How often is Wordfence Security updated? =

The Wordfence Security plugin is frequently updated and we update the code on our security scanning servers
more frequently. Our cloud servers are continually updated with the latest known security threats and vulnerabilities so
that we can blog any security threat as soon as it emerges in the wild.

= What if I need support? =

All our paid customers receive priority support. Excellent customer service is a key part
of being a Wordfence Security member. As free or Premium member can visit [support.wordfence.com](http://support.wordfence.com/) and where you will find out knowledgebase. If you're a Premium member you can also open a support ticket.

= Can I disable certain security features of Wordfence Security? =

Yes! Simply visit the Options page, click on advanced options and enable or disable the security features you want.

= What if my site security has already been compromised by a hacker? =

Wordfence Security is the only security plugin that is able to repair core files, themes and plugins on sites where security is already compromised.
However, please note that site security can not be assured unless you do a full reinstall if your site has been hacked. We recommend you only
use Wordfence Security to get your site into a running state in order to recover the data you need to do a full reinstall. A full reinstall is the only
way to ensure site security once you have been hacked. 

= How will I be alerted that my site has a security problem? =

Wordfence Security sends security alerts via email. Once you install Wordfence Security, you will configure a list of email addresses where security alerts will be sent.
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

= Will Wordfence Security protect me against the Timthumb security problem? =

The timthumb security exploit occurred in 2011 and all good plugins and themes now use an updated 
version of timthumb (which the creator of Wordfence Security wrote and donated to the timthumb author) which closes the security hole that
caused the problem. However we do scan for old version of timthumb for good measure to make sure they don't 
cause a security hole on your site. 


== Screenshots ==

1. The home screen of Wordfence Security where you can see a summary, manage security issues and do a manual security scan. 
2. The Live Traffic view of Wordfence Security where you can see real-time activity on your site.
3. The "Blocked IPs" page where you can manage blocked IP's, locked out IP's and see recently throttled IPs that violated security rules.
4. The basic view of Wordfence Security options. There is very little to configure other than your alert email address and security level.
5. If you're technically minded, this is the under-the-hood view of Wordfence Security options where you can fine-tune your security settings.

== Changelog ==

= 5.0.9 =
* Feature: (Premium) Advanced Comment Spam Filter. Checks comment source IP, author URL and hosts and IP's in body against additional spam lists. 
* Feature: (Premium) Check if your site is being Spamvertised i.e. your domain is being included in spam emails. Usually indicates you've been hacked.
* Feature: (Premium) Check if your website IP is generating spam. Checks against spam lists if your IP is a known source of spam.
* Improvement: Cache clearing errors are nown shown with clear explanations. 
* Improvement: Added lightweight stats logging internally in preparation for displaying them on the admin UI in the next release. 
* Fix: If a non-existent user tries to sign in it is not logged in the live logins tab. Fixed.
* Fix: Removed warning "Trying to get property of non-object" that would occur under certain conditions. 
* Fix: Removed call to is_404() which was not having any effect and would issue a warning if debug mode is enabled. 
* Fix: Check if CURL is installed as part of connectivity test.

= 5.0.8 =
* Feature: Support for Jetpack Mobile Theme in Falcon Caching engine. Regular pages are cached, mobile pages are served direct to browser. 
* Improvement: Pages that are less than 1000 bytes will not be cached. The avg web page size in 2014 is 1246,000 bytes. Anything less than 1000 bytes is usually an error. 
* Improvement: Wordfence will now request 128M on hosts instead of 64M where memory in php.ini is set too low. 
* Fix: Wordfence was caching 404's under certain conditions. Fixed. 
* Fix: Nginx/FastCGI users would sometimes receive an error about not being able to edit .htaccess. Fixed. 

= 5.0.7 =
* Feature: Immediately block IP if hacker tries any of the following usernames. (Comma separated list that you can specify on the Wordfence options page)
* Feature: Exclude exact URL's from caching. Specifically, this allows you to exclude the home page which was not possible before. 
* Feature: Exclude browsers or partial browser matches and specific cookies from caching. 
* Fix: Fixed issue where /.. dirs would be included in certain scandir operations. 
* Fix: logHuman function was not analyzing user-agent strings correctly which would allow some crawlers that execute JS to be logged as humans. 
* Fix: Removed ob_end_clean warnings about empty buffers when a human is being logged. 
* Fix: Removed warning in lib/wfCache.php caused by unset $_SERVER['QUERY_STRING'] when we check it. 
* Fix: Fixed "logged out as ''" blank username logout messages. 
* Fix: Improved security of config cache by adding a PHP header to file that we strip. Already secure because we have a .htaccess denying access, but more is better. 
* Fix: Falcon Engine option to clear Falcon cache when a post scheduled to be published in future is published.
* Fix: Fixed Heartbleed scans hanging. 

= 5.0.6 =
* Feature: Prevent discovery of usernames through '?/author=N' scans. New option under login security which you can enable. 
* Fix: Introduced new global hash whitelist on our servers that drastically reduces false positives in all scans especially theme and plugin scans.  
* Fix: Fixed issue that corrupted .htaccess because stat cache would store file size and cause filesize() to report incorrect size when reading/writing .htaccess. 
* Fix: Fixed LiteSpeed issue where Falcon Engine would not serve cached pages under LiteSpeed and LiteSpeed warned about unknown server variable in .htaccess.
* Fix: Fixed issue where Wordfence Security Network won't block known bad IP after first login attempt if "Don't let WordPress reveal valid users in login errors" option is not enabled.
* Fix: Sites installed under a directory would sometimes see Falcon not serving cached docs. 
* Fix: If you are a premium customer and you have 2FA enabled and your key expires, fixed issue that may have caused you to get locked out.
* Improvement: If your Premium API key now expires, we simply downgrade you to free scanning and continue rather than disabling Wordfence. 
* Improvement: Email warnings a few days before your Premium key expires so you have a chance to upgrade for uninterrupted service. 

= 5.0.5 =
* Fix: Removed mysql_real_escape_string because it’s deprecated. Using WP’s internal escape.
* Fix: Wordfence issues list would be deleted halfway through scan under certain conditions. 
* Fix: Connection tester would generate php error under certain conditions. 

= 5.0.4 =
* Feature: We now scan for the infamous heartbleed openssl vulnerability using a non-intrusive scan method safe for production servers. 
* Improvement: We now check if .htaccess is writable and if not we give you rules to manually enable Falcon.
* Improvement: Once Falcon is enabled, if we can’t write to .htaccess, we fall back to PHP based IP blocking. 
* Feature: You can now clear pages and posts from the cache on the list-posts page under each item or on their edit pages next to the Update button.
* Fix: We now support sites who use a root URI but store their files and .htaccess in a subdirectory of the web root. 
* Fix: Added an additional filter to prevent crawlers like Bing who execute javascript from being logged as humans. 
* Fix: Changed the extension of the backup .htaccess to be .txt to avoid anti-virus software alerting on a download with .com extension. [Props to Scott N. for catching this]

= 5.0.3 =
* Removed ability to disable XML-RPC. The feature broke many mobile apps and other remote services. 

= 5.0.2 =
* Fix: Issue that caused users running WordPress in debug mode to see a is_404 warning message.
* Fix: Issue that caused Call to undefined function wp_get_current_user warning.
* Fix: Issue that caused caching to not work on sites using subdirectories. 
* Fix: Issue that caused SQL errors to periodically appear about wfPerfLog table.
* Fix: Issue that caused warnings about array elements not being declared. 

= 5.0.1 =
* To see a video introduction of Falcon Engine included with Wordfence 5, [please watch this video](https://vimeo.com/91217997)
* SUMMARY: This is a major release which includes Falcon Engine which provides the fastest WordPress caching available today. It also includes many other improvements and fixes. Upgrade immediatelly to get a massive performance boost for your site, many new features and fixes. 
* Feature: Falcon Engine provides the fastest caching algorithm for WordPress. Get up to a 50x site speedup now when you use Wordfence. 
* Feature: PHP based caching as an alternative to Falcon.
* Feature: IP, browser and IP range blocking is now done using .htaccess if Falcon Engine is enabled providing a big performance boost.
* Feature: Falcon and PHP caching includes ability to exclude URL patterns from cache along with cache management. 
* Feature: Disable XML-RPC in WordPress to prevent your site from being used as a drone in a DDoS attack. 
* Feature: Option to disable Wordfence cookies from being sent. 
* Feature: Option to start all scans using the remote start-scan option. This may fix some customers who can’t start scans. 
* Feature: Falcon Engine includes the ability to block IP ranges using .htaccess. We take your ranges and convert them into CIDR compatible .htaccess lines that very efficiently block the ranges you’ve specified. Another great performance improvement. 
* Feature: If user disables permalinks we automatically disable Falcon Engine caching. 
* Feature: Before you enable Falcon Engine we make you download a backup of your .htaccess file just in case. 
* Improvement: Real-time traffic monitoring loads asynchronously to provide a faster user experience.
* Improvement: All Wordfence configuration variables are now cached on disk rather than repeatedly looked up on the database providing a big performance improvement. 
* Improvement: Updated browser detection algorithms for new browsers.
* Improvement: Updated country GeoIP database to the April edition.
* Improvement: Improved performance by only loading routines required for logged in users if they have a login cookie. No DB lookup required. 
* Improvement: Added on-off switches to top of live traffic to make it easy to turn on/off. 
* Improvement: Removed marketing message from Wordfence email alerts. 
* Improvement: Added ability to exclude files from scan that match patterns. Multiple excludes using wildcards allowed. 
* Improvement: Improved performance by moving all actions that would only be used by a logged in user to be set up using add_action if the user actually has a login cookie. 
* Fix: Added a throttle to prevent identical email alerts being sent repeatedly. 
* Fix: Changed order of IP blocking and alerting code to prevent multiple email alerts being sent in a race condition. 
* Fix: Cleaned up legacy code including removing all array_push statements. 
* Fix: Added try/catch block to fileTooBig() function when we encounter files that we can’t seek on and that throw an IO error to prevent scans from crashing.
* Fix: Resolved issue that may have caused wfhits table to grow continuously on some sites. 
* Fix: Ensured that runInstall() isn’t called multiple times. 
* Fix: Moved register_activation_hook to only be called if the user has a login cookie and has a likelihood of being actually logged in as admin. Performance improvement. 
* Fix: Added doEarlyAccessLogging routine to move logging before caching so we can have both. 
* Fix: Removed the “update LOW_PRIORITY” sql statement when updating wfHits which was intended to speed up MySQL performance but may have actually caused queries to queue up and slow things down. 
* Fix: Whitelisted IP’s are no longer put through two factor authentication as one would expect. 
* Fix: Changed our wp_enqueue_script calls to add a ‘wf’ prefix to our script names so that another plugin doesn’t cause our scripts to not load. 
* Fix: Removed code that would cause all alerts to be turned on for some users under certain conditions. 
* Fix: Automatically excluding backup files and log files from URL scans to reduce false positives on referring URLs in logs and backups. 

= 4.0.3 =
* Improvement: Added "high sensitivity" scanning which catches evals with other bad functions but may give false positives. Not enabled by default.
* Fix: Removed code that caused error message during scan initialization. 
* Fix: IP to number conversation code had a problem with IP's with a single 0 in them. Bug was introduced in 4.0.2. 
* Fix: Very fast attacks would generate a lot of email alerts due to race condition. Fixed. 


= 4.0.2 =
* Feature: Ability to bulk repair or delete files when cleaning a site.
* Feature: You can now limit the number of emails per hour that Wordfence sends.
* Feature: You can now scan image files as if they are executables when cleaning a site. See the option under scanning options.
* Feature: New connectivity test for wp_remote_post to our servers.
* Feature: New detection for backdoors that were previously missed in scans. 
* Improvement: Added a link to the Wordfence admin URL for a site when an email alert is received.
* Improvement: Removed "buy premium" message from the alert emails which was causing confusion and irritation.
* Improvement: Improved private address detection by making it faster and adding all private subnets, not just RFC1918 nets. 
* Improvement: Switched to wp_remote_get for triggering scans instead of wp_remote_post()
* Improvement: Added some more verbose debugging for scan starts when in debug mode.
* Improvement: No longer include private addresses when checking malware URL's and scanning IP's.
* Improvement: Added code to disable Wordfence if WordPress is installing. 
* Fix: Text change because not all "scan" buttons are blue.
* Fix: Removed URL from wfBrowscapCache.php which was causing false positives during scans.
* Fix: Fixed SQL bug that triggered when we logged a vulnerability scan.
* Fix: IP range blocks where a digit is preceded by a '0' char will no longer generate an error. 
* Fix: The getIP() routine will no longer use the IP closest to a visitor in network topology if that IP is a private address and behind a proxy. 


= 4.0.1 =
* Real-time WordPress Security Network Launched. 
* If another site is attacked and blocks the attacker, your site also blocks the attacker. Shared data among Wordfence sites. 
* See our home page on www.wordfence.com for a live map of attacks being blocked. Then blog about us!!
* Fixed bug where wfBrowscapCache.php is reported as malicious.
* Big improvement in scanning speed and efficiency of URL's and IP addresses.
* Fixed preg_replace() warning by using newer preg_replace_callback() func.


= 3.9.1 =
* Fixed issue that caused Wordfence security to not log 404's.
* Made 404's more visible on the live traffic page. 
* Fixed panel width that was too narrow for WP 3.8 on live traffic and issues pages.
* Report hack attempts to Wordfence Security scanning server for DDoS protection. 
* Remind admin if security alert email is blank and tour is closed.
* Updated links to new Wordfence Security support website at support.wordfence.com.
* Made Wordfence Security paid-users-only message a little more user friendly.

= 3.8.9 =
* Fix: Fixed issue that caused certain Wordfence Security login functions to not work. Was a PHP 5.4 vs older version incompatability issue.
* Updated GeoIP location database to new version for country blocking.
* Fix: Resolved issue that caused the Issues that Wordfence Security found to not be displayed in some cases.
* Updated Wordfence Security to WordPress 3.8 Compatability.

= 3.8.8 =
* Fix: We now truncate the wfHoover table after scans to save disk space on servers with huge numbers of URLs in files.
* Fix: isStrongPasswd function was being called statically but not declared as static.
* Fix: Improved error reporting when we can't connect to Wordfence Security API servers.
* Fix: Fixed code that was causing an error log warning when we read the requested URL.
* Fix: Disable and clear cellphone sign-in if you downgrade to free from paid to prevent lockouts.

= 3.8.7 =
* Fixed issue that caused cellphone sign-in to not work with PHP version 5.4 or greater.
* Fixed conflict with other plugins that also use the Whois PHP library.
* Fixed an unsanitized user-agent string.
* Added new malware signatures for string rot13 heuristics.
* Updated compatibility to 3.7.

= 3.8.6 =
* Fixed issue that caused scheduled scans to run even if disabled.
* Fixed display bug when signin fails.

= 3.8.5 =
* Fixed issue that caused Human traffic to not be logged in Wordfence Security live traffic view. 

= 3.8.4 =
* Removed Wordfence Security .htaccess because it doesn't offer any security functionality and increases incompatibility.
* Fixed spelling errors.
* Added check to see if HTTP_USER_AGENT server variable is defined before using it to suppress large number of warnings on some sites.
* Changed the way we call admin_url to the correct syntax.
* Correctly escaped HTML on error messages.
* Fixed issue that generated non-compliant query string.
* Updated GeoIP database to newest version.

= 3.8.3 =
* Updated GeoIP database for country blocking security.
* Fixed bug in Wordfence Security where we called reverseLookup in wfUtils statically and it's a non-static method. Thanks Juliette. 
* Removed characters that are invalid in an IP address or domain from the Whois facility to improve security.
* Prevent users from creating 1 character passwords to improve security.
* Fixed issue that caused an invalid variable to be used in an error message and improved Wordfence Security temporary file implementation for get_ser/ser_ser functions. Thanks R.P.
* Fixed issue that caused IP to output as integer in status msg. Not security related but display issue.
* Declared Wordfence Security reverseLookup function as static to remove warning.
* Fixed returnARr syntax error in Wordfence Security class.
* Note, there is no Wordfence Security version 3.8.2.

= 3.8.1 =
* Added Cellphone Sign-in (Two Factor Authentication) for paid Wordfence Security members. Stop brute-force attacks permanently! See new "Cellphone Sign-in" menu option.
* Added ability to enforce strong passwords using Wordfence Security when accounts are created or users change their password. See Wordfence Security 'options' page under 'Login Security Options'. 
* Added new backdoor/malware signatures to Wordfence Security scanning including detection for spamming scripts, youtube spam scripts and a new attack shell.
* Fixed issue: Under some conditions, files not part of core or a known theme or plugin would be excluded from a Wordfence Security scan. 
* Fixes from Juliette R. F. Remove warnings for unset variables. Fix options 'save' spinner spinning infinitely on some platforms. Removed redundant error handling code in Wordfence Security. 
* Added ability to downgrade a paid Wordfence Security license to free.

= 3.7.2 =
* Fixed issue that caused locked out IP's to not appear, or to appear with incorrect "locked out until" time. 

= 3.7.1 =
* Moved global firewall, login security and live traffic options to top of options page.
* Made it clear that if you have Wordfence Security firewall disabled, IP's won't be blocked, country blocking won't work and advanced blocking won't work with warnings on each page.

= 3.6.9 =
* Fixed JS error in Wordfence Security that occurs occasionally when users are viewing Wordfence Security activity log in real-time.
* New Feature: Prevent users registering 'admin' username if it doesn't exist to improve security. Recommended if you've deleted 'admin'. Enable on 'options' page. 
* Check if Wordfence Security GeoIP library is already declared for all functions. Fixes Fatal error: Cannot redeclare geoip_country_code_by_name.
* Fixed a Wordfence Security compatibility issue with sites and hosts using Varnish front-end cache to ensure legit users don't get blocked. Added two HTTP no-cache and Expires headers.
* Fixed bug when using Wordfence Security Advanced User-Agent blocking with certain patterns this would appear: Warning: preg_match() [function.preg-match]: Unknown modifier
* Vastly improved speed of Wordfence Security Advanced User-Agent blocking security feature. No longer using regex but still support wildcards using fnmatch()
* We now support usernames with spaces in the list of users to ignore in the live traffic config on 'options' page.
* Improved language in status messages to avoid confusion. Changed "unrecognized files" to "additional files" to describe non-core/theme/plugin files.

= 3.6.8 =
* Fixed bug in Wordfence Security that caused IP range blocking to not block.
* Fixed bug that caused unblocking a permanently blocked IP to work, but not refresh the list. 
* Added usernames to the email you receive when a user is locked out.
* Added a few more status messages for Wordfence Security URL malware scanning.
* Removed the sockets function call from connection testing because some hosts don't allow calls to socket_create()
* Added detection in the Wordfence Security Whois page to check if the server has the fsockopen() function available with helpful message if it's disabled. 
* Whitelisted IP's now override Wordfence Security country blocking and range blocking.
* Removed Bluehost affiliate links for free customers
* Fixed issue that caused scans to crash when checking URLs for malware.
* Fixed issue that caused scans with large numbers of posts that contain the same URL to crash.
* Updated the Wordfence Security GeoIP database for country blocking to newest version.

= 3.6.7 =
* Improved security for Cloudflare customers to prevent spoofing attacks and protect when a hacker bypasses Cloudflare proxies.
* Added clear explanation of what increasing AJAX polling time does on options page.
* Fixed issue with Wordfence Security detecting itself as malware. We messed up the version number in previous release. 

= 3.6.6 =
* Added option to change AJAX polling frequency
* Fixed issue that caused whitelisted IP's to not be whitelisted. 
* Added code that prevents blocking of Wordfence's API server (or Wordfence Security will cease to function)
* Added link at bottom of 'options' page to test connectivity to our API servers.
* Include any CURL error numbers in error reporting.
* Fixed issue that caused IP range blocking to not block access to login page.
* Fixed issue that caused cache files to be flagged as malicious.

= 3.6.5 =
* Fixed Fatal error: func_get_args(): Can't be used as a function parameter.
* This bug affected users using PHP older than 5.3.0

= 3.6.4 =
* Fixed a major javascript bug that snuck in 2 releases ago and has disabled many features for Internet Explorer browsers. 
* Clarified range blocking examples.

= 3.6.3 =
* Fixed 'max_user_connections' issue. 
* Wordfence Security now uses WordPress's WPDB and this halves the number of DB connections Wordfence Security establishes to your DB.
* Wordfence Security is now HyperDB compatible.
* Advanced blocking i.e. Browser and IP Range blocking is now a free feature.
* We no longer disable Live Traffic if we detect a caching plugin. Based on user feedback, apparently live traffic actually works with those plugins.
* Fixed issue that causes site to crash if a conflicting GeoIP library is installed.
* Changed logHuman routine to do a LOW_PRIORITY MySQL update to speed things up.
* Login failure counter is now reset if you send yourself an unlock email so you're not locked out again after 1 failure. 
* The free version of Wordfence Security is now supported with ads at the top of the admin pages. Please visit our sponsors and help keep Wordfence Security free!
* Fixed issue that may cause scans to not be scheduled using the default schedule for new users.
* There was no 3.6.2 release, in case you're wondering about the version skip.

= 3.6.1 =
* Major new release that includes the much asked for IP Range blocking with ISP blocking ability and browser blocking. 
* Added Wordfence Security feature: WHOIS for IP's and Domains. Supports all registries and local rWhois
* Added Wordfence Security feature: Advanced Blocking to block IP ranges and browser patterns.
* Added Wordfence Security feature: WHOIS on live traffic pages.
* Added Wordfence Security feature: network blocking links on live traffic pages. 
* Fixed bug where W3 Total Cache and WP Super Cache cache blocked Wordfence Security pages.
* Added explanation of how caching affects live traffic logging if we detect a caching plugin.
* Fixed AJAX loading to deal with multiple parallel ajax requests. 
* Updated tour to include info on new WHOIS and Advanced Blocking features.
* Changed manual IP blocks to be permanent by default.
* Fixed issue in Wordfence Security that caused live traffic page not to reload when IP is unblocked.
* Modified "How does your site get IP's" config to avoid confusing new users.
* Changed 503 block message to be more helpful with link to FAQ on how to unblock.
* Removed redundant code in wfAPI.php
* Optimized code by moving firewall specific code to execute only if firewall is enabled.
* Fixed issue that caused "last attempted access" to show over 500 months ago.
* Fixed issue that was causing warning in getIP() code.
* Upgraded to Wordfence Security API version 2.6.

= 3.5.3 =
* This is the dev version. Stable is 3.5.2.
* Added detection for "hacked by badi" hack. Check if wp_options has been changed to UTF-7.

= 3.5.2 =
* IP detection is now much more robust. Admins must specify how their site gets IP addresses.
* Fixed issue that would throw Ajax ticker into a hard loop and put load on a server if user is on "options" page and WF can't detect IPs.
* Added support for Cloudflare proxies when getting client's real IP address.
* If we fail to get an IP and then get an IP succesfully, we update the activity log.
* Activity log update in case of successful IP acquisition will warn if we're getting internal RFC1918 IP's e.g. the IP of your firewall.

= 3.5.1 =
* Fixed issue with twentyten, twentyeleven, twentytwelve themes showing up as modified in 3.5.
* Fixed issue with wpdb->prepare throwing warnings. WordPress changed their code and we have now caught up.
* Fixed issue of files containing "silence is golden" showing up as being changed with no executable content. 

= 3.4.5 =
* Fixed security issue of being able to list wordfence Security's own virtual dir on some server configurations.
* Fixed issue of WF using deprecated function which caused warnings or errors on install.
* Added link to security alert mailing list on "Scan" page next to manual start scan button and in tour.

= 3.4.4 =
* Fixed issue that caused scans to not complete.
* Fixed issue that caused scans to launch a large number of child processes due to very short scan timeout.
* Fixed issue that caused websites that don't know their own hostname to not be able to scan.
* Added workaround for a bug in Better WP Security breaking Wordfence Security due to their code overwriting the WP version.
* Optimized the way we calculate max execution time for each process while scanning.

= 3.4.1 =
* Removed wfscan.php script and now using pseudo-ajax calls to fire off scans. Much more reliable.
* Removed visitor.php script and now using pseudo-ajax calls to log human visits.
* Added config option to allow admin to specify max execution time (advanced only!!).
* Fixed issue that caused API calls to fail on MultiSite installs.
* Fixed issue that caused comments to break on MultiSite installs under certain conditions.
* Fixed issue that caused incorrect domain to be shown in live traffic view on multi-site installs.
* Fixed issue where some proxies/firewalls send space delimited IP addresses in HTTP headers and Wordfence Security now handles that.
* Fixed issue that caused Wordfence Security to capture activation errors of other plugins. 
* Geo IP database update to November 7th edition.

= 3.3.7 =
* Upgrade immediately. Fixes possible XSS vulnerability in Wordfence Security "firewall unlock" form.
* Also added rate limiting to max of 10 requests per second to the unlock form.

= 3.3.5 =
* Re-releasing to try and fix an issue with the WordPress plugin distro system.

= 3.3.4 =
* Fixed bug that caused malformed URLs to be sent to scanning server which caused errors on some installations.
* Fixed issue that caused scans to "hang" or stall on larger sites during "Analyzing" phase when we hash files. Sites of arbitrary size can now be scanned.
* Fixed issue that caused "plugin generated X characters of unexpected output" error during install or upgrade.

= 3.3.3 =
* Fixed errors caused by ini_set being disabled on certain servers.
* Removed error logging messages in certain cases because some badly configured hosts write these errors to the web browser.
* Fixed getIP code that was evaluating arrays as strings in some cases.
* Added error logging so that if there is an activation error, the Wordfence Security will display the actual error to you.
* Fixed issue that caused scan to output "Could not get the administrator's user ID." when a user has changed their table prefixes under certain conditions.

= 3.3.2 =
* A complete rearchitecture of Wordfence Security scanning to massively improve performance.
* Our free customers are now 100% back in business. Apologies for the delay, but this was worth the wait.
* Wordfence Security is now 4X faster for both free and paid customers.
* Significantly reduced CPU and memory overhead.
* Significantly reduced network througput when communicating with Wordfence Security scanning servers.
* Big performance improvement on our own scanning servers which allows us to continue to provide Wordfence Security free for the forseeable future.
* Upgraded scanning API to version 2.4
* Upgraded Geo IP database to October version.
* Moved core, theme, plugin and malware scanning into hashing recursive routine for big performance gain.
* Removed need for fileQ in hashing routine for reduction in memory usage and reduction in DB write size.
* Removed send-packet architecture and now processing files locally by fetching comparison data from scanning server instead.
* Removed wfModTracker - old module that is no longer used.
* Malware is now scanned by fetching hash prefixes from WF server instead of sending hashes of every file to our server. Much more efficient.
* Made status messages in summary console a little more user friendly.

= 3.2.7 =
* Fixed dates and times in activity log alert emails and other emails to be in site's local timezone.
* Added advanced country blocking options which allow bypass if a special URL is hit.
* Added warning in options page if alert email is not configured under alert checkboxes.
* Modified scan times to be within 60 minute window after scheduled time to prevent stampede at the top of the hour on our scanning server.
* Fixed bug on Godaddy and a few other hosts where viewing list of files not in the repo caused error. This was caused by posix functions not being supported on Godaddy and some other hosts. 

= 3.2.6 =
* Paid feature: Remote site vulnerability and infection scanning.

= 3.2.5 =
* Moved all attack signatures out of the plugin to prevent Wordfence Security being detected as malicious in a false positive.

= 3.2.4 =
* Improved country blocking to make bulk adding/deleting of countries much easier.
* Fixed bug that caused Google feed fetcher and other Google UA bots to get blocked if blocking of unverified Googlebots was enabled.
* Fixed issue where Locked out users were shown having the same expiry time as Blocked IP's.
* Fixed issue where Locked out users were not shown in the locked out list, but were still locked out if Blocked IP and Locked out expiry was different.
* Improved performance of whitelisting so if whitelisted, all rules are bypassed.
* Fixed issue that caused twentyten and twentyeleven themes to be shown as missing core files if they have been removed and theme scanning is enabled.
* Fixed issue that made it impossible to end the tour for Firefox users.

= 3.2.1 =
* Theme and plugin scanning is now free. Woohoo!
* Added introductory tour for Wordfence Security.
* Upgraded to Wordfence Security scanning API version 2.0 to allow free theme and plugin scanning.
* Fixed two issue with scheduled scanning for premium users that would cause scans to not run or run at wrong times under certain conditions.
* Added feature to view unknown files on system to help clean badly infected systems. See on scanning page in "Tools" under yellow box.
* Fixed blocked countries overflowing their container in the user interface. 
* Fixed case where if user is using MySQL >= 5.1.16 and doesn't have the "drop" privilege, they can't truncate the wfFileQueue table and it could grow uncontrollably.
* Updated to the new Libyan flag.
* Fixed mysql_ping() reconnection to DB generating warnings.
* Fixed issue that caused scans to hang. Wordfence Security now processes smaller batches of files before checking if it needs to fork.
* Security scan for backdoors: "s72 Shell",  "r57 kartal",  "r57shell",  "rootshell",  "r57",  "r57 Mohajer22",  "r57 iFX",  "php backdoor",  "phpRemoteView"
* Security scan for backdoors: "nstview",  "nshell",  "mysql tool",  "nsTView",  "matamu",  "mysql shell",  "load shell",  "ironshell",  "lamashell",  "hiddens shell"
* Security scan for backdoors: "h4ntu shell",  "go shell",  "dC3 Shell",  "gfs sh",  "cybershell",  "c99 w4cking",  "ctt sh"
* Security scan for backdoors: "c99 madnet",  "c99 locus7s",  "c99 PSych0",  "c99",  "c0derz shell",  "accept language",  "Web shell"
* Security scan for backdoors: "aZRaiLPhp",  "SnIpEr SA Shell",  "Safe0ver Shell"
* Security scan for backdoors: "SimShell",  "Rootshell",  "Predator",  "PhpSpy",  "PHPJackal",  "PHANTASMA",  "PHP Shell"
* Security scan for backdoors: "NTDaddy",  "NetworkFileManagerPHP",  "NIX REMOTE WEB SHELL",  "NGH"
* Security scan for backdoors: "NFM",  "Mysql interface",  "NCC Shell",  "MySQL Web Interface",  "MyShell",  "Macker PHPShell"
* Security scan for backdoors: "Loaderz WEB Shell",  "KA uShell",  "KAdot Universal Shell",  "Liz0ziM"
* Security scan for backdoors: "Gamma Web Shell",  "JspWebshell",  "GRP WebShell",  "GFS web shell"
* Security scan for backdoors: "GFS Web Shell",  "Dx",  "DxShell,  "Dive Shell",  "DTool Pro"
* Security scan for backdoors: "Ajax PHP Command Shell",  "Antichat Shell",  "Ayyildiz Shell"
* Security scan for backdoors: "C99 Shell", "C99 madShell",  "CTT Shell",  "CasuS",  "CmdAsp",  "Crystal Shell",  "Cyber Shell" 
* DNS fix from previous release backed out because it's no longer needed. (We temporarily hardcoded an IP)

= 3.1.6 =
* Emergency release to deal with DNS issue.

= 3.1.4 =
* Fixed SQL error in code that checks if IP blockedTime has expired.  Changed column type to signed.
* Added detection of malicious injected titles with scripts or meta redirects.
* Fixed bug introduced in previous release that prevents blocked IP's from being blocked.

= 3.1.2 =
* Fixed permanent IP blocking bug which caused permanently blocked IP's to no longer display in the list after some time, even though there were still blocked. (Incorrect SQL query)
* Fixed "Can't get admin ID" on scan starts for both MU and single site installs.
* Improved status messages for sites with very large numbers of comments.
* Fixed bug that caused sites in subdirectories to not be able to view site config or run the memory test on the Wordfence Security "options" page.
* Fixed database disconnect bug (mysql server has gone away). An additional fix was required to finally squash this bug.
* Removed the code that prevented you from installing Wordfence Security on Windows. Sorry Windows customers!
* Improved scheduling so that it is now more reliable.
* Fixed bug that caused a loop for customers who could not contact the Wordfence Security servers on install.
* Added helpful message if you get the "can't connect to itself" error message with some additional documentation to help solve this issue.
* Improved error reporting when Wordfence Security can't connect to the scanning servers. Now features a helpful explanation rather than a generic message.
* Added Country Geo-Blocking feature for paid customers.
* Added Scan Scheduling feature for paid customers.

= 3.1.1 =
* Added another fix for "mysql server has gone away" error. Wordfence Security now makes sure the DB is still connected and reconnects if not.
* Added new detection for encoded malicious code in files.
* Fixed bug introduced yesterday that prevented permanent blocking of IP's.
* Improved ability to detect if we're running on Windows (but we don't support Windows yet).
* Issue intelligent warning if Wordfence Security can't read base WordPress directory.
* Don't activate Wordfence Security if user is running Windows.
* Cleaned up errors if a file can't be scanned due to permission restrictions.
* Improved reporting of which user scan is running as and how we determined who the admin user is.

= 3.1.0 =
* Changed the way we monitor disk space from % to warning on 20 megs and critical on 5 megs remaining. This deals with very large disks in a more rational way. (Thanks Yael M. and Ola A.)
* We now deal with cases where the $_SERVER variable contains an array instead of string for IP address. It seems that some installations modify the value into an array. (Thanks S.S.)
* The Wordfence Security DB connection now more reliably changes the mysql timeout for the session to prevent "mysql server has gone away" errors. (Thanks Peter A.) 

= 3.0.9 =
* Fixed problem where scan process can't get admin ID.
* Fixed issue that caused permanent IP's to not be permanent.
* Fixed SQL error when calculating if IP block has expired.
* Fixed incorrect calling of is_404 that caused intermittent issues.
* Fixed basedir warnings when scan tries to scan files it does not have access to.
* Fixed warning and incorrect calculation of rows in DB.
* Added ability to get IP from "HTTP_X_REAL_IP" header of a front-end proxy is sending it.
* Fixed warning about HTTPS element not existing in getRequestedURL()
* Fixed problem with paid vs free keys getting confused.
* Fixed error with fetching vulnerability patterns.

= 3.0.8 =
* Fixed bug that caused "Could not get the administrator’s user ID. Scan can’t continue."

= 3.0.7 =
* Fixed bug that caused scan to loop, stop halfway or not start for many sites.
* Fix bug that caused scan to not start on sites with thousands (over 20,000 in one case) users.
* Scan start is now faster for sites with large numbers of users.
* Fix bug that caused scan to get killed when checking passwords on sites with thousands of users.
* Wordfence Security now intelligently determines how to do a loopback request to kick off a scan.
* Scan is no longer called with a cron key in HTTP header but uses a query string value to authenticate itself which is more reliable. 

= 3.0.6 =
* Improved malware and phishing URL detection.
* Upgraded to Wordfence Security API version 1.9
* Fixed issue that caused large files to slow or crash a scan.
* Added workaround for PHP's broken filesize() function on 32 bit systems.
* Added an improved test mode for URL scanner for better unit testing on our end.
* Suppressed warnings issued when a reverse DNS lookup fails.
* Added improved debug output to becomeAdmin() function in scans to help diagnose scans not starting.

= 3.0.5 =
* Fixed "The key used to start a scan has expired." error and added data to help diagnose future issues like this.
* Removed HTTPHeaders from wfHits table which was using a lot of disk space and not used much.
* Removed limiting wfHits table size because it was unreliable.
* We're now limiting wfHits to 20,000 rows and the rows are much smaller. About 2 to 8 megs.
* Fixed bug that could have caused install routine to run repeatedly.
* Fixed typo bug in blocking code that didn't have any impact but was sloppy.
* Changed wfscan.php message when accessed directly to be more helpful.

= 3.0.4 =
* Detects if the Wordfence Security app (not scanner) is short on memory and requests more
* Fixes an issue where scan breaks if all scanning options are disabled

= 3.0.3 =
* Issue that caused all core files to show as missing has been fixed.
* We now handle all API server errors gracefully using exceptions.
* If your installation didn't activate correctly you now get a friendly message.
* Removed unused menu_config.php code.
* The 503 message now tells you why your access to the site has been limited so that admin's can tune firewall rules better.
* We no longer reuse the WordPress wpdb handle because we get better stability with our own connection.

= 3.0.2 =
* Overall this release is a very important upgrade. It drastically reduces memory usage on systems with large files from hundreds of megs to around 8 megs max memory used per scan.
* Moved queue of files that get processed to a new DB table to save memory.
* Reduced max size of tables before we truncate to avoid long DB queries.
* Reduced max size of wfStatus table from 100,000 rows to 1,000 rows.
* Introduced feature to kill hung or crashed scans reliably. 
* Made scan locking much more reliable to avoid multiple concurrent scans hogging resources.
* Debug status messages are no longer written to the DB in non-debug mode.
* Modified the list of unknown files we receive back from the WF scanning servers to be a packed string rather than an array which is more memory efficient.
* Added summary at the end of scans to show the peak memory that Wordfence Security used along with server peak memory.
* Hashes are now progressively sent to Wordfence Security servers during scan to drastically reduce memory usage.
* Upgraded to Wordfence Security server API version 1.8 
* List of hosts that Wordfence Security URL scanner compiles now uses wfArray which is a very memory efficient packed binary structure.
* Writes that WF URL scanner makes to the DB are now batched into bulk inserts to reduce load on DB.
* Fixed bug in wfscan.php (scanning script) that could have caused scans to loop or pick up old data.
* Massively reduced the number of status messages we log, but kept very verbose logging for debug mode with a warning about DB load.
* Added summary messages instead of individual file scanning status messages which show files scanned and scan rate.
* Removed bin2hex and hex2bin conversions for scanning data which were slow, memory heavy and unneeded.
* Wordfence Security database class will now reuse the WordPress database handle from $wpdb if it can to reduce DB connections.

= 2.1.5 =
* Fixed bug that caused WF to not work when certain DB caching plugins are used and override wpdb object.
* Fixed Wordfence Security so activity log only shows our own errors unless in debug mode.
* Wordfence Security now deletes all it's tables and deletes all saved options when you deactivate the plugin.
* Removed all exit() on error statements. Critical errors are handled more gracefully by writing to the log instead.
* Fixed a bug that would cause a database loop until running out of memory under certain error conditions.
* Suppressed useless warnings that occur in environments with basedir set or where functions are disabled for security reasons.
* Removed redundant check that executed on every request and put it in activation instead.
* If serialization during scan breaks, exit gracefully instead of looping.
* Disk space in log is now shown as Gigabytes and formatted nicely.
* Removed wdie() function which is a little obnoxious. Writing to WF error log instead.
* Fixed bug where a non-empty but useless HTTP header can break getIP() function.
* Added useful data to error output if getIP() tells you it can't work on your system. 
* Removed option to start scan in debug because it's no longer possible with a forked scan.
* Removed option to test process running time on a system because it breaks on most systems and confuses customers.
* Database connection errors no longer call die() but log an error instead in a way that removes the risk of a logging loop.
* Removed dropAll.php script because we now clean up tables on deactivate and it's not needed.
* Updated readme to show that we support 3.4. 

= 2.1.4 =
* Fixed registered users not appearing in live traffic.
* Fixed temp file deletion bug that caused warnings and loops.
* Fixed issue that caused warning about WORDFENCE_VERSION
* Fixed Wordfence Security admin area not working under SSL
* Fixed bug that caused IP addresses of clients to be misinterpreted if there are multiple addresses from chained proxies. 
* Now stripping port numbers from IP's which we weren't doing before.
* Added check for validity of IP's and report fatal error if it fails because this could lock users out.
* Improved error reporting including fixing an out of memory error when a specific error condition arose in wfConfig::set()
* Changed order of tmp dirs to be wordfence/lib protected dir first and then system temp dir. Added uploads as tmp dir for last resort.
* Malware URL's are now marked in red in alerts so it's obvious what the offending URL in a file is.

= 2.1.3 =
* Added fix for hosts that have max_allowed_packet set too small. We will write a temp file to disk instead if possible.
* Increased size of status column to 1000 chars

= 2.1.2 =
* Fixed issue with scan scheduling that caused a loop
* Fixed issue that caused version constant to not be included in scans

= 2.1.1 =
* Added ability to permanently block IP's
* Added ability to manually block IP's
* Made Wordfence Security more memory efficient, particularly the forking process.
* Fixed issue that caused WF to not work on databases with blank passwords.
* Wordfence Security now stops execution of a DB connection error is encountered.
* Clear cron jobs if Wordfence Security is uninstalled.
* Enabled hourly cron for Wordfence security network.
* Wordfence Security now works if your server doesn't have openssl installed
* Wordfence Security now works even if you don't have CURL
* Fixed visitor logging so it works with HTTPS websites.
* Alert emails now contain filenames in each alert description.
* Users with weak passwords alerts now contain the username in the email.
* Upgraded API to 1.7.
* Fixed issue that caused DISALLOW_FILE_MODS to make WF menu disappear.
* Modified wfDB to deal with very large queries without exceeding max_allowed_packet
* Fixed issue that broke ability to see file changes and repair files in security scan results.

= 2.1.0 =
* Fixed scans hanging on Dreamhost and other hosts.
* Made Wordfence Security more memory efficient.
* Wordfence Security scans are now broken into steps so we can scan a huge number of files, posts and comments.
* Alert emails now include IP address, hostname lookup and geographic location (city if available).
* Improved security scan locking. No longer time based but uses flock() if on unix or time on Windows.
* Suppressed warnings that WF was generating.
* Improve handling of non-standard wp-content directories.
* Fix restored files were still showing as changed if they contained international characters.
* Improve permission denied message if attempting to repair a file.
* Fixed problem that caused scans to not start because some hosts take too long to look up their own name.
* Fixed issue with Wordfence Security menu that caused it to not appear or conflict with other menus under certain conditions.
* Upgraded to security API version 1.6
* Improved geo lookup code for IP's to improve security. 
* Fixed debug mode output in live status box - coloring was wrong.
* Added ajax status message to WF admin pages.
* Fixed colorbox popup so that it doesn't jump around on refresh.

= 2.0.7 =
* Fixed CSS bug that changed plugins page layout in admin area
* Added memory benchmark utility.
* Added process runtime benchmark utility.
* Added ability to security scan in debug mode which accesses the scan app directly.

= 2.0.6 =
* Added IP whitelisting including ability to whitelist ranges that are excluded from firewall and login security measures.
* RFC1918 private networks and loopback address is automatically whitelisted to prevent firewall or login security blocking internal routers and proxy servers, internal firewalls and internal users.
* Added WORDFENCE_VERSION constant to improve version lookup performance.
* Fixed issue that caused security scans to not start and humans to not be logged in live traffic. Wordfence Security makes security scan script and visitors script executable on install or upgrade now.
* Fixed bug that caused disk space scanning to still show an issue found in security scan summary even when user chooses to ignore the security issue.
* Made disk space thresholds 1 and 1.5% space remaining because many hosts have very large disks where 1% is gigabytes.
* Made wordfence Security database handle cache deal with concurrent connections to different databases.
* Improved Wordfence Security database library's error reporting.
* Improved performance when Wordfence Security looks up it's own version during security scans and other operations.
* Removed three rules in base wordfence Security htaccess that could cause 500 errors on servers that don't allow these options to be overridden. Does not affect htaccess security because we inherit the base htaccess and still protect our lib/ directory with our own htaccess.

= 2.0.5 =
* If your plugin PHP files are viewable by the world, we now give you a detailed warning on the seriousness of this security threat with ability to view the offending .htaccess files.
* Added a debug mode in options for very verbose logging and marking errors in red.
* Added more logging for the process that starts the security scan.
* Ability to securely view the entire activity log added.
* Using plugin version in all CSS URL's instead of API version.
* Activity log microtime is more accurate now.
* Fixed bug that would cause security scanning of PHP files with base64 content to stop.

= 2.0.4 =
* Now security scanning all comments, posts and pages on multi-site installation for malware and phishing URL's. Significant security enhancement.
* Improved messages on multisite when a bad comment or post is found.
* Fixed bug that caused paid users to not be able to activate their premium key.
* Made upgrade process much friendlier. 
* Got rid of GeSHi syntax highlighting because it segfaults and is resource intensive. Using built in PHP highlighting instead.
* Message asking you to configure an alert email address only appears for 3 pageviews after plugin activation so it's less irritating.
* Fixed bug for MU users that caused WF to tell you that your WF schema is missing and you need to reactivate. 
* Fixed bug that caused malware URL security scanner to not work for MU users.

= 2.0.3 =
* Removed unbuffered queries and switched to conventional queries that are memory efficient for better stability.
* Made security scanning large numbers of URL's contained in things like awstats log files extremely memory efficient and way faster.
* Removed alerts about unknown files in core directory if they belong to an older wordpress version and are unchanged.
* Other performance improvements like using strpos instead of strstr.
* Moved "scan files outside base dir" option to be in correct place on config page.

= 2.0.2 =
* Fixed plugin upgrades so that css and scripts are not cached across versions.

= 2.0.1 =
* Improved security scanning for specific attacks being used in the PHP-CGI vulnerability ( CVE-2012-1823)
* API keys no longer required. WF fetches a temporary anonymous API key for you on activation.
* Added real-time activity log on scan page.
* Added real-time summary updates on scan page.
* Fixed ability to view files that have symlinks in path.
* Added message to configure alert email address for multi-site and single site installs on activation.
* Disabled firewall security rules by default because most sites don't need them.
* Disabled blocking of fake googlebots except for high security levels to prevent users who like to pretend they're googlebot from blocking themselves.
* Geshi the syntax highlighter now asks for more memory before running.
* Fixed bug that caused scan to hang on very large files.
* Added an index to wfStatus to make it faster for summary statuses
* Removed multisite pre-activation check to make activation more reliable on multisite installs.
* Better problem reporting if you trashed your Wordfence Security schema but the plugin is still installed.

= 1.5.6 =
* Removed use of nonces and purely using 30 minute key for unlocking emails.
* Fixed bug that caused admin emails to not get emailed when requesting unlocking email.
* Fixed minor issue with undefined array in issues loop.

= 1.5.5 =
* Added ability for admin's to unlock login and unblock their IP addresses if they're accidentally locked out by the firewall or login security. Uses two security tokens to prevent abuse.
* Admins can now also disable firewall and login security from the unlock-me email, just in case of emergency.
* Made advanced security options visible so you know they exist.
* Fixed dns_get_record() function not existing bug on Windows sytems pre PHP 5.3.0. Was causing scans to hang.
* Increased login lockout defaults to be much higher which still protects against brute force hacks.
* Removed CURLOPT_MAXREDIRS in curl to avoid safe mode warnings.
* Fixed ability to view and diff files on blogs installed in subdirectories.
* Fixed ability to see individual IP hits on subdir sites.
* Plugin and theme update messages now include links to the upgrade page.
* Removed the link on the login form that mentions the site is protected by Wordfence Security.
* Changed lockout defaults to be much higher.
* Added options for higher number of failures before lockout in options page for configurable login security.
* Now including plugin version in the activity log when the admin chooses to email it to us for debugging.

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
* Increased memory available to Wordfence Security to 256M during security scans, configurable in wordfenceConstants.php
* Improved memory logging during security scans. Current memory usage is now shown on the far right of filenames while scans occur.

= 1.4.5 =
* Bugfix - fixed bug that caused Wordfence Security menu to dissapear.

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
* This is a major release of Wordfence Security, please upgrade immediately.
* Only scan files in the WordPress ABSPATH root directory and known WordPress subdirectories. Prevents potentially massive scans on hosts that have large dirs off their wordpress root.
* Don't generate plain SHA hashes anymore because we don't currently use them on the server side for scanning. (Still generates md5's and SHAC)
* No longer do change tracking on files before scans because the change tracking does almost the same amount of work when generating hashes as the actual scan. So just do the scan, which is now faster.
* Updated internal version to 1.2 to use new code on the server side which sends back a list of unknown files rather than known files, which is usually smaller and more network efficient.
* Improved logging in activity log.
* Removed SSL peer verification because some hosts have bad cert config. Connection to our servers is still via SSL to enhance security. 
* Fixed a few minor issues. Overall you should notice that scans are much faster now.

= 1.3.3 =
* Made real-time server polling more efficient.
* Entering your API key now automatically starts your first scan. Was causing some confusion.

= 1.3.2 =
* Reduced the number of database connections that Wordfence Security makes to one.
* Modified the memory efficient unbuffered queries we use to only use a single DB connection.
* Removed status updates during post and comment scans which prevents interference with unbuffered queries and makes the scans even faster.

= 1.3.1 =
* Fixed a bug where if you have the plugin "secure-wordpress" installed, you can't do a Wordfence Security scan because it says you have the wrong version. This is because secure-wordpress trashes the $wp_version global variable to hide your version rather than using the filters provided by WordPress. So coded a workaround so that your Wordfence Security scans will work with that plugin installed.

= 1.3 =
* Minor fix to point to the correct binary API URL on the Wordfence Security cloud servers.

= 1.2 =
* It is now free to get a Wordfence Security API key.
* Premium keys include theme and plugin file security verification which consumes resources on the Wordfence Security servers.
* Various bugfixes and performance enhancements.

= 1.1 =
* Initial public release of Wordfence Security Plugin.

== Upgrade Notice ==
= 3.1.1 =
Upgrade immediately. Fixes bug introduced in last release that broke permenent IP blocking.

= 3.0.9 =
Upgrade immediately. Fixes two security critical bugs: Could not get admin ID bug and permanent IP blocks not staying permanent. 

= 3.0.6 =
Upgrade immediately. Improves malware URL detection by 20% or more to improve security.

= 3.0.3 =
Upgrade immediately. This release fixes an issue that caused Wordfence Security to show all your core files
missing under certain conditions. It was usually caused by high load on our scanning server and the
plugin not handling an error condition halfway through the scan correctly.

= 3.0.2 =
Upgrade immediately. This release drastically reduces memory, reduces new DB connections created by 
Wordfence Security to zero (we simply reuse the WordPress DB handle), reduces the number of DB queries to 
about 1% of the previous version by removing unneeded status messages and fixes a bug that 
could cause Wordfence Security to launch multiple concurrent scans that can put high load on your system.
This is a critical release. Upgrade immediately.
