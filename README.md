HeadersAnlyzer
----

HeadersAnlyzer is a small project that help to identify a server weeknes and potential vulnerabilities for pentesting.
The application send one malicous request to the server and try to anlyze the response (Headers, Cookies) to find a vulnerabilites. In addtion, it tries to figure out what WAF is behiend.

WAF Supported:
 * F5 ASM (and TrafficShield)
 * NetScalar (Citrix)
 * Barckuda
 * Mod_Secuirty
 * Webknight
 * BinerySec
 * DotDefender
 * Incapsula

Installtion
----

Use pip to install dependency called requests:

    pip install requests

Then, download this script to you machine and running with Python 2.7.x only.

Usage
----

To run the tool:

    python headers.py --url=http://mytarget.com
  
If you want to export the shell verbrose to txt file you could use the following flag:

    python headers.py --url=http://mytarget.com --export=MyReport

Vulnerabilites Support
----
Currently, the application anlyze the following vulnerabilites:
 * No Secure Attribute
 * No HttpOnly Attribute
 * Banner Server Exposure
 * Technology information about the server
 * Detection of AngularJS CSRF Protection
 * Protection for XSS in IE
 * Weaknees against ClickJacking
 * Weaknees against CSP attacks
 * Weaknees vs. CORS attacks
 
