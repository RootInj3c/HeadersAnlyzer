HeadersAnlyzer
----

HeadersAnlyzer is a small project that help to identify a server weeknes and potential vulnerabilities for pentesting.
The application send one malicous reqest to the server and try to anlyze the response. In addtion, it tries to figure out eat WAF id behiend.

Usage
----

To run the tool:

    python headers.py --url="http://mytarget.com"
  
If you want to export the shell verbrose to txt file you could use the following flag:
    python headers.py --url="http://mytarget.com" --export=MyReport
