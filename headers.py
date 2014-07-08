import requests,requests.utils
import re,os,sys
import argparse

print '#############################################'
print '####  Headers Anlazyer     ##################'
print '####       @@@@@@          ##################'
print '####    @By Maor T.    ######################'
print '#############################################'
parser = argparse.ArgumentParser(description='Anlyze Headers in Response that could asset during finding vulnerabilites')
parser.add_argument('--url', help='Website address to analyze headers')
parser.add_argument('--export', help='Export findings to .txt file (ie. --export=website')
parser.print_help()
args = vars(parser.parse_args())

if(len(sys.argv) < 2):
    sys.exit()

if args['export']:
    try:
        file = open(args['export']+'.txt', 'w+')
    except IOError:
        print "Error: can\'t find file or read data."
    
url = str(args['url'])+'/<script>alert(0);</script>'
# Set the Verify=False to continue with SSL connections properly
r = requests.get(url,verify=False)

print "\nSTAT ANLYZING.....\n"
print "[ ~~ ] Checking for secuirty Headers..."

# Test For Headers that migrate Attacks
if 'x-frame-options' not in r.headers:
    info = "[ + ] NO ClickJacking Header Protection Found !"
    if args['export']:
        file.write(info+"\n\t\t|_ Missing X-FRAME-OPTIONS Header");
    print info
if 'x-xss-protection' not in r.headers:
    infoXSS = "[ + ] XSS Protection header NOT found !"
    if args['export']:
        file.write("\n"+infoXSS+"\n\t\t|_ Missing X-XSS-Protection Header, thats could lead to XSS in Chrome, IE and Safari!");
    print infoXSS
if 'x-content-secuirty-policy' not in r.headers or 'content-secuirty-policy' not in r.headers or 'x-webkit-csp' not in r.headers:
    infoCSP = "[ + ] No CSP Protection enabled, use content-secuirty-policy to disallow load unsafe resources!"
    if args['export']:
        file.write("\n"+infoCSP+"\n\t\t|_ Missing Content-Secuirty-Policy\n\t\t|_ OR - X-Content-Secuirty-Policy\n\t\t|_ OR - X-Webkit-CSP");
    print infoCSP
if 'access-control-allow-origin' in r.headers:
    if r.headers['access-control-allow-origin'] == '*':
        XHRRe = "[ + ] Unsafe Using CORS, allows sending remote XHR requests."
        if args['export']:
            file.write("\n"+infoCSP+"\n\t\t|_ The header Access-Control-Allow-Origin set as * (=all) which could lead to CORS attack")
        print XHRRe
if 'x-xsrf-token' in r.headers:
    if r.cookies['xsrf-token']:
        Angu = "[ + ] AngularJS Framework CSRF Protection Found !!"
        if args['export']:
            file.write("\n"+Angu+"\n\t\t|_ The Anti-CSRF module in AngularJS Framwork is enable, could be issue to bypass!")
        print Angu

print "[ ~~ ] Checking for Misconfiguration settings in Headers..."

# Test For Senstive Headers
if 'server' in r.headers:
    server = r.headers['server']
    if args['export']:
        file.write("\n"+"[ + ] Application Server Banner Exposed!"+"\n\t\t|_ This is the server banner - "+server+"(could be faked)")
    print "[ + ] Found Server Banner: "+server
if 'x-powered-by' in r.headers:
    version = r.headers['x-powered-by']
    if args['export']:
        file.write("\n[ + ] Application Server Techngloy Information\n\t\t|_ This is the platform version - "+version)
    print "[ + ] Found Technoloy Exposure: "+version
if 'x-aspnet-version' in r.headers:
    aspnet = r.headers['x-aspnet-version']
    if args['export']:
        file.write("\n[ + ] .NET Disclosure of the Version\n\t\t|_ This is the .NET framework version - "+aspnet)
    print "[ + ] Found .NET framework version: "+aspnet
    
# Test for HttpOnly / Secure Attributes
if 'Set-Cookie' in r.headers:
    if 'HttpOnly' not in r.headers['Set-Cookie']:
        if args['export']:
            file.write("\n"+"Cookie not HttpOnly"+"\n\t\t|_ The HttpOnly flag not enable by the server")
        print "[ + ] No HTTPOnly Cookie Setup !"
    if 'Secure' not in r.headers['Set-Cookie']:
        if args['export']:
            file.write("\n"+"Cookie not Secure"+"\n\t\t|_ The Secure flag not enable by the server")
        print "[ + ] No Secure Cookie Setup !"
if 'Cookie' in r.headers:
    if 'HttpOnly' not in r.headers['Cookie']:
        if args['export']:
            file.write("\n"+"Cookie not HttpOnly"+"\n\t\t|_ The HttpOnly flag not enable by the server")
        print "[ + ] No HTTPOnly Cookie Setup !"
    if 'Secure' not in r.headers['Cookie']:
        if args['export']:
            file.write("\n"+"Cookie not Secure"+"\n\t\t|_ The Secure flag not enable by the server")
        print "[ + ] No Secure Cookie Setup !"
        
# Test For WAF Detection
# F5 BIGIP - WAF
# part of the regex goes to W3AF & WAFW00f
prob = 0
if r.status_code == 419:
        prob +=1

if 'Server' in r.headers:
    if 'F5-TrafficShield' in r.headers['Server']:
        prob +=1
        
if 'X-Cnection' in r.headers:
    if re.match('^close$',r.headers['X-Cnection']):
        prob +=1
        
if 'Set-Cookie' in r.headers:
    if re.match('^TS[a-zA-Z0-9]{3,6}=',r.headers['Set-Cookie']):
        prob +=1
    if re.match('^ASINFO=',r.headers['Set-Cookie']):
        prob +=1
        
if 'Cookie' in r.headers:
    if re.match('^TS[a-zA-Z0-9]{3,6}=',r.headers['Cookie']):
        prob +=1
    if re.match('^ASINFO=',r.headers['Set-Cookie']):
        prob +=1
        
if prob > 0:
    print "[ + ] F5 BIG IP WAF Detected !"
    waf_detect = "F5 BIG IP"

# NetScalar Citrix WAF
prob_scalar = 0
if 'Set-Cookie' in r.headers:
    if re.match('^(ns_af=|citrix_ns_id|NSC_)',r.headers['Set-Cookie']):
        prob_scalar +=1
        
if 'Cookie' in r.headers:
    if re.match('^(ns_af=|citrix_ns_id|NSC_)',r.headers['Cookie']):
        prob_scalar +=1

if 'Cneonction' in r.headers:
    if 'close' in r.headers['Cneonction']:
        prob_scalar +=1

if 'nnCoection' in r.headers:
    if 'close' in r.headers['nnCoection']:
        prob_scalar +=1
        
if prob_scalar > 0:        
    print "[ + ] NetScalar (Citrix) WAF Detected !"
    waf_detect = "NetScalar (Citrix)"

# Barckuda WAF
if 'Set-Cookie' in r.headers:
    if re.match('^barra_counter_session=',r.headers['Set-Cookie']):
        print "[ + ] Barckuda WAF Detected !"
        waf_detect = "Barckuda"
    # credit goes to Charlie Campbell (Wafwo00f)
    if re.match('^BNI__BARRACUDA_LB_COOKIE=',r.headers['Set-Cookie']):
        print "[ + ] Barckuda WAF Detected !"
        waf_detect = "Barckuda"

if 'Cookie' in r.headers:
    if re.match('^barra_counter_session=',r.headers['Cookie']):
        print "[ + ] Barckuda WAF Detected !"
        waf_detect = "Barckuda"
    # credit goes to Charlie Campbell (Wafwo00f)
    if re.match('^BNI__BARRACUDA_LB_COOKIE=',r.headers['Cookie']):
        print "[ + ] Barckuda WAF Detected !"
        waf_detect = "Barckuda"
        
# Mod_Secuirty WAF Detection
prob_modsec = 0
if r.status_code == 406:
        prob_modsec +=1 
if 'Mod_Security' in r.text:
        prob_modsec +=1
if prob_modsec > 0:
        print "[ + ] Mod_Security WAF (Apache Model) Detected !"
        waf_detect = "Mod_Security"

# Webknight WAF Detection
if r.status_code == 999:
        print "[ + ] Webknight WAF Detected !"
        waf_detect = "Webknight"

# BinerySec WAF (SaaS Based)
if 'Server' in r.headers:
    if 'BinarySec' in r.headers['Server']:
        print "[ + ] BinarySec WAF Detected !"
        waf_detect = "BinarySec"

# DotDefender WAF (IIS)
if 'X-dotDefender-denied' in r.headers:
    if re.match('^1$',r.headers['X-dotDefender-denied']):
        print "[ + ] dotDefender WAF Detected !"
        waf_detect = "dotDefender"

if re.search('[A-Z0-9]{,4}-[A-Z0-9]{,4}-[A-Z0-9]{,4}-[A-Z0-9]{,4}',r.text):
        print "[ + ] dotDefender WAF Detected !"
        waf_detect = "dotDefender"
        
# Incapsula WAF
if '.incap_ses' in r.cookies:
        print "[ + ] Incapsula WAF Detected !"
        waf_detect = "Incapsula"
if 'visid.' in r.cookies:
        print "[ + ] Incapsula WAF Detected !"
        waf_detect = "Incapsula"

if args['export']:
    file.write("\n----------------------------------------------------\nWeb Application Firewall Detected: " + waf_detect)
