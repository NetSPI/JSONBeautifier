## JSONBeautifier

This is a Burp Extension for beautifying JSON output.  There exists a [python version](https://portswigger.net/bappstore/showbappdetails.aspx?uuid=ceed5b1568ba4b92abecce0dff1e1f2c) in the BApp Store at the moment.  After some difficulties with Jython I opted to port it to Java.

### Using
Download the repo > Open Burp > Extender > Extensions > Add > Java > ~/burp/out/artifacts/burp_jar/burp

#### Before
<img src="/img/JSONRaw.PNG"/>

#### After
<img src="/img/JSONBeautified.PNG"/>

### Developing
All development was done in IntelliJ.

In case any changes need to be made make sure to include ~/lib/gson-2.8.0 in File > Project Structure > Libraries > Plus.  

Once gson is added do the following to create the new jar archive. 

File > Project Structure > Artifacts > Plus Sign > Jar > From modules with dependencies > OK and check the Include in project build checkbox.  After this anytime the project builds a .jar archive will be made.
[Thanks Gruber for those instructions](https://github.com/NetSPI/Wsdler/blob/master/README.md#how-to-compile).
