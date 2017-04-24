## JSONBeautifier

This is a Burp Extension for beautifying JSON output.  There exists a [python version](https://portswigger.net/bappstore/showbappdetails.aspx?uuid=ceed5b1568ba4b92abecce0dff1e1f2c) in the BApp Store at the moment.  After some difficulties with Jython I opted to port it to Java.

#### Before
<img src="/img/JSONRaw.PNG"/>

#### After
<img src="/img/JSONBeautified.PNG"/>

### Building
To build a jar file:
```sh
gradle fatJar
```
