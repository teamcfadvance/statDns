<cfscript>
	// instantiate component
	statdns = createobject("component","StatDNSConsumer").init();
	
	writeoutput("Info for www.github.com<br /><blockquote>");
	a = statdns.domain("www.github.com").getHostAddress();  // sets active domain for inquiries and invokes a method
	writeoutput("Host Address: " & a.result & "<br />");
	
	b = statdns.getCanonicalName(); // continues executing against the previously specified domain
	writeoutput("Canonical Name: " & b.result & "</blockquote><br />");
	 
	writeoutput("<hr />Info for www.statdns.net<br /><blockquote>");
	c = statdns.domain("statdns.net").getMX(); // sets a new domain and invokes a method 
	writeoutput("Mail Exchange: " & c.result & "<br />");
	
	d = statdns.getNS(); // executes the newly set domain 
	writeoutput("Name Servers: " & d.result & "</blockquote><br />");
</cfscript>
