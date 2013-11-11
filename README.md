statDNS API Consumer
====================
CFC to consume the [REST API](http://www.statdns.com/api/) from statdns.com.


Additional Information
----------------------
Some of the available record types referenced below are uncommon.  A full list of DNS records with 
explanations may be found here on the [list of DNS record types](http://en.wikipedia.org/wiki/List_of_DNS_record_types).


Simple Example
--------------
	<cfscript>
		// instantiate component
		statdns = createobject("component","StatDNSConsumer").init();
		
		// verbose method name example
		a = statdns.domain("www.whitehouse.gov").getHostAddress();  // sets active domain for inquiries and invokes a method
		b = statdns.getCanonicalName(); // continues executing against the previously specified domain
		
		writeOutput("Host Address: " & a.result & "<br />"); // outputs simplified results in a comma-separated list
		writeOutput("Canonical Name: " & b.result & "<br />"); // outputs simplified results in a comma-separated list
		
		// note that only those result types matching the original inquiry (A records) 
		// are included in the simplified 'result' value above; full results may be looped below for more verbose info
		writeOutput("Full Results:<br />");
		if(arraylen(a.results)) {
			for(r in a.results) { 
				writeDump(r);
			}
		}
		 
		// terse method name example
		c = statdns.domain("statdns.net").getMX(); // sets a new domain and invokes a method 
		d = statdns.getNS(); // executes the newly set domain 
	</cfscript>
	
	
Response Format
---------------
Response is a standardized struct containing the following keys:

	response = {
			inquiry = { // an echo of the request being processed
				name = "", // typically the domain or ip value for which info is being retrieved
				type = "", // the type of record data requested; this is used when determining how to build the 'result' key below
				class = "" 
			},
			result = "", // convenience value; comma-delimited list of result data values which specifically match the query type
			results = [], // array of raw results
			authoritative = [], // array of entities acting as authoritative sources for the returned data
			timestamp = "", // timestamp of the request
			success = false, // whether the data request was successful; requests which will result in NO data will have this flag set false
			errors = "" // any errors which may have occurred during the call; when response.success key is false, this string will be relevant
	};	

A valid response for the domain www.whitehouse.gov from a call to getHostAddress() with its result formatted as JSON (for display purposes) - notice how only those results whose type matched the inquiry type will be included in the simplified 'result' value:

	{
		"inquiry" : {
			"name" : "www.whitehouse.gov.",
			"class" : "IN",
			"type" : "A"
		},
		"result" : "92.122.189.80,92.122.189.59",
		"results" : [{
				"name" : "www.whitehouse.gov.",
				"data" : "www.whitehouse.gov.edgesuite.net.",
				"datalength" : 34,
				"class" : "IN",
				"ttl" : 3527,
				"type" : "CNAME"
			}, {
				"name" : "www.whitehouse.gov.edgesuite.net.",
				"data" : "www.eop-edge-lb.akadns.net.",
				"datalength" : 25,
				"class" : "IN",
				"ttl" : 827,
				"type" : "CNAME"
			}, {
				"name" : "www.eop-edge-lb.akadns.net.",
				"data" : "a1128.dsch.akamai.net.",
				"datalength" : 20,
				"class" : "IN",
				"ttl" : 227,
				"type" : "CNAME"
			}, {
				"name" : "a1128.dsch.akamai.net.",
				"data" : "92.122.189.80",
				"datalength" : 4,
				"class" : "IN",
				"ttl" : 20,
				"type" : "A"
			}, {
				"name" : "a1128.dsch.akamai.net.",
				"data" : "92.122.189.59",
				"datalength" : 4,
				"class" : "IN",
				"ttl" : 20,
				"type" : "A"
			}
		],
		"authoritative" : [],
		"success" : true,
		"errors" : "",
		"timestamp" : "November, 10 2013 21:03:10 -0600"
	}
	

Methods
-------

__Initialization methods:__  
The following set of methods are chainable, returning the StatDNSConsumer component itself.  

	Example:	
		statdns = createobject("component","StatDNSConsumer").init(); // instantiate component
		
		statdns.domain("www.whitehouse.gov"); // set domain to query
		a = statdns.getHostAddress(); // get A record data
		
		// alternatively, may be chained as:		
		a = statdns.domain("www.whitehouse.gov").getHostAddress();
		

* __init()__ - initializes the component
>	*	Arguments
>		*	domain (optional) - string - if specified, sets the active domain against which subsequent methods will be invoked
>		*	ipv4 (optional) - string - if specified, sets the active IPV4 address against which subsequent methods will be invoked
>		*	ipv6 (optional) - string - if specified, sets the active IPV6 address against which subsequent methods will be invoked
>		*	arpa (optional) - string - if specified, sets the active ARPA address against which subsequent methods will be invoked 
>		*	httptimeout (optional) - numeric - if specified, overrides the default of 60 seconds timeout when making API calls
>	*	Returns
>		*	StatDNSConsumer (this) - _chainable_
	
* __domain()__ - sets the active domain against which methods are invoked
>	*	Arguments
>		*	domain (required) - string - a valid domain name without protocol or path; note that some methods return different information
>			depending on the nature of the domain name; e.g., www.statdns.net may return different information than statdns.net
>	*	Returns
>		*	StatDNSConsumer (this) - _chainable_
>	*	Throws
>		*	InvalidDomain exception if domain value cannot be reliably determined to be a valid format

* __ipv4()__ - sets the active IPV4 address against which methods are invoked
>	*	Arguments
>		*	ipv4 (required) - string - a valid IPV4 address
>	*	Returns
>		*	StatDNSConsumer (this) - _chainable_
>	*	Throws
>		*	InvalidIPv4 exception if ipv4 value cannot be reliably determined to be a valid format

* __ipv6()__ - sets the active IPV6 address against which methods are invoked
>	*	Arguments
>		*	ipv6 (required) - string - a valid IPV6 address
>	*	Returns
>		*	StatDNSConsumer (this) - _chainable_
>	*	Throws
>		*	InvalidIPv4 exception if ipv6 value cannot be reliably determined to be a valid format

* __arpa()__ - sets the active ARPA address against which methods are invoked
>	*	Arguments
>		*	arpa (required) - string - a valid ARPA address
>	*	Returns
>		*	StatDNSConsumer (this) - _chainable_
>	*	Throws
>		*	InvalidARPA exception if arpa value is empty string (no additional validation at this time)
	

__Data retrieval methods:__

Note that both terse and verbose method names are available and may be used; you may prefer one or the other for either brevity or readability.
Invoking these methods without previously setting the data they require, domain(), ipv4(), etc., will throw an exception.

* __getA()__ - __getHostAddress()__ - gets Host Address data for the current _domain_
>	*	Arguments:
>		* type (optional) - string - ipv4 / ipv6 - specifies the type of IP data to return; defaults to ipv4
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods
	
* __getCERT()__ - __getCertificate()__ - gets Certificate data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods

* __getCNAME()__ - __getCanonicalName()__ - gets Canonical Name data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getDHCPID()__ - __getDHCPIdentifier()__ - gets DHCP Identifier data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getDLV()__ - __getDNSSECLookasideValidation()__ - gets DNSSEC Lookaside Validation data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getDNAME()__ - __getDelegationName()__ - gets Delegation Name data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getDS()__ - __getDelegationSigner()__ - gets Delegation Signer data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getHINFO()__ - __getHostInformation()__ - gets Host Information data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getHIP()__ - __getHostIdentityProtocol()__ - gets Host Identifiy Protocol data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getKX()__ - __getKeyExchanger()__ - gets Key Exchanger data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getLOC()__ - __getLocation()__ - gets Location data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getMX()__ - __getMailExchange()__ - gets Mail Exchange data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getNAPTR()__ - __getNameAuthorityPointer()__ - get Name Authority Pointer data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getNS()__ - __getNameServers()__ - gets Name Servers data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getNSEC()__ - __getNextSecure()__ - gets Next-Secure data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getNSEC3()__ - __getNextSecureV3()__ - gets Next-Secure v3 data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getNSEC3Param()__ - __getNextSecureV3Parameters()__ - gets Next-Secure v3 Parameters data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getOPT()__ - __getOption()__ - gets Option data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getPTR()__ - __getPointer()__ - gets Pointer data for the current _ARPA_ address
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the arpa() or init() methods


* __getRRSIG()__ - __getResourceRecordsSignature()__ - gets Resource Records Signature data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getSOA()__ - __getStartOfAuthority()__ - gets Start of Authority data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getSPF()__ - __getSenderPolicyFramework()__ - gets Sender Policy Framework data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getSRV()__ - __getServiceLocator()__ - gets Service Locator data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getSSHFP()__ - __getSSHPublicKeyFingerprint()__ - gets SSH Public Key Fingerprint data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getTA()__ - __getTrustAuthorities()__ - __getDNSSECTrustAuthorities()__ - gets DNSSEC Trust Authorities data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getTALINK()__ - __getTrustAnchorLink()__ - gets Trust Anchor LINK data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getTXT()__ - __getText()__ - __getTextRecord()__ - gets Text record data for the current _domain_
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the domain() or init() methods


* __getRPTR()__ - __getReversePointer()__ - gets Reverse Pointer data for the current _ipv4 or ipv6_ address
>	*	Arguments:
>		* type (optional) - string - ipv4 / ipv6 - specifies the type of IP data being passed; defaults to ipv4
>	*	Returns
>		*	standardized response (struct)
>	*	Throws
>		*	RequiredValueMissing exception if domain has not been set via the ipv4(), ipv6 or init() methods

	

