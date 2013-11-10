statDNS API Consumer
====================

CFC to consume REST API from the statdns.com (http://www.statdns.com/api/)


Simple Example
--------------
	<cfscript>
		// instantiate component
		statdns = createobject("component","StatDNSConsumer").init();
		
		// note that both verbose and short method names are used below
		a = statdns.domain("statdns.net").getHostAddress();  // sets active domain for inquiries and invokes a method
		b = statdns.getCanonicalName(); // continues executing against the previously specified domain
		 
		c = statdns.domain("whitehouse.gov").getMX(); // sets a new domain and invokes a method 
		d = statdns.getNS(); // executes the newly set domain 
	</cfscript>


Methods
-------

__Initialization methods:__

* init() - initializes the component
	*	domain (optional) - string - if specified, sets the active domain against which subsequent methods will be invoked
	*	ipv4 (optional) - string - if specified, sets the active IPV4 address against which subsequent methods will be invoked
	*	ipv6 (optional) - string - if specified, sets the active IPV6 address against which subsequent methods will be invoked
	*	arpa (optional) - string - if specified, sets the active ARPA address against which subsequent methods will be invoked 
	*	httptimeout (optional) - numeric - if specified, overrides the default of 60 seconds timeout when making API calls
	
* domain() - sets the active domain against which methods are invoked
	*	domain (required) - string - a valid domain name without protocol or path; note that some methods return different information
		depending on the nature of the domain name; e.g., www.statdns.net may return different information than statdns.net
	*	Throws exception if domain value cannot be reliably determined to be a valid format

* ipv4() - sets the active IPV4 address against which methods are invoked
	*	ipv4 (required) - string - a valid IPV4 address
	*	Throws exception if domain value cannot be reliably determined to be a valid format

* ipv6() - sets the active IPV6 address against which methods are invoked
	*	ipv6 (required) - string - a valid IPV6 address
	*	Throws exception if domain value cannot be reliably determined to be a valid format

* arpa() - sets the active ARPA address against which methods are invoked
	*	arpa (required) - string - a valid ARPA address
	*	Throws exception if domain value cannot be reliably determined to be a valid format
	
	
__Data retrieval methods:__

Note that both terse and verbose method names are available and may be used; you may prefer one or the other for either brevity or readability.
Invoking these methods without previously setting the data they require, domain(), ipv4(), etc., will throw an exception.

* getA() - getHostAddress() - gets Host Address data for the current _domain_
	* type (optional) - string - ipv4 / ipv6 - specifies the type of IP data to return; defaults to ipv4

	
* getCERT() - getCertificate() - gets Certificate data for the current _domain_


* getCNAME() - getCanonicalName() - gets Canonical Name data for the current _domain_


* getDHCPID() - getDHCPIdentifier() - gets DHCP Identifier data for the current _domain_


* getDLV() - getDNSSECLookasideValidation() - gets DNSSEC Lookaside Validation data for the current _domain_


* getDNAME() - getDelegationName() - gets Delegation Name data for the current _domain_


* getDS() - getDelegationSigner() - gets Delegation Signer data for the current _domain_


* getHINFO() - getHostInformation() - gets Host Information data for the current _domain_


* getHIP() - getHostIdentityProtocol() - gets Host Identifiy Protocol data for the current _domain_


* getKX() - getKeyExchanger() - gets Key Exchanger data for the current _domain_


* getLOC() - getLocation() - gets Location data for the current _domain_


* getMX() - getMailExchange() - gets Mail Exchange data for the current _domain_


* getNAPTR() - getNameAuthorityPointer() - get Name Authority Pointer data for the current _domain_


* getNS() - getNameServers() - gets Name Servers data for the current _domain_


* getNSEC() - getNextSecure() - gets Next-Secure data for the current _domain_


* getNSEC3() - getNextSecureV3() - gets Next-Secure v3 data for the current _domain_


* getNSEC3Param() - getNextSecureV3Parameters() - gets Next-Secure v3 Parameters data for the current _domain_


* getOPT() - getOption() - gets Option data for the current _domain_


* getPTR() - getPointer() - gets Pointer data for the current _ARPA_ address


* getRRSIG() - getResourceRecordsSignature() - gets Resource Records Signature data for the current _domain_


* getSOA() - getStartOfAuthority() - gets Start of Authority data for the current _domain_


* getSPF() - getSenderPolicyFramework() - gets Sender Policy Framework data for the current _domain_


* getSRV() - getServiceLocator() - gets Service Locator data for the current _domain_


* getSSHFP() - getSSHPublicKeyFingerprint() - gets SSH Public Key Fingerprint data for the current _domain_


* getTA() - getTrustAuthorities() - getDNSSECTrustAuthorities() - gets DNSSEC Trust Authorities data for the current _domain_


* getTALINK() - getTrustAnchorLink() - gets Trust Anchor LINK data for the current _domain_


* getTXT() - getText() - getTextRecord() - gets Text record data for the current _domain_


* getRPTR() - getReversePointer() - gets Reverse Pointer data for the current _ipv4 or ipv6_ address
	* type (optional) - string - ipv4 / ipv6 - specifies the type of IP data being passed; defaults to ipv4

	

