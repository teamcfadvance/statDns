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
		 
		c = statdns.domain("").getMX(); // sets a new domain and invokes a method 
		d = statdns.getNS(); // executes the newly set domain 
	</cfscript>


Methods
-------

Initialization methods:

* init() - initializes the component
	*	domain (optional) - string - if specified, sets the active domain against which subsequent methods will be invoked
	*	ipv4 (optional) - string - if specified, sets the active IPV4 address against which subsequent methods will be invoked
	*	ipv6 (optional) - string - if specified, sets the active IPV6 address against which subsequent methods will be invoked
	*	arpa (optional) - string - if specified, sets the active ARPA address against which subsequent methods will be invoked 
	
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
	
	
Data retrieval methods:

Note that both terse and verbose method names are available and may be used; you may prefer one or the other for either brevity or readability.
Invoking these methods without previously setting the data they require, domain(), ipv4(), etc., will throw an exception.

* getA() - getHostAddress() - gets Host Address data for the current domain
	* type (optional) - string - ipv4 / ipv6 - specifies the type of IP data to return; defaults to ipv4
	
* getCERT() - getCertificate() - gets Certificate data for the current domain

* getCNAME() - getCanonicalName() - gets Canonical Name data for the current domain

* getDHCPID() - getDHCPIdentifier() - gets DHCP Identifier data for the current domain

* getDLV() - getDNSSECLookasideValidation() - gets DNSSEC Lookaside Validation data for the current domain

* getDNAME() - getDelegationName() - gets Delegation Name data for the current domain

* getDS() - getDelegationSigner() - gets Delegation Signer data for the current domain

* getHINFO() - getHostInformation() - gets Host Information data for the current domain

* getHIP() - getHostIdentityProtocol() - gets Host Identifiy Protocol data for the current domain

* getKX() - getKeyExchanger() - gets Key Exchanger data for the current domain

* getLOC() - getLocation() - gets Location data for the current domain

* getMX() - getMailExchange() - gets Mail Exchange data for the current domain

* getNAPTR() - getNameAuthorityPointer() - get Name Authority Pointer data for the current domain

* getNS() - getNameServers() - gets Name Servers data for the current domain

* getNSEC() - getNextSecure() - gets Next-Secure data for the current domain

* getNSEC3() - getNextSecureV3() - gets Next-Secure v3 data for the current domain

* getNSEC3Param() - getNextSecureV3Parameters() - gets Next-Secure v3 Parameters data for the current domain

* getOPT() - getOption() - gets Option data for the current domain

* getPTR() - getPointer() - gets Pointer data for the current ARPA address

* getRRSIG() - getResourceRecordsSignature() - gets Resource Records Signature data for the current domain

* getSOA() - getStartOfAuthority() - gets Start of Authority data for the current domain

* getSPF() - getSenderPolicyFramework() - gets Sender Policy Framework data for the current domain

* getSRV() - getServiceLocator() - gets Service Locator data for the current domain

* getSSHFP() - getSSHPublicKeyFingerprint() - gets SSH Public Key Fingerprint data for the current domain

* getTA() - getTrustAuthorities() - getDNSSECTrustAuthorities() - gets DNSSEC Trust Authorities data for the current domain

* getTALINK() - getTrustAnchorLink() - gets Trust Anchor LINK data for the current domain

* getTXT() - getText() - getTextRecord() - gets Text record data for the current domain

* getRPTR() - getReversePointer() - gets Reverse Pointer data for the current ipv4 or ipv6 address
	* type (optional) - string - ipv4 / ipv6 - specifies the type of IP data being passed; defaults to ipv4

