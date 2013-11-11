<cfcomponent hint="Consumes the statdns.com API">
	
	<cfscript>
		variables.config = {
			api = {
				name = "StatDNS API",
				baseuri = "http://api.statdns.com/"
			}, 
			httptimeout = 60 // default http request timeout in seconds
		};
		
		variables.instance = { 
			domain = "",
			ipv4 = "",
			ipv6 = "",
			arpa = "" 
		};
	</cfscript>
	
	<!--- INITIALIZATION/SETUP METHODS --->
		
	<cffunction name="init" access="public" output="false" returntype="StatDNSConsumer">
		<cfargument name="domain" type="string" required="false">
		<cfargument name="ipv4" type="string" required="false">
		<cfargument name="ipv6" type="string" required="false">
		<cfargument name="arpa" type="string" required="false">
		<cfargument name="httptimeout" type="numeric" required="false">
		
		<cfscript>
			clear();
			
			if(structkeyexists(arguments,"ip")) { // attempt auto-detect if arbitrary ip is passed 
				if(isIPv4(arguments,ip)) { 
					ipv4(arguments.ip);
				}
				else if(isIPv6(arguments.ip)) { 
					ipv6( arguments.ip);
				}
			}
	
			if(structkeyexists(arguments,"domain") and len(arguments.domain)) { 
				domain(arguments.domain);
			}
			if(structkeyexists(arguments,"ipv4") and len(arguments.ipv4)) { 
				ipv4(arguments.ipv4);
			}
			if(structkeyexists(arguments,"ipv6") and len(arguments.ipv6)) { 
				ipv6(arguments.ipv6);
			}
			if(structkeyexists(arguments,"arpa") and len(arguments.arpa)) { 
				arpa(arguments.arpa);
			}			
			if(structkeyexists(arguments,"httptimeout")) { // override default timeout for http requests
				variables.config.httptimeout = arguments.httptimeout;
			}
			return this;
		</cfscript>
		
	</cffunction>	

	<cffunction name="clear" access="public" output="false" returntype="void" hint="Clears all instance variables">
		
		<cfscript>
			// clear existing values 
			variables.instance = { 
				domain = "",
				ipv4 = "",
				ipv6 = "",
				arpa = ""
			};
		</cfscript>
		
	</cffunction>

	<cffunction name="domain" access="public" output="false" returntype="StatDNSConsumer" hint="Sets the domain name for the active query">
		<cfargument name="domain" type="string" required="true" hint="The domain name, minus protocol and path">
		
		<cfscript>
			var extracteddomain = extractDomain(arguments.domain);
			if(not isValidDomain(extracteddomain)) {
				throw(type="InvalidDomain",message="The value #arguments.domain# is not a valid domain string");
			}
			variables.instance.domain = arguments.domain;
			return this;
		</cfscript>
		
	</cffunction>

	<cffunction name="ipv4" access="public" output="false" returntype="StatDNSConsumer" hint="Sets the IPv4 value for the active query">
		<cfargument name="ipv4" type="string" required="true" hint="A valid IPv4 value">
		
		<cfscript>
			if(not isIPv4(arguments.ipv4)) {
				throw(type="InvalidIPv4",message="The value #arguments.ipv4# is not a valid IPv4 address");
			}
			variables.instance.ipv4 = arguments.ipv4;
			return this;
		</cfscript>
		
	</cffunction>

	<cffunction name="ipv6" access="public" output="false" returntype="StatDNSConsumer" hint="Sets the IPv6 value for the active query">
		<cfargument name="ipv6" type="string" required="true" hint="A valid IPv6 value">
		
		<cfscript>
			if(not isIPv4(arguments.ipv6)) {
				throw(type="InvalidIPv6",message="The value #arguments.ipv6# is not a valid IPv6address");
			}
			variables.instance.ipv6 = arguments.ipv6;
			return this;
		</cfscript>
		
	</cffunction>

	<cffunction name="arpa" access="public" output="false" returntype="StatDNSConsumer" hint="Sets the ARPA address value for the active query">
		<cfargument name="arpa" type="string" required="true" hint="A valid ARPA value">
		
		<cfscript>
			if(not len(arguments.arpa)) { // TODO!: need format validation for ARPA
				throw(type="InvalidARPA",message="The value #arguments.arpa# is not a valid ARPA address");
			}
			variables.instance.arpa = arguments.arpa;
			return this;
		</cfscript>
		
	</cffunction>
	
	<!--- API CONSUMPTION METHODS --->		

	<cffunction name="getA" access="public" output="false" returntype="struct" hint="Gets Host Address record data for the current domain">
		<cfargument name="type" type="string" required="false" default="ipv4" hint="The address type to return">
		
		<cfscript>
			var response = "";  
			var accesspoint = "a"; // aaaa for ipv6 calls
			
			requireValue("domain");

			if(arguments.type eq "ipv6") {
				accesspoint = "aaaa";
			}
			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/#accesspoint#");
			return formatResponse(response); 
		</cfscript>
		
	</cffunction>

	<cffunction name="getCERT" access="public" output="false" returntype="struct" hint="Gets Certificate record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/cert");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getCNAME" access="public" output="false" returntype="struct" hint="Gets Canonical Name record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/cname");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getDHCPID" access="public" output="false" returntype="struct" hint="Gets DHCP Identifier record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/dhcid");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getDLV" access="public" output="false" returntype="struct" hint="Gets DNSSEC Lookaside Validation record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/dlv");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getDNAME" access="public" output="false" returntype="struct" hint="Gets Delegation Name record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/dname");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getDNSKEY" access="public" output="false" returntype="struct" hint="Gets DNS Key record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/dnskey");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getDS" access="public" output="false" returntype="struct" hint="Gets Delegation Signer record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/ds");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getHINFO" access="public" output="false" returntype="struct" hint="Gets Host Info record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/hinfo");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getHIP" access="public" output="false" returntype="struct" hint="Gets Host Identity Protocol record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/hip");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getIPSECKEY" access="public" output="false" returntype="struct" hint="Gets IPSec Key record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/ipseckey");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getKX" access="public" output="false" returntype="struct" hint="Gets Key eXchanger record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/kx");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getLOC" access="public" output="false" returntype="struct" hint="Gets Location record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/loc");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getMX" access="public" output="false" returntype="struct" hint="Gets Mail Exchang record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/mx");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getNAPTR" access="public" output="false" returntype="struct" hint="Gets Name Authority Pointer record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/naptr");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getNS" access="public" output="false" returntype="struct" hint="Gets Name Server record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/ns");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getNSEC" access="public" output="false" returntype="struct" hint="Gets Next-Secure record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/nsec");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getNSEC3" access="public" output="false" returntype="struct" hint="Gets Next-Secure v3 record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/nsec3");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getNSEC3Param" access="public" output="false" returntype="struct" hint="Gets Next-Secure v3 Paramter data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/nsec3param");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getOPT" access="public" output="false" returntype="struct" hint="Gets Option record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/opt");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getPTR" access="public" output="false" returntype="struct" hint="Gets Pointer record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("arpa");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/ptr");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getRRSIG" access="public" output="false" returntype="struct" hint="Gets Resource Records Signature record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/rrsig");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getSOA" access="public" output="false" returntype="struct" hint="Gets Start of Authority record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/soa");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getSPF" access="public" output="false" returntype="struct" hint="Gets Sender Policy Framework record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/spf");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getSRV" access="public" output="false" returntype="struct" hint="Gets Service Locator record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/srv");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getSSHFP" access="public" output="false" returntype="struct" hint="Gets SSH Public Key Fingerprint record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/sshfp");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getTA" access="public" output="false" returntype="struct" hint="Gets DNSSEC Trust Authorities record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/ta");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getTALINK" access="public" output="false" returntype="struct" hint="Gets Trust Anchor LINK record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/talink");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getTLSA" access="public" output="false" returntype="struct" hint="Gets TLSA record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/tlsa");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>

	<cffunction name="getTXT" access="public" output="false" returntype="struct" hint="Gets Text record data for the current domain">
		
		<cfscript>
			var response = ""; 
			
			requireValue("domain");

			response = httpGet(uri="#variables.config.api.baseuri##variables.instance.domain#/txt");
			return formatResponse(response);
		</cfscript>
		
	</cffunction>	

	<cffunction name="getRPTR" access="public" output="false" returntype="struct" hint="Gets Reverse Pointer record data for the current domain">
		<cfargument name="type" type="string" required="false" default="ipv4" hint="The address type for which to perform lookup">
		
		<cfscript>
			var response = "";
			
			if(not listfindnocase("ipv4,ipv6",arguments.type)) {
				arguments.type = "ipv4";
			}   
			
			if(arguments.type eq "ipv4") {
				requireValue("ipv4");
				response = httpGet(uri="#variables.config.api.baseuri#x/#variables.instance.ipv4#");
				return formatResponse(response); 
			}
			else {
				requireValue("ipv6");
				response = httpGet(uri="#variables.config.api.baseuri#x/#variables.instance.ipv6#");
				return formatResponse(response); 
			}
		</cfscript>
		
	</cffunction>
	
	
	<!--- PRIVATE METHODS --->

	<cffunction name="httpGet" access="private" output="false" returntype="struct" hint="Wrapper for cfhttp calls">
		<cfargument name="uri" type="string" required="true">
		
		<cfset var response = "">
		
		<cfhttp url="#arguments.uri#" method="get" result="response" redirect="true" throwonerror="false" timeout="#variables.config.httptimeout#">
		<cfset response.uri = arguments.uri>
		
		<cfreturn response>
		
	</cffunction>

	<cffunction name="formatResponse" access="private" hint="Returns a formatted response from the various api calls" output="no" returntype="struct">
		<cfargument name="httpresponse" required="true" type="struct" hint="The full response object from a cfhttp call">
		
		<cfscript>		
			var h = arguments.httpresponse; 
			var response = {
					inquiry = {
						name = "",
						type = "",
						class = ""
					},
					results = [], // array of raw results
					result = "", // convenience value; comma-delimited list of result data values which specifically match the query type
					authoritative = [], // array of entities acting as authoritative sources for the returned data
					timestamp = "", // timestamp of the request
					success = false, 
					errors = ""
			};			
			
			if(listfirst(h.statuscode," ") eq 200) {
				if(isjson(h.filecontent)) {
					response.success = true;
					response.timestamp = now();
					local.fc = deserializejson(h.filecontent);
					if(structkeyexists(fc,"question") and isarray(fc.question)) {
						if(arraylen(fc.question)) {
							response.inquiry.name = fc.question[1]["name"];
							response.inquiry.type = fc.question[1]["type"];
							response.inquiry.class = fc.question[1]["class"];
						}
					}
					if(structkeyexists(fc,"authority") and isarray(fc.authority)) {
						if(arraylen(fc.authority)) {
							for(local.f in fc.authority) {
								local.a = {
									name = local.f["name"],
									type = local.f["type"],
									class = local.f["class"],
									ttl = local.f["ttl"],
									data = local.f["rdata"],
									datalength = local.f["rdlength"]
								}
								arrayappend(response.authoritative,local.a);
							}							
						}						
					}
					if(structkeyexists(fc,"answer") and isarray(fc.answer)) {
						if(arraylen(fc.answer)) {
							for(local.f in fc.answer) {
								local.a = {
									name = local.f["name"],
									type = local.f["type"],
									class = local.f["class"],
									ttl = local.f["ttl"],
									data = local.f["rdata"],
									datalength = local.f["rdlength"]
								}
								arrayappend(response.results,local.a);
								if(local.a.type eq response.inquiry.type) {
									response.result = listappend(response.result,local.a.data);
								}
							}							
						}						
					}
					else {
						response.success = false;
						response.errors = "No data was returned for the specified value";
					}
				}
			}
			else {
				response.errors = "The api call to #h.uri# failed with a status code of #h.statuscode#";
			}
			
			return response;
		</cfscript>

	</cffunction>

	<cffunction name="requireValue" access="private" output="false" returntype="void" hint="Validates required data exists for the requested operation">
		<cfargument name="value" type="string" required="true" hint="The instance variable name to check">
		
		<cfscript>
			if(not len(variables.instance[value])) {
				throw(type="RequiredValueMissing",message="The requested operation requires a valid #arguments.value# value to be set");
			} 
		</cfscript>
		
	</cffunction>

	<cffunction name="isIPv4" access="private" hint="Returns whether or not the passed value is a valid IPv4 address" output="no" returntype="boolean">
		<cfargument name="ip" required="true" type="string">
		
		<!--- http://answers.oreilly.com/topic/318-how-to-match-ipv4-addresses-with-regular-expressions/ --->
		<cfscript>
			if (refind("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",arguments.ip)) {
				return true;
			}
			else {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction name="isIPv6" access="private" hint="Returns whether or not the passed value is a valid IPv6 address" output="no" returntype="boolean">
		<cfargument name="ip" required="true" type="string">
		
		<!--- http://regexlib.com/REDetails.aspx?regexp_id=2690 --->
		<cfscript>
			if (refindnocase("(^\d{20}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})){3}$)|(^((:[a-fA-F0-9]{1,4}){6}|::)ffff(:[a-fA-F0-9]{1,4}){2}$)|(^([a-fA-F0-9]{1,4}) (:[a-fA-F0-9]{1,4}){7}$)|(^:(:[a-fA-F0-9]{1,4}(::)?){1,6}$)|(^((::)?[a-fA-F0-9]{1,4}:){1,6}:$)|(^::$)",arguments.ip)) {
				return true;
			}
			else {
				return false;
			}
		</cfscript>

	</cffunction>

	<cffunction name="isValidDomain" access="private" hint="Returns whether or not the passed value is a valid domain format" output="no" returntype="boolean">
		<cfargument name="domain" required="no" type="string" default="">

			<cfscript>
				if (refindnocase("^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}$",arguments.domain)) {
					return true;
				}
				else {
					return false;
				}
			</cfscript>

	</cffunction>

	<cffunction name="extractDomain" access="private" hint="Returns the domain portion of a URI">
		<cfargument name="uri" required="yes" type="string">

		<cfscript>
			// strip protocols
			arguments.uri = rereplacenocase(trim(arguments.uri),"^https?://","");
	
			// return domain portion
			return listfirst(arguments.uri,":/?##");
		</cfscript>

	</cffunction>

	<cffunction name="extractNormalizedDomain" access="private" hint="Returns the normalized domain portion of a URL">
		<cfargument name="uri" required="yes" type="string">

		<cfscript>
			arguments.uri = extractDomain(arguments.uri);
	
			// if first node of domain is 'www', we want to strip it out 
			if(listfirst(arguments.uri,".") eq "www") {
				return listrest(arguments.uri,".");
			}
			else {
				return arguments.uri;
			}
		</cfscript>

	</cffunction>
	
	
	<!--- UTILITY METHODS --->
	
	<cffunction name="onMissingMethod" access="public" returntype="any" output="false">
		<cfargument name="missingMethodName" type="string" required="true">
		<cfargument name="missingMethodArguments" type="struct" required="true">
		
		<cfscript>
			var response = "";
			var lookup = "#rereplacenocase(arguments.missingMethodName,"^(get)","")#";
			// method aliases
			var aliases = {
				HostAddress = "A",
				Certificate = "CERT",
				CanonicalName = "CNAME",
				DHCPIdentifier = "DHCPID",
				DNSSECLookasideValidation = "DLV",
				DelegationName = "DNAME",
				DelegationSigner = "DS",
				HostInformation = "HINFO",
				HostIdentityProtocol = "HIP",
				KeyExchanger = "KX",
				Location = "LOC",
				MailExchange = "MX",
				NameAuthorityPointer = "NAPTR",
				NameServers = "NS",
				NextSecure = "NSEC",
				NextSecureV3 = "NSEC3",
				NextSecureV3Parameters = "NSEC3Param",
				Option = "OPT",
				Pointer = "PTR",
				ResourceRecordsSignature = "RRSIG",
				StartOfAuthority = "SOA",
				SenderPolicyFramework = "SPF",
				ServiceLocator = "SRV",
				SSHPublicKeyFingerprint = "SSHFP",
				DNSSECTrustAuthorities = "TA",
				TrustAuthorities = "TA",
				TrustAnchorLink = "TALINK",
				TextRecord = "TXT",
				Text = "TXT",
				ReversePointer = "RPTR"				
			}; 
		</cfscript>
		
		<cfif structkeyexists(aliases,lookup)>
			<cfinvoke method="get#aliases[lookup]#" argumentcollection="#arguments.missingMethodArguments#" returnvariable="response">
			<cfreturn response>
		<cfelse>
			<cfthrow type="MethodNotFound" message="The #arguments.missingMethodName# method could not be found">
		</cfif>		
		
	</cffunction>

</cfcomponent>