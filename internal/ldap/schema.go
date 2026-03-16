package ldap

import (
	"log"
	"strings"

	"github.com/jimlambrt/gldap"
)

// isSchemaQuery 检查是否为 Schema 查询
func isSchemaQuery(baseDN string) bool {
	baseDN = strings.ToLower(strings.TrimSpace(baseDN))
	return strings.HasPrefix(baseDN, "cn=schema") ||
		strings.Contains(baseDN, "subschema")
}

// searchSchema 处理 Schema 查询
func searchSchema(w *gldap.ResponseWriter, r *gldap.Request, searchBaseDN, filter string, scope int, baseDN string) {
	schemaDN := "cn=schema"
	e := r.NewSearchResponseEntry(schemaDN)

	e.AddAttribute("objectClass", []string{"top", "subentry", "subschema", "extensibleObject"})
	e.AddAttribute("cn", []string{"schema"})
	e.AddAttribute("subschemaSubentry", []string{"cn=schema"})

	e.AddAttribute("objectClasses", getObjectClasses())
	e.AddAttribute("attributeTypes", getAttributeTypes())
	e.AddAttribute("ldapSyntaxes", getLdapSyntaxes())
	e.AddAttribute("matchingRules", getMatchingRules())
	e.AddAttribute("matchingRuleUse", getMatchingRuleUse())

	e.AddAttribute("structuralObjectClass", []string{"subschema"})
	e.AddAttribute("entryDN", []string{schemaDN})
	e.AddAttribute("createTimestamp", []string{"20250101000000Z"})
	e.AddAttribute("modifyTimestamp", []string{"20250101000000Z"})

	w.Write(e)
	sendSearchDone(w, r, gldap.ResultSuccess)
	log.Printf("[LDAP] Schema query returned 1 entry")
}

// searchRootDSE 处理 Root DSE 查询
func searchRootDSE(w *gldap.ResponseWriter, r *gldap.Request, baseDN string) {
	e := r.NewSearchResponseEntry("")
	e.AddAttribute("objectClass", []string{"top", "extensibleObject"})
	e.AddAttribute("namingContexts", []string{baseDN})
	e.AddAttribute("supportedLDAPVersion", []string{"3"})
	e.AddAttribute("supportedControl", []string{
		"2.16.840.1.113730.3.4.18",
		"1.3.6.1.4.1.4203.1.10.1",
		"1.2.840.113556.1.4.319",
		"1.2.826.0.1.3344810.2.3",
		"1.3.6.1.1.12",
		"1.3.6.1.1.13.1",
		"1.3.6.1.1.13.2",
	})
	e.AddAttribute("supportedSASLMechanisms", []string{})
	e.AddAttribute("subschemaSubentry", []string{"cn=schema"})
	e.AddAttribute("rootDomainNamingContext", []string{baseDN})
	e.AddAttribute("ldapServiceName", []string{"ldap.example.com"})
	e.AddAttribute("serverName", []string{"ldap.example.com"})
	e.AddAttribute("supportedCapabilities", []string{
		"1.3.6.1.4.1.4203.1.5.5",
		"1.3.6.1.4.1.4203.1.5.6",
		"1.3.6.1.4.1.4203.1.5.7",
	})
	e.AddAttribute("vendorName", []string{"FeiShu LDAP Server"})
	e.AddAttribute("vendorVersion", []string{"1.0.0"})
	w.Write(e)
	sendSearchDone(w, r, gldap.ResultSuccess)
	log.Printf("[LDAP] Root DSE query returned 1 entry")
}

// getObjectClasses 返回对象类定义
func getObjectClasses() []string {
	return []string{
		"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
		"( 2.5.6.1 NAME 'alias' SUP top ABSTRACT MUST aliasedObjectName )",
		"( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c )",
		"( 2.5.6.3 NAME 'locality' SUP top STRUCTURAL )",
		"( 2.5.6.4 NAME 'organization' SUP top STRUCTURAL MUST o )",
		"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou )",
		"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( cn $ sn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
		"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( title $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ internationalISDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l ) )",
		"( 2.5.6.8 NAME 'organizationalRole' SUP top STRUCTURAL MUST cn MAY ( x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ seeAlso $ roleOccupant $ preferredDeliveryMethod $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l $ description ) )",
		"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( cn $ member ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
		"( 2.5.6.10 NAME 'residentialPerson' SUP person STRUCTURAL MUST l MAY ( x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ internationalISDNNumber $ facsimileTelephoneNumber $ preferredDeliveryMethod $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ st $ l ) )",
		"( 2.5.6.11 NAME 'applicationProcess' SUP top STRUCTURAL MUST cn MAY ( seeAlso $ ou $ l $ description ) )",
		"( 2.5.6.12 NAME 'applicationEntity' SUP top STRUCTURAL MUST ( cn $ presentationAddress ) MAY ( supportedApplicationContext $ seeAlso $ ou $ o $ l $ description ) )",
		"( 2.5.6.13 NAME 'dSA' SUP applicationEntity STRUCTURAL MAY knowledgeInformation )",
		"( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST cn MAY ( serialNumber $ seeAlso $ owner $ ou $ o $ l $ description ) )",
		"( 2.5.6.15 NAME 'strongAuthenticationUser' SUP top AUXILIARY MUST userCertificate )",
		"( 2.5.6.16 NAME 'certificationAuthority' SUP top AUXILIARY MUST ( authorityRevocationList $ certificateRevocationList $ cACertificate ) MAY crossCertificatePair )",
		"( 2.5.6.17 NAME 'groupOfUniqueNames' SUP top STRUCTURAL MUST ( cn $ uniqueMember ) MAY ( businessCategory $ seeAlso $ owner $ ou $ o $ description ) )",
		"( 2.5.6.18 NAME 'userSecurityInformation' SUP top AUXILIARY MAY ( supportedAlgorithms ) )",
		"( 2.5.6.19 NAME 'certificationAuthority-V2' SUP certificationAuthority AUXILIARY MAY deltaRevocationList )",
		"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( audio $ businessCategory $ carLicense $ departmentNumber $ displayName $ employeeNumber $ employeeType $ givenName $ homePhone $ homePostalAddress $ initials $ jpegPhoto $ labeledURI $ mail $ manager $ mobile $ o $ pager $ photo $ roomNumber $ secretary $ uid $ userCertificate $ x500uniqueIdentifier $ preferredLanguage $ userSMIMECertificate $ userPKCS12 ) )",
		"( 1.3.6.1.1.1.2.0 NAME 'posixAccount' SUP top AUXILIARY MUST ( cn $ uid $ uidNumber $ gidNumber $ homeDirectory ) MAY ( userPassword $ loginShell $ gecos $ description ) )",
		"( 1.3.6.1.1.1.2.1 NAME 'shadowAccount' SUP top AUXILIARY MUST uid MAY ( userPassword $ shadowLastChange $ shadowMin $ shadowMax $ shadowWarning $ shadowInactive $ shadowExpire $ shadowFlag $ description ) )",
		"( 1.3.6.1.1.1.2.2 NAME 'posixGroup' SUP top STRUCTURAL MUST ( cn $ gidNumber ) MAY ( userPassword $ memberUid $ description ) )",
		"( 1.2.840.113556.1.5.6 NAME 'samaccount' SUP top STRUCTURAL MUST sAMAccountName )",
	}
}

// getAttributeTypes 返回属性类型定义
func getAttributeTypes() []string {
	return []string{
		"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.4.1 NAME 'aliasedObjectName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
		"( 2.5.4.2 NAME 'knowledgeInformation' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		"( 2.5.4.3 NAME 'cn' SUP name )",
		"( 2.5.4.4 NAME 'sn' SUP name )",
		"( 2.5.4.5 NAME 'serialNumber' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.44{64} )",
		"( 2.5.4.6 NAME 'c' SUP name SINGLE-VALUE )",
		"( 2.5.4.7 NAME 'l' SUP name )",
		"( 2.5.4.8 NAME 'st' SUP name )",
		"( 2.5.4.9 NAME 'street' SUP name )",
		"( 2.5.4.10 NAME 'o' SUP name )",
		"( 2.5.4.11 NAME 'ou' SUP name )",
		"( 2.5.4.12 NAME 'title' SUP name )",
		"( 2.5.4.13 NAME 'description' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )",
		"( 2.5.4.14 NAME 'searchGuide' SYNTAX 1.3.6.1.4.1.1466.115.121.1.25 )",
		"( 2.5.4.15 NAME 'businessCategory' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )",
		"( 2.5.4.16 NAME 'postalAddress' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
		"( 2.5.4.17 NAME 'postalCode' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{40} )",
		"( 2.5.4.18 NAME 'postOfficeBox' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{40} )",
		"( 2.5.4.19 NAME 'physicalDeliveryOfficeName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128} )",
		"( 2.5.4.20 NAME 'telephoneNumber' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} )",
		"( 2.5.4.21 NAME 'telexNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )",
		"( 2.5.4.22 NAME 'teletexTerminalIdentifier' SYNTAX 1.3.6.1.4.1.1466.115.121.1.51 )",
		"( 2.5.4.23 NAME 'facsimileTelephoneNumber' SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )",
		"( 2.5.4.24 NAME 'x121Address' EQUALITY numericStringMatch SUBSTR numericStringSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.36{15} )",
		"( 2.5.4.25 NAME 'internationalISDNNumber' EQUALITY numericStringMatch SUBSTR numericStringSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.36{16} )",
		"( 2.5.4.26 NAME 'registeredAddress' SUP postalAddress )",
		"( 2.5.4.27 NAME 'destinationIndicator' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.44{128} )",
		"( 2.5.4.28 NAME 'preferredDeliveryMethod' SYNTAX 1.3.6.1.4.1.1466.115.121.1.14 SINGLE-VALUE )",
		"( 2.5.4.29 NAME 'presentationAddress' EQUALITY presentationAddressMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.43 SINGLE-VALUE )",
		"( 2.5.4.30 NAME 'supportedApplicationContext' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.4.31 NAME 'member' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.4.32 NAME 'owner' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.4.33 NAME 'roleOccupant' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.4.34 NAME 'seeAlso' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.4.35 NAME 'userPassword' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
		"( 2.5.4.36 NAME 'userCertificate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )",
		"( 2.5.4.37 NAME 'cACertificate' SYNTAX 1.3.6.1.4.1.1466.115.121.1.8 )",
		"( 2.5.4.38 NAME 'authorityRevocationList' SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )",
		"( 2.5.4.39 NAME 'certificateRevocationList' SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )",
		"( 2.5.4.40 NAME 'crossCertificatePair' SYNTAX 1.3.6.1.4.1.1466.115.121.1.10 )",
		"( 2.5.4.41 NAME 'name' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		"( 2.5.4.42 NAME 'givenName' SUP name )",
		"( 2.5.4.43 NAME 'initials' SUP name )",
		"( 2.5.4.44 NAME 'generationQualifier' SUP name )",
		"( 2.5.4.45 NAME 'x500UniqueIdentifier' EQUALITY bitStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )",
		"( 2.5.4.46 NAME 'dnQualifier' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
		"( 2.5.4.47 NAME 'enhancedSearchGuide' SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )",
		"( 2.5.4.48 NAME 'protocolInformation' EQUALITY protocolInformationMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )",
		"( 2.5.4.49 NAME 'distinguishedName' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.4.50 NAME 'uniqueMember' EQUALITY uniqueMemberMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )",
		"( 2.5.4.51 NAME 'houseIdentifier' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		"( 2.5.4.52 NAME 'supportedAlgorithms' SYNTAX 1.3.6.1.4.1.1466.115.121.1.49 )",
		"( 2.5.4.53 NAME 'deltaRevocationList' SYNTAX 1.3.6.1.4.1.1466.115.121.1.9 )",
		"( 2.5.4.54 NAME 'dmdName' SUP name )",
		"( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )",
		"( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
		"( 0.9.2342.19200300.100.1.25 NAME 'dc' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
		"( 0.9.2342.19200300.100.1.37 NAME 'associatedDomain' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.1 NAME 'gidNumber' EQUALITY integerMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.2 NAME 'gecos' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		"( 1.3.6.1.1.1.1.3 NAME 'homeDirectory' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
		"( 1.3.6.1.1.1.1.4 NAME 'loginShell' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 SINGLE-VALUE )",
		"( 2.16.840.1.113730.3.1.1 NAME 'carLicense' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.16.840.1.113730.3.1.2 NAME 'departmentNumber' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.16.840.1.113730.3.1.3 NAME 'employeeNumber' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 2.16.840.1.113730.3.1.4 NAME 'employeeType' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		"( 0.9.2342.19200300.100.1.41 NAME 'mobile' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} )",
		"( 1.2.840.113556.1.2.102 NAME 'memberOf' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 1.2.840.113556.1.2.261 NAME 'sAMAccountName' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SINGLE-VALUE )",
	}
}

// getLdapSyntaxes 返回语法定义
func getLdapSyntaxes() []string {
	return []string{
		"( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )",
		"( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' )",
		"( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' )",
		"( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )",
		"( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' )",
		"( 1.3.6.1.4.1.1466.115.121.1.9 DESC 'Certificate List' )",
		"( 1.3.6.1.4.1.1466.115.121.1.10 DESC 'Certificate Pair' )",
		"( 1.3.6.1.4.1.1466.115.121.1.11 DESC 'Country String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )",
		"( 1.3.6.1.4.1.1466.115.121.1.14 DESC 'Delivery Method' )",
		"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.21 DESC 'Enhanced Guide' )",
		"( 1.3.6.1.4.1.1466.115.121.1.22 DESC 'Facsimile Telephone Number' )",
		"( 1.3.6.1.4.1.1466.115.121.1.23 DESC 'Fax' )",
		"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )",
		"( 1.3.6.1.4.1.1466.115.121.1.25 DESC 'Guide' )",
		"( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )",
		"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' )",
		"( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'Name And Optional UID' )",
		"( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )",
		"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
		"( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )",
		"( 1.3.6.1.4.1.1466.115.121.1.42 DESC 'Protocol Information' )",
		"( 1.3.6.1.4.1.1466.115.121.1.43 DESC 'Presentation Address' )",
		"( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )",
		"( 1.3.6.1.4.1.1466.115.121.1.49 DESC 'Supported Algorithm' )",
		"( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )",
		"( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )",
		"( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )",
		"( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTCTime' )",
		"( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )",
		"( 1.3.6.1.4.1.1466.115.121.1.55 DESC 'Modify Rights' )",
		"( 1.3.6.1.4.1.1466.115.121.1.56 DESC 'LDAP Schema Definition' )",
		"( 1.3.6.1.4.1.1466.115.121.1.57 DESC 'LDAP Schema Description' )",
		"( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring Assertion' )",
	}
}

// getMatchingRules 返回匹配规则
func getMatchingRules() []string {
	return []string{
		"( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		"( 2.5.13.5 NAME 'caseExactMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.5.13.6 NAME 'caseExactOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 2.5.13.7 NAME 'caseExactSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		"( 2.5.13.8 NAME 'numericStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )",
		"( 2.5.13.9 NAME 'numericStringOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )",
		"( 2.5.13.10 NAME 'numericStringSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		"( 2.5.13.11 NAME 'caseIgnoreListMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
		"( 2.5.13.12 NAME 'caseIgnoreListSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		"( 2.5.13.13 NAME 'booleanMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
		"( 2.5.13.14 NAME 'integerMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		"( 2.5.13.15 NAME 'integerOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		"( 2.5.13.16 NAME 'bitStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )",
		"( 2.5.13.17 NAME 'octetStringMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		"( 2.5.13.18 NAME 'octetStringOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		"( 2.5.13.19 NAME 'octetStringSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		"( 2.5.13.20 NAME 'telephoneNumberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
		"( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		"( 2.5.13.22 NAME 'presentationAddressMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.43 )",
		"( 2.5.13.23 NAME 'uniqueMemberMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )",
		"( 2.5.13.24 NAME 'protocolInformationMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )",
		"( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		"( 2.5.13.29 NAME 'integerFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		"( 2.5.13.31 NAME 'directoryStringFirstComponentMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		"( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
	}
}

// getMatchingRuleUse 返回匹配规则用途
func getMatchingRuleUse() []string {
	return []string{
		"( 2.5.13.17 NAME 'octetStringMatch' APPLIES ( userPassword ) )",
		"( 2.5.13.20 NAME 'telephoneNumberMatch' APPLIES ( telephoneNumber $ mobile $ pager $ homePhone $ facsimileTelephoneNumber ) )",
		"( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' APPLIES ( telephoneNumber $ mobile $ pager $ homePhone $ facsimileTelephoneNumber ) )",
		"( 2.5.13.24 NAME 'protocolInformationMatch' APPLIES ( protocolInformation ) )",
		"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' APPLIES ( supportedApplicationContext $ objectClass $ attributeType $ matchingRule $ matchingRuleUse $ ldapSyntaxes ) )",
		"( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' APPLIES ( mail $ dc $ associatedDomain $ uid $ labeledURI ) )",
		"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' APPLIES ( mail $ dc $ associatedDomain $ uid $ labeledURI ) )",
		"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' APPLIES ( mail $ dc $ associatedDomain $ uid $ labeledURI ) )",
	}
}
