package main

import (
	"strings"
	"testing"
)

func TestSamlEngineLifecycleAndAssertions(t *testing.T) {
	eng, err := NewSamlEngine("127.0.0.1", 18080, 0, "", "admin", "secret", false)
	if err != nil {
		t.Fatal(err)
	}
	idpXML, err := eng.IDPMetadataXML()
	if err != nil || !strings.Contains(idpXML, "IDPSSODescriptor") {
		t.Fatalf("IDP metadata: %v", err)
	}
	spXML, err := eng.SPMetadataXML()
	if err != nil || !strings.Contains(spXML, "SPSSODescriptor") {
		t.Fatalf("SP metadata: %v", err)
	}
	if !eng.AuthenticateUser("admin", "secret") || eng.AuthenticateUser("admin", "wrong") {
		t.Fatal("admin authentication failed")
	}

	u, err := eng.UpsertUser("alice", UserInput{
		Password:   "pw123",
		Email:      "alice@example.com",
		CommonName: "Alice Smith",
		Groups:     []string{"eng"},
	})
	if err != nil || u.Email != "alice@example.com" {
		t.Fatalf("UpsertUser: %v %+v", err, u)
	}

	issued, err := eng.IssueAssertion("alice", "", "", "")
	if err != nil || issued.SAMLResponseB64 == "" {
		t.Fatalf("IssueAssertion: %v", err)
	}

	verified, err := eng.VerifyAssertion(issued.SAMLResponseB64, "", "", "")
	if err != nil || !verified.Valid || verified.Subject != "alice@example.com" {
		t.Fatalf("VerifyAssertion: %v %+v", err, verified)
	}

	tampered := strings.Replace(issued.XML, "alice@example.com", "evil@example.com", 1)
	if _, err := eng.VerifyAssertion(tampered, "", "", ""); err == nil {
		t.Fatal("expected tampered assertion to fail verification")
	}
}

func TestLmcodeRegistryMatchesEmbeddedSchema(t *testing.T) {
	reg, _, err := buildLmcodeRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.StdSignatures()) != 226 {
		t.Fatalf("std signatures = %d, want 226", len(reg.StdSignatures()))
	}
	if len(reg.HostSignatures()) != 22 {
		t.Fatalf("host signatures = %d, want 22: %v", len(reg.HostSignatures()), reg.HostSignatures())
	}
}
