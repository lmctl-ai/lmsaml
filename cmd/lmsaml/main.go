package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
	"github.com/crewjam/saml/samlsp"
	lmcode "github.com/lmctl-ai/lmcode-go"
	dsig "github.com/russellhaering/goxmldsig"
	"golang.org/x/crypto/bcrypt"
)

const lmsamlVersion = "0.1.0"

//go:embed lmsaml.dsl.json
var embeddedSchemaBytes []byte

// SamlEngine encapsulates the SAML 2.0 IdP, SP, Store, and cryptographic keys.
type SamlEngine struct {
	mu            sync.RWMutex
	Host          string
	Port          int
	RestPort      int
	BaseURL       url.URL
	IDPURL        url.URL
	SPURL         url.URL
	AdminUser     string
	AdminPassword string
	RequireAuth   bool

	IDPKey  *rsa.PrivateKey
	IDPCert *x509.Certificate
	SPKey   *rsa.PrivateKey
	SPCert  *x509.Certificate

	Store     *samlidp.MemoryStore
	IDPServer *samlidp.Server
	SP        *samlsp.Middleware
	Mux       *http.ServeMux
}

func generateSelfSignedCert(cn string) (*rsa.PrivateKey, *x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"LMScript SAML 2.0"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return priv, cert, nil
}

func NewSamlEngine(host string, port, restPort int, entityID, adminUser, adminPassword string, requireAuth bool) (*SamlEngine, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = 8080
	}
	if adminUser == "" {
		adminUser = "admin"
	}
	if adminPassword == "" {
		adminPassword = "admin"
	}

	baseURLStr := fmt.Sprintf("http://%s:%d", host, port)
	if entityID != "" && (strings.HasPrefix(entityID, "http://") || strings.HasPrefix(entityID, "https://")) {
		if u, err := url.Parse(entityID); err == nil && u.Host != "" {
			baseURLStr = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
	}
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, err
	}
	idpURL := *baseURL
	idpURL.Path = "/idp"
	spURL := *baseURL
	spURL.Path = "/sp"

	idpKey, idpCert, err := generateSelfSignedCert("lmsaml-idp.example.com")
	if err != nil {
		return nil, err
	}
	spKey, spCert, err := generateSelfSignedCert("lmsaml-sp.example.com")
	if err != nil {
		return nil, err
	}

	store := &samlidp.MemoryStore{}
	hashedAdminPw, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.MinCost)
	if err != nil {
		return nil, err
	}
	_ = store.Put("/users/"+adminUser, samlidp.User{
		Name:              adminUser,
		HashedPassword:    hashedAdminPw,
		Email:             adminUser + "@example.com",
		CommonName:        "Administrator",
		Surname:           "User",
		GivenName:         "Admin",
		ScopedAffiliation: "admin@example.com",
		Groups:            []string{"admins", "users"},
	})

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         idpURL,
		Key:         idpKey,
		Signer:      idpKey,
		Certificate: idpCert,
		Store:       store,
		Logger:      logger.DefaultLogger,
	})
	if err != nil {
		return nil, err
	}

	idpMetadata := idpServer.IDP.Metadata()
	spMiddleware, err := samlsp.New(samlsp.Options{
		URL:         spURL,
		EntityID:    spURL.String() + "/metadata",
		Key:         spKey,
		Certificate: spCert,
		IDPMetadata: idpMetadata,
		SignRequest: false,
	})
	if err != nil {
		return nil, err
	}
	// Configure SP ACS and Metadata URLs explicitly under /sp/acs and /sp/metadata
	acsURL := spURL
	acsURL.Path = "/sp/acs"
	spMetaURL := spURL
	spMetaURL.Path = "/sp/metadata"
	spSloURL := spURL
	spSloURL.Path = "/sp/slo"
	spMiddleware.ServiceProvider.AcsURL = acsURL
	spMiddleware.ServiceProvider.MetadataURL = spMetaURL
	spMiddleware.ServiceProvider.SloURL = spSloURL

	// Pre-register the built-in SP in the IdP store and live service provider map
	spDesc := spMiddleware.ServiceProvider.Metadata()
	rawSPMeta, err := xml.MarshalIndent(spDesc, "", "  ")
	if err == nil {
		_ = store.Put("/services/sp-default", samlidp.Service{
			Name:        "sp-default",
			Metadata:    *spDesc,
			RawMetadata: rawSPMeta,
		})
		rec := &httptestRecorder{header: http.Header{}}
		req, _ := http.NewRequest("PUT", "/services/sp-default", bytes.NewReader(rawSPMeta))
		req.SetPathValue("id", "sp-default")
		idpServer.HandlePutService(rec, req)
	}

	eng := &SamlEngine{
		Host:          host,
		Port:          port,
		RestPort:      restPort,
		BaseURL:       *baseURL,
		IDPURL:        idpURL,
		SPURL:         spURL,
		AdminUser:     adminUser,
		AdminPassword: adminPassword,
		RequireAuth:   requireAuth,
		IDPKey:        idpKey,
		IDPCert:       idpCert,
		SPKey:         spKey,
		SPCert:        spCert,
		Store:         store,
		IDPServer:     idpServer,
		SP:            spMiddleware,
	}
	eng.initRoutes()
	return eng, nil
}

type httptestRecorder struct {
	header http.Header
	body   bytes.Buffer
	code   int
}

func (r *httptestRecorder) Header() http.Header         { return r.header }
func (r *httptestRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *httptestRecorder) WriteHeader(statusCode int)  { r.code = statusCode }

func (e *SamlEngine) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if !e.RequireAuth {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if ok {
		uMatch := subtle.ConstantTimeCompare([]byte(user), []byte(e.AdminUser)) == 1
		pMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(e.AdminPassword)) == 1
		if uMatch && pMatch {
			return true
		}
		if e.AuthenticateUser(user, pass) {
			return true
		}
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(token), []byte(e.AdminPassword)) == 1 {
			return true
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="lmsaml"`)
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"ok":    false,
		"error": "Unauthorized",
	})
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(payload)
}

func (e *SamlEngine) IDPMetadataXML() (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	buf, err := xml.MarshalIndent(e.IDPServer.IDP.Metadata(), "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func (e *SamlEngine) SPMetadataXML() (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	buf, err := xml.MarshalIndent(e.SP.ServiceProvider.Metadata(), "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

type UserInput struct {
	Name              string   `json:"name"`
	Password          string   `json:"password,omitempty"`
	Email             string   `json:"email,omitempty"`
	CommonName        string   `json:"common_name,omitempty"`
	Surname           string   `json:"surname,omitempty"`
	GivenName         string   `json:"given_name,omitempty"`
	ScopedAffiliation string   `json:"scoped_affiliation,omitempty"`
	Groups            []string `json:"groups,omitempty"`
}

func (e *SamlEngine) UpsertUser(name string, in UserInput) (samlidp.User, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" {
		name = strings.TrimSpace(in.Name)
	}
	if name == "" {
		return samlidp.User{}, errors.New("user name is required")
	}
	var existing samlidp.User
	err := e.Store.Get("/users/"+name, &existing)
	hasExisting := err == nil

	user := samlidp.User{
		Name:              name,
		Email:             in.Email,
		CommonName:        in.CommonName,
		Surname:           in.Surname,
		GivenName:         in.GivenName,
		ScopedAffiliation: in.ScopedAffiliation,
		Groups:            in.Groups,
	}
	if user.Email == "" {
		if hasExisting && existing.Email != "" {
			user.Email = existing.Email
		} else {
			user.Email = name + "@example.com"
		}
	}
	if user.CommonName == "" {
		if hasExisting && existing.CommonName != "" {
			user.CommonName = existing.CommonName
		} else {
			user.CommonName = name
		}
	}
	if user.Surname == "" {
		if hasExisting && existing.Surname != "" {
			user.Surname = existing.Surname
		} else {
			user.Surname = name
		}
	}
	if user.GivenName == "" {
		if hasExisting && existing.GivenName != "" {
			user.GivenName = existing.GivenName
		} else {
			user.GivenName = name
		}
	}
	if user.ScopedAffiliation == "" {
		if hasExisting && existing.ScopedAffiliation != "" {
			user.ScopedAffiliation = existing.ScopedAffiliation
		} else {
			user.ScopedAffiliation = "member@example.com"
		}
	}
	if len(user.Groups) == 0 && hasExisting {
		user.Groups = existing.Groups
	}
	if in.Password != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.MinCost)
		if err != nil {
			return samlidp.User{}, err
		}
		user.HashedPassword = hashed
	} else if hasExisting {
		user.HashedPassword = existing.HashedPassword
	} else {
		hashed, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.MinCost)
		user.HashedPassword = hashed
	}
	if err := e.Store.Put("/users/"+name, user); err != nil {
		return samlidp.User{}, err
	}
	user.HashedPassword = nil
	return user, nil
}

func (e *SamlEngine) GetUser(name string) (samlidp.User, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var user samlidp.User
	if err := e.Store.Get("/users/"+name, &user); err != nil {
		return samlidp.User{}, err
	}
	user.HashedPassword = nil
	return user, nil
}

func (e *SamlEngine) DeleteUser(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var user samlidp.User
	if err := e.Store.Get("/users/"+name, &user); err != nil {
		return err
	}
	return e.Store.Delete("/users/" + name)
}

func (e *SamlEngine) ListUsers() ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	users, err := e.Store.List("/users/")
	if err != nil {
		return nil, err
	}
	sort.Strings(users)
	if users == nil {
		users = []string{}
	}
	return users, nil
}

func (e *SamlEngine) AuthenticateUser(name, password string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var user samlidp.User
	if err := e.Store.Get("/users/"+name, &user); err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword(user.HashedPassword, []byte(password)) == nil
}

type IssuedAssertion struct {
	OK              bool   `json:"ok"`
	User            string `json:"user"`
	Subject         string `json:"subject"`
	Issuer          string `json:"issuer"`
	Audience        string `json:"audience"`
	ACSURL          string `json:"acs_url"`
	RequestID       string `json:"request_id,omitempty"`
	AssertionID     string `json:"assertion_id"`
	ResponseID      string `json:"response_id"`
	SAMLResponseB64 string `json:"saml_response_b64"`
	XML             string `json:"xml"`
}

func randomSAMLID() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return fmt.Sprintf("id-%x", b)
}

// IssueAssertion builds and cryptographically signs a SAML 2.0 Response + Assertion for a stored user.
func (e *SamlEngine) IssueAssertion(userName, audience, acsURL, requestID string) (*IssuedAssertion, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var user samlidp.User
	if err := e.Store.Get("/users/"+userName, &user); err != nil {
		return nil, fmt.Errorf("user %q not found", userName)
	}
	if audience == "" {
		audience = e.SP.ServiceProvider.MetadataURL.String()
	}
	if acsURL == "" {
		acsURL = e.SP.ServiceProvider.AcsURL.String()
	}

	now := time.Now().UTC()
	assertionID := randomSAMLID()
	responseID := randomSAMLID()
	issuer := e.IDPServer.IDP.MetadataURL.String()
	subject := user.Email
	if subject == "" {
		subject = user.Name
	}

	attrs := []saml.Attribute{
		{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: user.Name}},
		},
	}
	if user.Email != "" {
		attrs = append(attrs, saml.Attribute{
			FriendlyName: "mail",
			Name:         "urn:oid:0.9.2342.19200300.100.1.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: user.Email}},
		})
	}
	if user.CommonName != "" {
		attrs = append(attrs, saml.Attribute{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: user.CommonName}},
		})
	}
	if user.Surname != "" {
		attrs = append(attrs, saml.Attribute{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: user.Surname}},
		})
	}
	if user.GivenName != "" {
		attrs = append(attrs, saml.Attribute{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: user.GivenName}},
		})
	}
	if len(user.Groups) > 0 {
		var groupVals []saml.AttributeValue
		for _, g := range user.Groups {
			groupVals = append(groupVals, saml.AttributeValue{Type: "xs:string", Value: g})
		}
		attrs = append(attrs, saml.Attribute{
			FriendlyName: "groups",
			Name:         "memberOf",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
			Values:       groupVals,
		})
	}

	sessionEnd := now.Add(1 * time.Hour)
	assertion := saml.Assertion{
		ID:           assertionID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format:          string(saml.EmailAddressNameIDFormat),
				NameQualifier:   issuer,
				SPNameQualifier: audience,
				Value:           subject,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: requestID,
						NotOnOrAfter: now.Add(5 * time.Minute),
						Recipient:    acsURL,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    now.Add(-30 * time.Second),
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{Value: audience},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant:        now,
				SessionNotOnOrAfter: &sessionEnd,
				SessionIndex:        assertionID,
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: attrs,
			},
		},
	}

	signingCtx, err := dsig.NewSigningContext(e.IDPKey, [][]byte{e.IDPCert.Raw})
	if err != nil {
		return nil, err
	}
	signingCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signingCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}

	assertionEl := assertion.Element()
	signedAssertionEl, err := signingCtx.SignEnveloped(assertionEl)
	if err != nil {
		return nil, err
	}
	sigEl := signedAssertionEl.Child[len(signedAssertionEl.Child)-1]
	assertion.Signature = sigEl.(*etree.Element)
	signedAssertionEl = assertion.Element()

	response := saml.Response{
		Destination:  acsURL,
		ID:           responseID,
		InResponseTo: requestID,
		IssueInstant: now,
		Version:      "2.0",
		Status: saml.Status{
			StatusCode: saml.StatusCode{
				Value: saml.StatusSuccess,
			},
		},
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
	}
	responseEl := response.Element()
	responseEl.AddChild(signedAssertionEl)

	signedResponseEl, err := signingCtx.SignEnveloped(responseEl)
	if err != nil {
		return nil, err
	}
	respSigEl := signedResponseEl.ChildElements()[len(signedResponseEl.ChildElements())-1]
	response.Signature = respSigEl
	responseEl = response.Element()
	responseEl.AddChild(signedAssertionEl)

	doc := etree.NewDocument()
	doc.SetRoot(responseEl)
	xmlBytes, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	return &IssuedAssertion{
		OK:              true,
		User:            user.Name,
		Subject:         subject,
		Issuer:          issuer,
		Audience:        audience,
		ACSURL:          acsURL,
		RequestID:       requestID,
		AssertionID:     assertionID,
		ResponseID:      responseID,
		SAMLResponseB64: base64.StdEncoding.EncodeToString(xmlBytes),
		XML:             string(xmlBytes),
	}, nil
}

type VerifiedAssertion struct {
	OK          bool                `json:"ok"`
	Valid       bool                `json:"valid"`
	AssertionID string              `json:"assertion_id"`
	Issuer      string              `json:"issuer"`
	Subject     string              `json:"subject"`
	Audience    string              `json:"audience,omitempty"`
	Attributes  map[string][]string `json:"attributes"`
}

// VerifyAssertion cryptographically verifies a SAML 2.0 Response XML (or base64) using crewjam/saml's ServiceProvider.
func (e *SamlEngine) VerifyAssertion(xmlOrB64, audience, acsURL, requestID string) (*VerifiedAssertion, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	trimmed := strings.TrimSpace(xmlOrB64)
	if trimmed == "" {
		return nil, errors.New("empty SAML response")
	}
	var rawXML []byte
	if strings.HasPrefix(trimmed, "<") {
		rawXML = []byte(trimmed)
	} else {
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 SAML response: %w", err)
		}
		rawXML = decoded
	}

	spCopy := e.SP.ServiceProvider
	if audience != "" {
		spCopy.EntityID = audience
		if u, err := url.Parse(audience); err == nil {
			spCopy.MetadataURL = *u
		}
	}
	var parsedACS url.URL
	if acsURL != "" {
		u, err := url.Parse(acsURL)
		if err != nil {
			return nil, err
		}
		parsedACS = *u
		spCopy.AcsURL = parsedACS
	} else {
		parsedACS = spCopy.AcsURL
	}

	var possibleReqIDs []string
	if requestID != "" {
		possibleReqIDs = []string{requestID}
	} else {
		spCopy.AllowIDPInitiated = true
	}

	assertion, err := spCopy.ParseXMLResponse(rawXML, possibleReqIDs, parsedACS)
	if err != nil {
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			return nil, fmt.Errorf("%w: %v", err, ire.PrivateErr)
		}
		return nil, err
	}

	attrs := map[string][]string{}
	for _, stmt := range assertion.AttributeStatements {
		for _, a := range stmt.Attributes {
			key := a.FriendlyName
			if key == "" {
				key = a.Name
			}
			for _, v := range a.Values {
				attrs[key] = append(attrs[key], v.Value)
			}
		}
	}
	subject := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		subject = assertion.Subject.NameID.Value
	}
	aud := ""
	if assertion.Conditions != nil && len(assertion.Conditions.AudienceRestrictions) > 0 {
		aud = assertion.Conditions.AudienceRestrictions[0].Audience.Value
	}

	return &VerifiedAssertion{
		OK:          true,
		Valid:       true,
		AssertionID: assertion.ID,
		Issuer:      assertion.Issuer.Value,
		Subject:     subject,
		Audience:    aud,
		Attributes:  attrs,
	}, nil
}

func (e *SamlEngine) initRoutes() {
	mux := http.NewServeMux()
	e.Mux = mux

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"result":        "PONG",
			"service":       "lmsaml",
			"version":       lmsamlVersion,
			"idp_entity_id": e.IDPServer.IDP.MetadataURL.String(),
			"sp_entity_id":  e.SP.ServiceProvider.MetadataURL.String(),
		})
	})

	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"result":  "PONG",
			"service": "lmsaml",
			"version": lmsamlVersion,
		})
	})

	// SAML 2.0 IdP endpoints (both root and /idp/* paths)
	serveIDPMetadata := func(w http.ResponseWriter, r *http.Request) {
		e.IDPServer.IDP.ServeMetadata(w, r)
	}
	mux.HandleFunc("GET /metadata", serveIDPMetadata)
	mux.HandleFunc("GET /idp/metadata", serveIDPMetadata)

	serveSSO := func(w http.ResponseWriter, r *http.Request) {
		e.IDPServer.IDP.ServeSSO(w, r)
	}
	mux.HandleFunc("/sso", serveSSO)
	mux.HandleFunc("/idp/sso", serveSSO)

	serveSLO := func(w http.ResponseWriter, r *http.Request) {
		e.IDPServer.IDP.ServeSLO(w, r)
	}
	mux.HandleFunc("/slo", serveSLO)
	mux.HandleFunc("/idp/slo", serveSLO)

	mux.HandleFunc("/login", e.IDPServer.HandleLogin)
	mux.HandleFunc("/idp/login", e.IDPServer.HandleLogin)
	mux.HandleFunc("GET /logout", e.IDPServer.HandleLogout)
	mux.HandleFunc("POST /logout", e.IDPServer.HandleLogout)
	mux.HandleFunc("GET /idp/logout", e.IDPServer.HandleLogout)
	mux.HandleFunc("POST /idp/logout", e.IDPServer.HandleLogout)

	// SAML 2.0 SP endpoints (/sp/metadata, /sp/acs, /sp/hello)
	mux.HandleFunc("GET /sp/metadata", func(w http.ResponseWriter, r *http.Request) {
		e.SP.ServeMetadata(w, r)
	})
	mux.HandleFunc("POST /sp/acs", func(w http.ResponseWriter, r *http.Request) {
		e.SP.ServeACS(w, r)
	})
	protectedHello := e.SP.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := samlsp.SessionFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"session": sess,
		})
	}))
	mux.Handle("GET /sp/hello", protectedHello)

	// REST Users API
	handleListUsers := func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		users, err := e.ListUsers()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": users})
	}
	mux.HandleFunc("GET /users", handleListUsers)
	mux.HandleFunc("GET /users/{$}", handleListUsers)

	mux.HandleFunc("GET /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		id := r.PathValue("id")
		u, err := e.GetUser(id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "User not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                 true,
			"name":               u.Name,
			"email":              u.Email,
			"common_name":        u.CommonName,
			"surname":            u.Surname,
			"given_name":         u.GivenName,
			"scoped_affiliation": u.ScopedAffiliation,
			"groups":             u.Groups,
		})
	})

	handlePutUser := func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		id := r.PathValue("id")
		var in UserInput
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(r.Body)
			if len(bytes.TrimSpace(bodyBytes)) > 0 {
				if err := json.Unmarshal(bodyBytes, &in); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid JSON body"})
					return
				}
			}
		}
		u, err := e.UpsertUser(id, in)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"result": "OK",
			"user":   u,
		})
	}
	mux.HandleFunc("PUT /users/{id}", handlePutUser)
	mux.HandleFunc("POST /users/{id}", handlePutUser)

	mux.HandleFunc("DELETE /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		id := r.PathValue("id")
		if err := e.DeleteUser(id); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "User not found"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": "DELETED"})
	})

	// REST Services & Sessions (samlidp)
	mux.HandleFunc("GET /services", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		e.IDPServer.HandleListServices(w, r)
	})
	mux.HandleFunc("GET /services/{$}", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		e.IDPServer.HandleListServices(w, r)
	})
	mux.HandleFunc("GET /services/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		e.IDPServer.HandleGetService(w, r)
	})
	mux.HandleFunc("PUT /services/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		e.IDPServer.HandlePutService(w, r)
	})
	mux.HandleFunc("POST /services/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		e.IDPServer.HandlePutService(w, r)
	})
	mux.HandleFunc("DELETE /services/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		e.IDPServer.HandleDeleteService(w, r)
	})

	// REST Authentication / Credential check
	handleAuthn := func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		username := req.Username
		if username == "" {
			username = req.User
		}
		if username == "" {
			if u, p, ok := r.BasicAuth(); ok {
				username, req.Password = u, p
			}
		}
		if username != "" && e.AuthenticateUser(username, req.Password) {
			u, _ := e.GetUser(username)
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":            true,
				"authenticated": true,
				"result":        "BOUND",
				"user":          u,
			})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":            false,
			"authenticated": false,
			"error":         "Invalid credentials",
		})
	}
	mux.HandleFunc("POST /authn", handleAuthn)
	mux.HandleFunc("POST /bind", handleAuthn)

	// REST SAML 2.0 Signed Assertion Issuance
	mux.HandleFunc("POST /assertion", func(w http.ResponseWriter, r *http.Request) {
		if !e.checkAuth(w, r) {
			return
		}
		var req struct {
			User      string `json:"user"`
			Username  string `json:"username"`
			Audience  string `json:"audience"`
			ACSURL    string `json:"acs_url"`
			RequestID string `json:"request_id"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&req)
		}
		user := req.User
		if user == "" {
			user = req.Username
		}
		if user == "" {
			user = e.AdminUser
		}
		issued, err := e.IssueAssertion(user, req.Audience, req.ACSURL, req.RequestID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, issued)
	})

	// REST SAML 2.0 Signed Assertion Verification
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SAMLResponseB64 string `json:"saml_response_b64"`
			SAMLResponse    string `json:"saml_response"`
			XML             string `json:"xml"`
			Audience        string `json:"audience"`
			ACSURL          string `json:"acs_url"`
			RequestID       string `json:"request_id"`
		}
		if r.Body != nil {
			bodyBytes, _ := io.ReadAll(r.Body)
			trimmed := strings.TrimSpace(string(bodyBytes))
			if strings.HasPrefix(trimmed, "{") {
				_ = json.Unmarshal(bodyBytes, &req)
			} else {
				req.XML = trimmed
			}
		}
		payload := req.SAMLResponseB64
		if payload == "" {
			payload = req.SAMLResponse
		}
		if payload == "" {
			payload = req.XML
		}
		verified, err := e.VerifyAssertion(payload, req.Audience, req.ACSURL, req.RequestID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"valid": false,
				"error": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, verified)
	})
}

// ---- lmcode Host Integration --------------------------------------------------------------------------------

type SamlHostClient struct {
	engine  *SamlEngine
	restURL string
	client  *http.Client
}

type SamlBatch struct {
	host *SamlHostClient
	ops  []func() (any, error)
}

func newSamlHostClient() (*SamlHostClient, error) {
	restURL := os.Getenv("SAML_REST_URL")
	if restURL == "" {
		if p := os.Getenv("SAML_REST_PORT"); p != "" {
			restURL = "http://127.0.0.1:" + p
		} else if p := os.Getenv("SAML_PORT"); p != "" {
			restURL = "http://127.0.0.1:" + p
		}
	}
	eng, err := NewSamlEngine("127.0.0.1", 8080, 0, "", "admin", "admin", false)
	if err != nil {
		return nil, err
	}
	return &SamlHostClient{
		engine:  eng,
		restURL: strings.TrimRight(restURL, "/"),
		client:  &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (h *SamlHostClient) doREST(method, path string, body []byte) (int, []byte, error) {
	if h.restURL == "" {
		return 0, nil, errors.New("no remote REST URL")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, h.restURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

func (h *SamlHostClient) Ping() string {
	if h.restURL != "" {
		if code, _, err := h.doREST("GET", "/ping", nil); err == nil && code == 200 {
			return "PONG"
		}
	}
	return "PONG"
}

func (h *SamlHostClient) Metadata() (string, error) {
	if h.restURL != "" {
		if code, data, err := h.doREST("GET", "/idp/metadata", nil); err == nil && code == 200 {
			return string(data), nil
		}
	}
	return h.engine.IDPMetadataXML()
}

func (h *SamlHostClient) SPMetadata() (string, error) {
	if h.restURL != "" {
		if code, data, err := h.doREST("GET", "/sp/metadata", nil); err == nil && code == 200 {
			return string(data), nil
		}
	}
	return h.engine.SPMetadataXML()
}

func (h *SamlHostClient) AddUser(name, userJSON string) (bool, error) {
	var in UserInput
	if strings.TrimSpace(userJSON) != "" {
		if err := json.Unmarshal([]byte(userJSON), &in); err != nil {
			return false, err
		}
	}
	if h.restURL != "" {
		code, _, err := h.doREST("PUT", "/users/"+url.PathEscape(name), []byte(userJSON))
		if err == nil && code >= 200 && code < 300 {
			_, _ = h.engine.UpsertUser(name, in)
			return true, nil
		}
	}
	_, err := h.engine.UpsertUser(name, in)
	return err == nil, err
}

func (h *SamlHostClient) GetUserJSON(name string) (string, error) {
	if h.restURL != "" {
		if code, data, err := h.doREST("GET", "/users/"+url.PathEscape(name), nil); err == nil {
			if code == 404 {
				return "null", nil
			}
			if code == 200 {
				return strings.TrimSpace(string(data)), nil
			}
		}
	}
	u, err := h.engine.GetUser(name)
	if err != nil {
		return "null", nil
	}
	buf, _ := json.Marshal(map[string]any{
		"ok":                 true,
		"name":               u.Name,
		"email":              u.Email,
		"common_name":        u.CommonName,
		"surname":            u.Surname,
		"given_name":         u.GivenName,
		"scoped_affiliation": u.ScopedAffiliation,
		"groups":             u.Groups,
	})
	return string(buf), nil
}

func (h *SamlHostClient) DelUser(name string) int64 {
	if h.restURL != "" {
		if code, _, err := h.doREST("DELETE", "/users/"+url.PathEscape(name), nil); err == nil {
			_ = h.engine.DeleteUser(name)
			if code >= 200 && code < 300 {
				return 1
			}
			return 0
		}
	}
	if err := h.engine.DeleteUser(name); err != nil {
		return 0
	}
	return 1
}

func (h *SamlHostClient) ListUsersJSON() (string, error) {
	if h.restURL != "" {
		if code, data, err := h.doREST("GET", "/users", nil); err == nil && code == 200 {
			var parsed struct {
				Users []string `json:"users"`
			}
			if json.Unmarshal(data, &parsed) == nil {
				b, _ := json.Marshal(parsed.Users)
				return string(b), nil
			}
		}
	}
	users, err := h.engine.ListUsers()
	if err != nil {
		return "[]", err
	}
	b, _ := json.Marshal(users)
	return string(b), nil
}

func (h *SamlHostClient) Authenticate(name, password string) bool {
	if h.restURL != "" {
		payload, _ := json.Marshal(map[string]string{"username": name, "password": password})
		if code, _, err := h.doREST("POST", "/authn", payload); err == nil {
			return code == 200
		}
	}
	return h.engine.AuthenticateUser(name, password)
}

func (h *SamlHostClient) IssueAssertionJSON(user, audience string) (string, error) {
	if h.restURL != "" {
		payload, _ := json.Marshal(map[string]string{"user": user, "audience": audience})
		if code, data, err := h.doREST("POST", "/assertion", payload); err == nil && code == 200 {
			return strings.TrimSpace(string(data)), nil
		}
	}
	issued, err := h.engine.IssueAssertion(user, audience, "", "")
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(issued)
	return string(b), nil
}

func (h *SamlHostClient) VerifyAssertionJSON(xmlOrB64 string) (string, error) {
	if h.restURL != "" {
		payload, _ := json.Marshal(map[string]string{"saml_response_b64": xmlOrB64})
		if code, data, err := h.doREST("POST", "/verify", payload); err == nil && (code == 200 || code == 400) {
			return strings.TrimSpace(string(data)), nil
		}
	}
	verified, err := h.engine.VerifyAssertion(xmlOrB64, "", "", "")
	if err != nil {
		b, _ := json.Marshal(map[string]any{"ok": false, "valid": false, "error": err.Error()})
		return string(b), nil
	}
	b, _ := json.Marshal(verified)
	return string(b), nil
}

func buildLmcodeRegistry() (*lmcode.Registry, *SamlHostClient, error) {
	reg := lmcode.NewRegistry()
	host, err := newSamlHostClient()
	if err != nil {
		return nil, nil, err
	}

	_ = reg.Context("saml", "Saml")
	_ = reg.Function("print", []string{"string"}, "void", func(a []lmcode.Value) (lmcode.Value, error) {
		fmt.Println(a[0].Str)
		return lmcode.None(), nil
	}, lmcode.Dry(lmcode.Function(func([]lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), nil
	})))

	S := []string{"string"}
	SS := []string{"string", "string"}

	_ = reg.Method("Saml", "ping", nil, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(self.(*SamlHostClient).Ping()), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String("PONG"), nil
	})))

	_ = reg.Method("Saml", "metadata", nil, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		xmlStr, err := self.(*SamlHostClient).Metadata()
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.String(xmlStr), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String("<EntityDescriptor/>"), nil
	})))

	_ = reg.Method("Saml", "sp_metadata", nil, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		xmlStr, err := self.(*SamlHostClient).SPMetadata()
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.String(xmlStr), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String("<EntityDescriptor/>"), nil
	})))

	_ = reg.Method("Saml", "add_user", SS, "bool", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		ok, err := self.(*SamlHostClient).AddUser(a[0].Str, a[1].Str)
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.Bool(ok), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(true), nil
	})))

	_ = reg.Method("Saml", "get_user", S, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		out, err := self.(*SamlHostClient).GetUserJSON(a[0].Str)
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.String(out), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String("{}"), nil
	})))

	_ = reg.Method("Saml", "del_user", S, "int", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(self.(*SamlHostClient).DelUser(a[0].Str)), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(1), nil
	})))

	_ = reg.Method("Saml", "list_users", nil, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		out, err := self.(*SamlHostClient).ListUsersJSON()
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.String(out), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String("[]"), nil
	})))

	_ = reg.Method("Saml", "authenticate", SS, "bool", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(self.(*SamlHostClient).Authenticate(a[0].Str, a[1].Str)), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(true), nil
	})))

	_ = reg.Method("Saml", "issue_assertion", SS, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		out, err := self.(*SamlHostClient).IssueAssertionJSON(a[0].Str, a[1].Str)
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.String(out), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String("{}"), nil
	})))

	_ = reg.Method("Saml", "verify_assertion", S, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		out, err := self.(*SamlHostClient).VerifyAssertionJSON(a[0].Str)
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.String(out), nil
	}, lmcode.Dry(lmcode.Method(func(any, []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(`{"ok":true,"valid":true}`), nil
	})))

	_ = reg.Method("Saml", "batch", nil, "Batch", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", &SamlBatch{host: self.(*SamlHostClient)}), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", &SamlBatch{}), nil
	})))

	// Batch methods
	_ = reg.Method("Batch", "ping", nil, "Batch", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		b := self.(*SamlBatch)
		b.ops = append(b.ops, func() (any, error) { return b.host.Ping(), nil })
		return lmcode.Object("Batch", b), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", self), nil
	})))

	_ = reg.Method("Batch", "add_user", SS, "Batch", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		b := self.(*SamlBatch)
		name, ujson := a[0].Str, a[1].Str
		b.ops = append(b.ops, func() (any, error) {
			_, err := b.host.AddUser(name, ujson)
			if err != nil {
				return nil, err
			}
			return "OK", nil
		})
		return lmcode.Object("Batch", b), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", self), nil
	})))

	_ = reg.Method("Batch", "get_user", S, "Batch", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		b := self.(*SamlBatch)
		name := a[0].Str
		b.ops = append(b.ops, func() (any, error) {
			raw, err := b.host.GetUserJSON(name)
			if err != nil {
				return nil, err
			}
			var v any
			_ = json.Unmarshal([]byte(raw), &v)
			return v, nil
		})
		return lmcode.Object("Batch", b), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", self), nil
	})))

	_ = reg.Method("Batch", "del_user", S, "Batch", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		b := self.(*SamlBatch)
		name := a[0].Str
		b.ops = append(b.ops, func() (any, error) { return b.host.DelUser(name), nil })
		return lmcode.Object("Batch", b), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", self), nil
	})))

	_ = reg.Method("Batch", "list_users", nil, "Batch", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		b := self.(*SamlBatch)
		b.ops = append(b.ops, func() (any, error) {
			raw, err := b.host.ListUsersJSON()
			if err != nil {
				return nil, err
			}
			var v any
			_ = json.Unmarshal([]byte(raw), &v)
			return v, nil
		})
		return lmcode.Object("Batch", b), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", self), nil
	})))

	_ = reg.Method("Batch", "issue_assertion", SS, "Batch", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		b := self.(*SamlBatch)
		user, aud := a[0].Str, a[1].Str
		b.ops = append(b.ops, func() (any, error) {
			raw, err := b.host.IssueAssertionJSON(user, aud)
			if err != nil {
				return nil, err
			}
			var v any
			_ = json.Unmarshal([]byte(raw), &v)
			return v, nil
		})
		return lmcode.Object("Batch", b), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Batch", self), nil
	})))

	_ = reg.Method("Batch", "len", nil, "int", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(int64(len(self.(*SamlBatch).ops))), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(0), nil
	})))

	_ = reg.Method("Batch", "clear", nil, "void", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		self.(*SamlBatch).ops = nil
		return lmcode.None(), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), nil
	})))

	_ = reg.Method("Batch", "exec", nil, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		b := self.(*SamlBatch)
		results := make([]any, 0, len(b.ops))
		for _, op := range b.ops {
			res, err := op()
			if err != nil {
				results = append(results, map[string]any{"error": err.Error()})
			} else {
				results = append(results, res)
			}
		}
		b.ops = nil
		encoded, _ := json.Marshal(results)
		return lmcode.String(string(encoded)), nil
	}, lmcode.Dry(lmcode.Method(func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String("[]"), nil
	})))

	return reg, host, nil
}

func runLmcodeFiles(files []string, dryFlag bool) int {
	if len(files) == 0 {
		return lmcode.FailureFrame(os.Stdout, "cli", lmcode.NewError(lmcode.CLI_USAGE, "missing bytecode file after --lmcode"))
	}
	results, err := lmcode.InvocationResultsFromCommand(files)
	if err != nil {
		return lmcode.FailureFrame(os.Stdout, "cli", err)
	}
	reg, host, err := buildLmcodeRegistry()
	if err != nil {
		return lmcode.FailureFrame(os.Stdout, "cli", err)
	}
	contract, err := lmcode.ResultContractFromSchema(embeddedSchemaBytes)
	if err != nil {
		return lmcode.FailureFrame(os.Stdout, "cli", err)
	}
	ctx := lmcode.NewContext()
	ctx.Set("saml", host)
	ctx.SetDry(results.Dry() || dryFlag)

	for _, part := range results.Registrations() {
		index := part.Index
		raw, err := os.ReadFile(part.File)
		if err != nil {
			_ = results.Fail(&index, "load", lmcode.NewError(lmcode.LOAD_BAD_BYTECODE, "cannot read bytecode file"))
			break
		}
		program, err := lmcode.Load(raw, embeddedSchemaBytes, reg)
		if err != nil {
			_ = results.Fail(&index, "load", err)
			break
		}
		if _, err := results.Select(index, reg, contract); err != nil {
			_ = results.Fail(&index, "load", err)
			break
		}
		if err := program.Run(ctx, reg); err != nil {
			_ = results.Fail(&index, "run", err)
			break
		}
		if err := results.Complete(index); err != nil {
			break
		}
	}
	return results.WriteFrame(os.Stdout)
}

func printUsage() {
	fmt.Println("lmsaml - Single-binary SAML 2.0 Identity Provider, Service Provider, REST API & lmcode Host")
	fmt.Println("Usage:")
	fmt.Println("  lmsaml [options]")
	fmt.Println("Options:")
	fmt.Println("  --port <N>                 SAML 2.0 IdP/SP & REST HTTP port (default: 8080)")
	fmt.Println("  --rest-port <N>            Optional dedicated REST HTTP port")
	fmt.Println("  --host <addr>              Listen address (default: 127.0.0.1)")
	fmt.Println("  --entity-id <url>          IdP base/entity URL")
	fmt.Println("  --admin-user <name>        Initial admin username (default: admin)")
	fmt.Println("  --admin-password <pw>      Initial admin password (default: admin)")
	fmt.Println("  --require-auth             Require HTTP Basic/Bearer auth on REST admin endpoints")
	fmt.Println("  --version, -v              Print version")
	fmt.Println("  --lmcode-schema [--json]   Print embedded lmcode schema")
	fmt.Println("  --lmcode-signatures        Print canonical lmcode signatures")
	fmt.Println("  --lmcode <file.dslb>       Execute compiled lmcode bytecode")
}

func main() {
	args := os.Args[1:]
	for _, a := range args {
		if a == "--dsl" || a == "--dsl-schema" || a == "--dsl-signatures" || strings.HasPrefix(a, "--dsl=") {
			fmt.Fprintf(os.Stderr, "retired option: %s\n", a)
			os.Exit(2)
		}
	}

	host := "127.0.0.1"
	port := 8080
	restPort := 0
	entityID := ""
	adminUser := "admin"
	adminPassword := "admin"
	requireAuth := false
	dryRun := false
	var lmcodeFiles []string
	lmcodeMode := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--version", "-v":
			fmt.Printf("lmsaml %s\n", lmsamlVersion)
			return
		case "--help", "-h":
			printUsage()
			return
		case "--lmcode-schema":
			if i+1 < len(args) && args[i+1] == "--json" {
				i++
			}
			os.Stdout.Write(embeddedSchemaBytes)
			return
		case "--lmcode-signatures", "--host-signatures":
			reg, _, err := buildLmcodeRegistry()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			sigs := reg.Signatures()
			if arg == "--host-signatures" {
				sigs = reg.HostSignatures()
			}
			for _, s := range sigs {
				fmt.Println(s)
			}
			return
		case "--dry-run":
			dryRun = true
		case "--lmcode":
			lmcodeMode = true
			for i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				i++
				lmcodeFiles = append(lmcodeFiles, args[i])
			}
		case "--port", "-p":
			if i+1 < len(args) {
				i++
				port, _ = strconv.Atoi(args[i])
			}
		case "--rest-port":
			if i+1 < len(args) {
				i++
				restPort, _ = strconv.Atoi(args[i])
			}
		case "--host":
			if i+1 < len(args) {
				i++
				host = args[i]
			}
		case "--entity-id":
			if i+1 < len(args) {
				i++
				entityID = args[i]
			}
		case "--admin-user":
			if i+1 < len(args) {
				i++
				adminUser = args[i]
			}
		case "--admin-password":
			if i+1 < len(args) {
				i++
				adminPassword = args[i]
			}
		case "--require-auth":
			requireAuth = true
		default:
			if strings.HasPrefix(arg, "--port=") {
				port, _ = strconv.Atoi(strings.TrimPrefix(arg, "--port="))
			} else if strings.HasPrefix(arg, "--rest-port=") {
				restPort, _ = strconv.Atoi(strings.TrimPrefix(arg, "--rest-port="))
			} else if strings.HasPrefix(arg, "--host=") {
				host = strings.TrimPrefix(arg, "--host=")
			} else if strings.HasPrefix(arg, "--entity-id=") {
				entityID = strings.TrimPrefix(arg, "--entity-id=")
			} else if strings.HasPrefix(arg, "--admin-user=") {
				adminUser = strings.TrimPrefix(arg, "--admin-user=")
			} else if strings.HasPrefix(arg, "--admin-password=") {
				adminPassword = strings.TrimPrefix(arg, "--admin-password=")
			}
		}
	}

	if lmcodeMode {
		os.Exit(runLmcodeFiles(lmcodeFiles, dryRun))
	}

	eng, err := NewSamlEngine(host, port, restPort, entityID, adminUser, adminPassword, requireAuth)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lmsaml init failed: %v\n", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lmsaml failed to listen on %s: %v\n", addr, err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: eng.Mux}
	go func() {
		_ = srv.Serve(ln)
	}()

	var restSrv *http.Server
	if restPort > 0 && restPort != port {
		restAddr := fmt.Sprintf("%s:%d", host, restPort)
		restLn, err := net.Listen("tcp", restAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lmsaml failed to listen on REST port %s: %v\n", restAddr, err)
			os.Exit(1)
		}
		restSrv = &http.Server{Handler: eng.Mux}
		go func() {
			_ = restSrv.Serve(restLn)
		}()
	}

	fmt.Printf("lmsaml %s listening on http://%s (IdP metadata: http://%s/idp/metadata, SP metadata: http://%s/sp/metadata)\n",
		lmsamlVersion, addr, addr, addr)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	_ = srv.Close()
	if restSrv != nil {
		_ = restSrv.Close()
	}
}
