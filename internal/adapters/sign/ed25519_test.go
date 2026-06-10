package sign

import "testing"

func TestSignVerifyRoundTrip(t *testing.T) {
	s, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data := []byte("sha256-deadbeef")
	sig, err := s.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := s.Verify(data, sig); err != nil {
		t.Fatalf("Verify of valid signature failed: %v", err)
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	s, _ := Generate()
	sig, _ := s.Sign([]byte("original"))
	if err := s.Verify([]byte("tampered"), sig); err == nil {
		t.Fatal("Verify must reject a signature over different data")
	}
}

func TestVerifyRejectsWrongScheme(t *testing.T) {
	s, _ := Generate()
	if err := s.Verify([]byte("x"), "cosign:abc"); err == nil {
		t.Fatal("Verify must reject an unknown signature scheme")
	}
}

func TestSignWithoutPrivateKey(t *testing.T) {
	s := New(nil, nil)
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Fatal("Sign without a private key must error")
	}
}
