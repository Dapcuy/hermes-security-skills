package dockerx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ImageVerificationSpec describes the image trust assertions required before execution.
type ImageVerificationSpec struct {
	Image             string
	ExpectedDigest    string
	SignatureRequired bool
}

// SignatureVerifier verifies a registry signature using an external trust provider.
// Implementations must perform real cryptographic verification; this interface is
// deliberately not a hook for a boolean or test-only signature.
type SignatureVerifier interface {
	Verify(context.Context, string) error
}

// CosignVerifier delegates signature verification to the cosign CLI. The CLI is
// the trust boundary for signature formats and key/identity policy; this package
// does not implement or emulate cryptography.
type CosignVerifier struct {
	Bin                   string
	CertificateIdentity   string
	CertificateOIDCIssuer string
	KeyRef                string
}

func (c CosignVerifier) policyArgs() ([]string, error) {
	identity := strings.TrimSpace(c.CertificateIdentity)
	issuer := strings.TrimSpace(c.CertificateOIDCIssuer)
	key := strings.TrimSpace(c.KeyRef)
	switch {
	case key != "" && (identity != "" || issuer != ""):
		return nil, errors.New("cosign: key reference cannot be combined with certificate identity/issuer")
	case key != "":
		return []string{"--key", key}, nil
	case identity == "" && issuer == "":
		return nil, errors.New("cosign: explicit trust policy required (key reference or certificate identity and issuer)")
	case identity == "" || issuer == "":
		return nil, errors.New("cosign: certificate identity and issuer must be configured together")
	default:
		return []string{"--certificate-identity", identity, "--certificate-oidc-issuer", issuer}, nil
	}
}

func (c CosignVerifier) Verify(ctx context.Context, image string) error {
	bin := c.Bin
	if bin == "" {
		bin = "cosign"
	}
	policy, err := c.policyArgs()
	if err != nil {
		return err
	}
	args := append([]string{"verify"}, policy...)
	args = append(args, image)
	cmd := exec.CommandContext(ctx, bin, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign verify %s: %w (%s)", image, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func validSHA256Digest(s string) bool {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	for _, r := range s[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// VerifyImage checks the daemon's resolved RepoDigests and, when required,
// delegates signature verification. Any missing or inconsistent evidence fails
// closed. It performs no network access itself.
func VerifyImage(ctx context.Context, x Execer, sig SignatureVerifier, spec ImageVerificationSpec) error {
	image := strings.TrimSpace(spec.Image)
	if image == "" {
		return errors.New("dockerx: image verification requires an image ref")
	}
	expected := strings.TrimSpace(spec.ExpectedDigest)
	if expected == "-" {
		expected = ""
	}
	if i := strings.LastIndex(image, "@sha256:"); i >= 0 {
		if expected == "" {
			expected = image[i+1:]
		} else if expected != image[i+1:] {
			return fmt.Errorf("dockerx: image digest mismatch: ref=%s expected=%s", image[i+1:], expected)
		}
	}
	if expected == "" && spec.SignatureRequired {
		return errors.New("dockerx: signature-required image must be digest-pinned")
	}
	if spec.SignatureRequired && !strings.Contains(image, "@sha256:") {
		return errors.New("dockerx: signature-required image reference must be digest-pinned")
	}
	if expected != "" && !validSHA256Digest(expected) {
		return fmt.Errorf("dockerx: invalid expected image digest %q", expected)
	}

	inspectCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	out, err := x.Exec(inspectCtx, "image", "inspect", "--format", "{{json .RepoDigests}}", image)
	if err != nil {
		return fmt.Errorf("dockerx: inspect image for verification: %w", err)
	}
	var repoDigests []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &repoDigests); err != nil {
		return fmt.Errorf("dockerx: invalid RepoDigests evidence: %w", err)
	}
	if expected != "" {
		want := "@" + expected
		matched := false
		for _, digest := range repoDigests {
			if strings.HasSuffix(digest, want) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("dockerx: image digest mismatch: expected %s, daemon reports %v", expected, repoDigests)
		}
	}
	if spec.SignatureRequired {
		if sig == nil {
			return errors.New("dockerx: signature verification required but no provider configured")
		}
		if err := sig.Verify(ctx, image); err != nil {
			return fmt.Errorf("dockerx: image signature verification failed: %w", err)
		}
	}
	return nil
}
