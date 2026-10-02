// Package image is the source of a container image: an image in the local
// Docker daemon or in a registry, named oci://REF, or an image tarball.
package image

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	layerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/plugin"
)

// Name is the registered name of the source.
const Name = "image"

// Scheme is the prefix of an image reference target.
const Scheme = "oci://"

// Options configure the source.
type Options struct {
	// Target is oci://REF or the path of an image tarball.
	Target string `json:"target"`
}

// Source yields the file system of one image.
type Source struct {
	opts Options
	// load opens the image. Tests replace it.
	load func(target string) (*layerimage.Image, string, error)
}

// New returns the source.
func New(o Options) *Source { return &Source{opts: o, load: load} }

// Artifacts yields the image file system. Close removes the files that the
// image unpacked.
func (s *Source) Artifacts(context.Context) iter.Seq2[plugin.Artifact, error] {
	return func(yield func(plugin.Artifact, error) bool) {
		img, key, err := s.load(s.opts.Target)
		if err != nil {
			yield(plugin.Artifact{}, err)
			return
		}
		yield(plugin.Artifact{
			Kind:  plugin.ArtifactImage,
			Root:  img.FS(),
			Label: s.opts.Target,
			Key:   key,
			Close: img.CleanUp,
		}, nil)
	}
}

// IsTarball reports a target that is an image tarball.
func IsTarball(target string) bool {
	return strings.HasSuffix(strings.ToLower(target), ".tar")
}

func load(target string) (*layerimage.Image, string, error) {
	cfg := layerimage.DefaultConfig()
	if IsTarball(target) {
		abs, err := filepath.Abs(target)
		if err != nil {
			return nil, "", err
		}
		img, err := layerimage.FromTarball(abs, cfg)
		if err != nil {
			return nil, "", fmt.Errorf("open image tarball %s: %w", target, err)
		}
		return img, "image:" + abs, nil
	}

	ref, ok := strings.CutPrefix(target, Scheme)
	if !ok {
		return nil, "", fmt.Errorf("image target %q needs the %s prefix or a .tar file", target, Scheme)
	}
	key, err := Key(ref)
	if err != nil {
		return nil, "", err
	}
	img, localErr := layerimage.FromLocalDockerImage(ref, cfg)
	if localErr == nil {
		return img, key, nil
	}
	log.Debugf("image: %s is not in the local Docker daemon: %v", ref, localErr)
	img, err = layerimage.FromRemoteName(ref, cfg, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, "", errors.Join(fmt.Errorf("pull image %s: %w", ref, err), localErr)
	}
	return img, key, nil
}

// Key returns the target key of an image reference, with the registry and
// the tag made explicit, for example "image:index.docker.io/library/alpine:3.20".
func Key(ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("bad image reference %q: %w", ref, err)
	}
	return "image:" + r.Name(), nil
}
