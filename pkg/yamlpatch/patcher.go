package yamlpatch

import (
	"bytes"
	"io"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Patcher struct {
	BaseFilePath  string
	PatchFilePath string
}

func NewPatcher(filePath string, suffix string) *Patcher {
	return &Patcher{
		BaseFilePath:  filePath,
		PatchFilePath: filePath + suffix,
	}
}

// read a single YAML file, check for errors (the merge package doesn't) then return the content as bytes.
func readYAML(filePath string) ([]byte, error) {
	var content []byte

	var err error

	if content, err = os.ReadFile(filePath); err != nil {
		return nil, errors.Wrap(err, "while reading yaml file")
	}

	var yamlMap map[interface{}]interface{}
	if err = yaml.Unmarshal(content, &yamlMap); err != nil {
		return nil, errors.Wrap(err, filePath)
	}

	return content, nil
}

// MergedPatchContent reads a YAML file and, if it exists, its patch file,
// then merges them and returns it serialized.
func (p *Patcher) MergedPatchContent() ([]byte, error) {
	var err error

	var base []byte

	base, err = readYAML(p.BaseFilePath)
	if err != nil {
		return nil, err
	}

	var over []byte

	over, err = readYAML(p.PatchFilePath)
	// optional file, ignore if it does not exist
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		log.Infof("Patching yaml: '%s' with '%s'", p.BaseFilePath, p.PatchFilePath)
	}

	var patched *bytes.Buffer

	// strict mode true, will raise errors for duplicate map keys and
	// overriding with a different type
	patched, err = YAML([][]byte{base, over}, true)
	if err != nil {
		return nil, err
	}

	return patched.Bytes(), nil
}

// read multiple YAML documents inside a file, and writes them to a buffer
// separated by the appropriate '---' terminators.
func decodeDocuments(file *os.File, buf *bytes.Buffer, finalDashes bool) error {
	var (
		err      error
		docBytes []byte
	)

	dec := yaml.NewDecoder(file)
	dec.SetStrict(true)

	dashTerminator := false

	for {
		yml := make(map[interface{}]interface{})

		err = dec.Decode(&yml)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return errors.Wrapf(err, "while decoding %s", file.Name())
		}

		docBytes, err = yaml.Marshal(&yml)
		if err != nil {
			return errors.Wrapf(err, "while marshaling %s", file.Name())
		}

		if dashTerminator {
			buf.Write([]byte("---\n"))
		}

		buf.Write(docBytes)
		dashTerminator = true
	}
	if dashTerminator && finalDashes {
		buf.Write([]byte("---\n"))
	}
	return nil
}

// PrependedPatchContent collates the base .yaml file with the .yaml.patch, by putting
// the content of the patch BEFORE the base document. The result is a multi-document
// YAML in all cases, even if the base and patch files are single documents.
func (p *Patcher) PrependedPatchContent() ([]byte, error) {
	var (
		result    bytes.Buffer
		patchFile *os.File
		baseFile  *os.File
		err       error
	)

	patchFile, err = os.Open(p.PatchFilePath)
	// optional file, ignore if it does not exist
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Wrapf(err, "while opening %s", p.PatchFilePath)
	}

	if patchFile != nil {
		if err = decodeDocuments(patchFile, &result, true); err != nil {
			return nil, err
		}
		log.Infof("Prepending yaml: '%s' with '%s'", p.BaseFilePath, p.PatchFilePath)
	}

	baseFile, err = os.Open(p.BaseFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "while opening %s", p.BaseFilePath)
	}

	if err = decodeDocuments(baseFile, &result, false); err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}
