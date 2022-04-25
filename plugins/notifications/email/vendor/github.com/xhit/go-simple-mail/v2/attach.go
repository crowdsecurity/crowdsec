package mail

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"mime"
	"path/filepath"
)

// File represents the file that can be added to the email message.
// You can add attachment from file in path, from base64 string or from []byte.
// You can define if attachment is inline or not.
// Only one, Data, B64Data or FilePath is supported. If multiple are set, then
// the first in that order is used.
type File struct {
	// FilePath is the path of the file to attach.
	FilePath string
	// Name is the name of file in attachment. Required for Data and B64Data. Optional for FilePath.
	Name string
	// MimeType of attachment. If empty then is obtained from Name (if not empty) or FilePath. If cannot obtained, application/octet-stream is set.
	MimeType string
	// B64Data is the base64 string to attach.
	B64Data string
	// Data is the []byte of file to attach.
	Data []byte
	// Inline defines if attachment is inline or not.
	Inline bool
}

type attachType int

const (
	attachData attachType = iota
	attachB64
	attachFile
)

// Attach allows you to add an attachment to the email message.
// The attachment can be inlined
func (email *Email) Attach(file *File) *Email {
	if email.Error != nil {
		return email
	}

	var name = file.Name
	var mimeType = file.MimeType

	// if no alternative name was provided, get the filename
	if len(name) == 0 && len(file.FilePath) > 0 {
		_, name = filepath.Split(file.FilePath)
	}

	// get the mimetype
	if mimeType == "" {
		mimeType = mime.TypeByExtension(filepath.Ext(name))
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
	}

	attachTy, err := getAttachmentType(file)
	if err != nil {
		email.Error = errors.New("Mail Error: Failed to add attachment with following error: " + err.Error())
		return email
	}

	file.Name = name
	file.MimeType = mimeType

	switch attachTy {
	case attachData:
		email.attachData(file)
	case attachB64:
		email.Error = email.attachB64(file)
	case attachFile:
		email.Error = email.attachFile(file)
	}

	return email
}

func getAttachmentType(file *File) (attachType, error) {
	// 1- data
	// 2- base64
	// 3- file

	// first check if Data
	if len(file.Data) > 0 {
		// data requires a name
		if len(file.Name) == 0 {
			return 0, errors.New("attach from bytes requires a name")
		}
		return attachData, nil
	}

	// check if base64
	if len(file.B64Data) > 0 {
		// B64Data requires a name
		if len(file.Name) == 0 {
			return 0, errors.New("attach from base64 string requires a name")
		}
		return attachB64, nil
	}

	// check if file
	if len(file.FilePath) > 0 {
		return attachFile, nil
	}

	return 0, errors.New("empty attachment")
}

// attachB64 does the low level attaching of the files but decoding base64
func (email *Email) attachB64(file *File) error {

	// decode the string
	dec, err := base64.StdEncoding.DecodeString(file.B64Data)
	if err != nil {
		return errors.New("Mail Error: Failed to decode base64 attachment with following error: " + err.Error())
	}

	email.attachData(&File{
		Name:     file.Name,
		MimeType: file.MimeType,
		Data:     dec,
		Inline:   file.Inline,
	})

	return nil
}

func (email *Email) attachFile(file *File) error {
	data, err := ioutil.ReadFile(file.FilePath)
	if err != nil {
		return errors.New("Mail Error: Failed to add file with following error: " + err.Error())
	}

	email.attachData(&File{
		Name:     file.Name,
		MimeType: file.MimeType,
		Data:     data,
		Inline:   file.Inline,
	})

	return nil
}

// attachData does the low level attaching of the in-memory data
func (email *Email) attachData(file *File) {
	// use inlines and attachments because is necessary to know if message has related parts and mixed parts
	if file.Inline {
		email.inlines = append(email.inlines, file)
	} else {
		email.attachments = append(email.attachments, file)
	}
}
