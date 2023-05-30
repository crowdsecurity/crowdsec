package mail

import (
	"errors"
)

// TODO: Remove this file before launch v3

// AddAttachment. DEPRECATED. Use Attach method. Allows you to add an attachment to the email message.
// You can optionally provide a different name for the file.
func (email *Email) AddAttachment(file string, name ...string) *Email {
	if email.Error != nil {
		return email
	}

	if len(name) > 1 {
		email.Error = errors.New("Mail Error: Attach can only have a file and an optional name")
		return email
	}
	
	var nm string
	if len(name) == 1 {
		nm = name[0]
	}
	return email.Attach(&File{Name: nm, FilePath: file})
}

// AddAttachmentData. DEPRECATED. Use Attach method. Allows you to add an in-memory attachment to the email message.
func (email *Email) AddAttachmentData(data []byte, filename, mimeType string) *Email {
	return email.Attach(&File{Data: data, Name: filename, MimeType: mimeType})
}

// AddAttachmentBase64. DEPRECATED. Use Attach method. Allows you to add an attachment in base64 to the email message.
// You need provide a name for the file.
func (email *Email) AddAttachmentBase64(b64File, name string) *Email {
	return email.Attach(&File{B64Data: b64File, Name: name})
}

// AddInline. DEPRECATED. Use Attach method. Allows you to add an inline attachment to the email message.
// You can optionally provide a different name for the file.
func (email *Email) AddInline(file string, name ...string) *Email {
	if email.Error != nil {
		return email
	}

	if len(name) > 1 {
		email.Error = errors.New("Mail Error: Inline can only have a file and an optional name")
		return email
	}
	
	var nm string
	if len(name) == 1 {
		nm = name[0]
	}
	
	return email.Attach(&File{Name: nm, FilePath: file, Inline: true})
}

// AddInlineData. DEPRECATED. Use Attach method. Allows you to add an inline in-memory attachment to the email message.
func (email *Email) AddInlineData(data []byte, filename, mimeType string) *Email {
	return email.Attach(&File{Data: data, Name: filename, MimeType: mimeType, Inline: true})
}

// AddInlineBase64. DEPRECATED. Use Attach method. Allows you to add an inline in-memory base64 encoded attachment to the email message.
// You need provide a name for the file. If mimeType is an empty string, attachment mime type will be deduced
// from the file name extension and defaults to application/octet-stream.
func (email *Email) AddInlineBase64(b64File, name, mimeType string) *Email {
	return email.Attach(&File{B64Data: b64File, Name: name, MimeType: mimeType, Inline: true})
}
