# Go Simple Mail

The best way to send emails in Go with SMTP Keep Alive and Timeout for Connect and Send.

<a href="https://goreportcard.com/report/github.com/xhit/go-simple-mail/v2"><img src="https://goreportcard.com/badge/github.com/xhit/go-simple-mail" alt="Go Report Card"></a>
<a href="https://pkg.go.dev/github.com/xhit/go-simple-mail/v2?tab=doc"><img src="https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white" alt="go.dev"></a>


# IMPORTANT

Examples in this README are for v2.2.0 and above. Examples for older versions
can be found [here](https://gist.github.com/xhit/54516917473420a8db1b6fff68a21c99).

The minimum Go version is 1.13, for Go 1.12 and older use branch `go1.12`.

Breaking change in 2.2.0: The signature of `SetBody` and `AddAlternative` used
to accept strings ("text/html" and "text/plain") and not require on of the
`contentType` constants (`TextHTML` or `TextPlain`). Upgrading, while not
quite following semantic versioning, is quite simple:

```diff
  email := mail.NewMSG()
- email.SetBody("text/html", htmlBody)
- email.AddAlternative("text/plain", plainBody)
+ email.SetBody(mail.TextHTML, htmlBody)
+ email.AddAlternative(mail.TextPlain, plainBody)
```

# Introduction

Go Simple Mail is a simple and efficient package to send emails. It is well tested and
documented.

Go Simple Mail can only send emails using an SMTP server. But the API is flexible and it
is easy to implement other methods for sending emails using a local Postfix, an API, etc.

This package contains (and is based on) two packages by **Joe Grasse**:

- https://github.com/joegrasse/mail (unmaintained since Jun 29, 2018), and
- https://github.com/joegrasse/mime (unmaintained since Oct 1, 2015).

A lot of changes in Go Simple Mail were sent with not response.

## Features

Go Simple Mail supports:

- Multiple Attachments with path
- Multiple Attachments in base64
- Multiple Attachments from bytes (since v2.6.0)
- Inline attachments from file, base64 and bytes (bytes since v2.6.0)
- Multiple Recipients
- Priority
- Reply to
- Set sender
- Set from
- Allow sending mail with different envelope from (since v2.7.0)
- Embedded images
- HTML and text templates
- Automatic encoding of special characters
- SSL/TLS and STARTTLS
- Unencrypted connection (not recommended)
- Sending multiple emails with the same SMTP connection (Keep Alive or Persistent Connection)
- Timeout for connect to a SMTP Server
- Timeout for send an email
- Return Path
- Alternative Email Body
- CC and BCC
- Add Custom Headers in Message
- Send NOOP, RESET, QUIT and CLOSE to SMTP client
- PLAIN, LOGIN and CRAM-MD5 Authentication (since v2.3.0)
- Custom TLS Configuration (since v2.5.0)
- Send a RFC822 formatted message (since v2.8.0)
- Send from localhost (yes, Go standard SMTP package cannot do that because... WTF Google!)

## Documentation

https://pkg.go.dev/github.com/xhit/go-simple-mail/v2?tab=doc

## Download

This package uses go modules.

```console
$ go get github.com/xhit/go-simple-mail/v2
```

# Usage

```go
package main

import (
	"log"

	"github.com/xhit/go-simple-mail/v2"
)

const htmlBody = `<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<title>Hello Gophers!</title>
	</head>
	<body>
		<p>This is the <b>Go gopher</b>.</p>
		<p><img src="cid:Gopher.png" alt="Go gopher" /></p>
		<p>Image created by Renee French</p>
	</body>
</html>`

func main() {
	server := mail.NewSMTPClient()

	// SMTP Server
	server.Host = "smtp.example.com"
	server.Port = 587
	server.Username = "test@example.com"
	server.Password = "examplepass"
	server.Encryption = mail.EncryptionSTARTTLS

	// Since v2.3.0 you can specified authentication type:
	// - PLAIN (default)
	// - LOGIN
	// - CRAM-MD5
	// server.Authentication = mail.AuthPlain

	// Variable to keep alive connection
	server.KeepAlive = false

	// Timeout for connect to SMTP Server
	server.ConnectTimeout = 10 * time.Second

	// Timeout for send the data and wait respond
	server.SendTimeout = 10 * time.Second

	// Set TLSConfig to provide custom TLS configuration. For example,
	// to skip TLS verification (useful for testing):
	server.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// SMTP client
	smtpClient,err := server.Connect()

	if err != nil{
		log.Fatal(err)
	}

	// New email simple html with inline and CC
	email := mail.NewMSG()
	email.SetFrom("From Example <nube@example.com>").
		AddTo("xhit@example.com").
		AddCc("otherto@example.com").
		SetSubject("New Go Email")

	email.SetBody(mail.TextHTML, htmlBody)

	// also you can add body from []byte with SetBodyData, example:
	// email.SetBodyData(mail.TextHTML, []byte(htmlBody))

	// add inline
	email.Attach(&mail.File{FilePath: "/path/to/image.png", Name:"Gopher.png", Inline: true})

	// always check error after send
	if email.Error != nil{
		log.Fatal(email.Error)
	}

	// Call Send and pass the client
	err = email.Send(smtpClient)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("Email Sent")
	}
}
```

## Send multiple emails in same connection

```go
	//Set your smtpClient struct to keep alive connection
	server.KeepAlive = true

	for _, to := range []string{
		"to1@example1.com",
		"to3@example2.com",
		"to4@example3.com",
	} {
		// New email simple html with inline and CC
		email := mail.NewMSG()
		email.SetFrom("From Example <nube@example.com>").
			AddTo(to).
			SetSubject("New Go Email")

		email.SetBody(mail.TextHTML, htmlBody)

		// add inline
		email.Attach(&mail.File{FilePath: "/path/to/image.png", Name:"Gopher.png", Inline: true})

		// always check error after send
		if email.Error != nil{
			log.Fatal(email.Error)
		}

		// Call Send and pass the client
		err = email.Send(smtpClient)
		if err != nil {
			log.Println(err)
		} else {
			log.Println("Email Sent")
		}
	}
```

## More examples

See [example/example_test.go](example/example_test.go).
