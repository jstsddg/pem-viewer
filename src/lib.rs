use rustls_pemfile::{read_all, Item};
use wasm_bindgen::prelude::*;
use web_sys::{Document, Element};
use x509_parser::{nom::AsBytes, prelude::*};

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn parse(input: &str) {
    let results = read_all(&mut input.as_bytes())
        .map(|item| match item {
            Ok(pem) => match pem {
                Item::X509Certificate(contents) => parse_x509(contents.as_bytes().to_vec()),
                _ => RenderElement {
                    header: "Unkown Type".to_string(),
                    content: RenderContent::Empty,
                },
            },
            Err(err) => RenderElement {
                header: "Unkown Type".to_string(),
                content: RenderContent::Value(format!("{:?}", err)),
            },
        })
        .collect();

    render(results);
}

fn parse_x509(contents: Vec<u8>) -> RenderElement {
    let result = X509Certificate::from_der(&contents);
    match result {
        Ok((rem, cert)) => {
            if !rem.is_empty() {
                return RenderElement {
                    header: "Parsing x509 failed".to_string(),
                    content: RenderContent::Value(format!("{} bytes left over", rem.len())),
                };
            }

            let exts = cert.extensions().iter().map(parse_x509_extension).collect();

            RenderElement {
                header: "X509".to_string(),
                content: RenderContent::List(vec![
                    RenderElement {
                        header: "Subject".to_string(),
                        content: RenderContent::Value(cert.subject().to_string()),
                    },
                    RenderElement {
                        header: "Issuer".to_string(),
                        content: RenderContent::Value(cert.issuer().to_string()),
                    },
                    RenderElement {
                        header: "Serial".to_string(),
                        content: RenderContent::Value(cert.raw_serial_as_string()),
                    },
                    RenderElement {
                        header: "Extensions".to_string(),
                        content: RenderContent::List(exts),
                    },
                ]),
            }
        }
        Err(err) => RenderElement {
            header: "Parsing x509 failed".to_string(),
            content: RenderContent::Value(format!("{:?}", err)),
        },
    }
}

fn parse_x509_extension(ext: &X509Extension) -> RenderElement {
    match ext.parsed_extension() {
        ParsedExtension::UnsupportedExtension { oid } => RenderElement {
            header: "Unsupported extension".to_string(),
            content: RenderContent::Value(format!("Oid {}", oid.to_id_string())),
        },
        ParsedExtension::ParseError { error } => RenderElement {
            header: "Parse error".to_string(),
            content: RenderContent::Value(format!("{}", error)),
        },
        ParsedExtension::AuthorityKeyIdentifier(aki) => RenderElement {
            header: format!("Authority Key Identifier ({})", ext.oid.to_id_string()),
            content: RenderContent::List(vec![
                RenderElement {
                    header: "Key Identifier".to_string(),
                    content: RenderContent::Value(format!("{:?}", aki.key_identifier)),
                },
                RenderElement {
                    header: "Authority Cert Issuer".to_string(),
                    content: RenderContent::Value(format!("{:?}", aki.authority_cert_issuer)),
                },
                RenderElement {
                    header: "Authority Cert Serial".to_string(),
                    content: RenderContent::Value(format!("{:?}", aki.authority_cert_serial)),
                },
            ]),
        },
        ParsedExtension::SubjectKeyIdentifier(ski) => RenderElement {
            header: format!("Subject Key Identifier ({})", ext.oid.to_id_string()),
            content: RenderContent::Value(format!(
                "{}",
                // Convert the bytes to a hex string with colon separated format
                ski.0
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<String>>()
                    .join(":")
            )),
        },
        ParsedExtension::KeyUsage(ku) => RenderElement {
            header: format!("Key Usage ({})", ext.oid.to_id_string()),
            content: RenderContent::List(vec![
                RenderElement {
                    header: "CRL Sign".to_string(),
                    content: RenderContent::Value(ku.crl_sign().to_string()),
                },
                RenderElement {
                    header: "Data Encipherment".to_string(),
                    content: RenderContent::Value(ku.data_encipherment().to_string()),
                },
                RenderElement {
                    header: "Decipher Only".to_string(),
                    content: RenderContent::Value(ku.decipher_only().to_string()),
                },
                RenderElement {
                    header: "Digital Signature".to_string(),
                    content: RenderContent::Value(ku.digital_signature().to_string()),
                },
                RenderElement {
                    header: "Encipher Only".to_string(),
                    content: RenderContent::Value(ku.encipher_only().to_string()),
                },
                RenderElement {
                    header: "Key Agreement".to_string(),
                    content: RenderContent::Value(ku.key_agreement().to_string()),
                },
                RenderElement {
                    header: "Key Cert Sign".to_string(),
                    content: RenderContent::Value(ku.key_cert_sign().to_string()),
                },
                RenderElement {
                    header: "Key Encipherment".to_string(),
                    content: RenderContent::Value(ku.key_encipherment().to_string()),
                },
                RenderElement {
                    header: "Non Repudiation".to_string(),
                    content: RenderContent::Value(ku.non_repudiation().to_string()),
                },
            ]),
        },
        ParsedExtension::ExtendedKeyUsage(eku) => RenderElement {
            header: format!("Extended Key Usage ({})", ext.oid.to_id_string()),
            content: RenderContent::List(vec![
                RenderElement {
                    header: "Any".to_string(),
                    content: RenderContent::Value(eku.any.to_string()),
                },
                RenderElement {
                    header: "Server Auth".to_string(),
                    content: RenderContent::Value(eku.server_auth.to_string()),
                },
                RenderElement {
                    header: "Client Auth".to_string(),
                    content: RenderContent::Value(eku.client_auth.to_string()),
                },
                RenderElement {
                    header: "Code Signing".to_string(),
                    content: RenderContent::Value(eku.code_signing.to_string()),
                },
                RenderElement {
                    header: "E-Mail Protection".to_string(),
                    content: RenderContent::Value(eku.email_protection.to_string()),
                },
                RenderElement {
                    header: "Time Stamping".to_string(),
                    content: RenderContent::Value(eku.time_stamping.to_string()),
                },
                RenderElement {
                    header: "OCSP Signing".to_string(),
                    content: RenderContent::Value(eku.ocsp_signing.to_string()),
                },
                RenderElement {
                    header: "Other".to_string(),
                    content: RenderContent::List(
                        eku.other
                            .iter()
                            .map(|e| RenderElement {
                                header: e.to_string(),
                                content: RenderContent::Empty,
                            })
                            .collect(),
                    ),
                },
            ]),
        },
        ParsedExtension::SubjectAlternativeName(san) => RenderElement {
            header: format!("Subject Alternative Name ({})", ext.oid.to_id_string()),
            content: RenderContent::List(
                san.general_names
                    .iter()
                    .map(|general_name| match general_name {
                        GeneralName::OtherName(oid, items) => RenderElement {
                            header: format!("Other Name ({})", oid.to_id_string()),
                            content: RenderContent::Value(format!("{:?}", items)),
                        },
                        GeneralName::RFC822Name(name) => RenderElement {
                            header: "RFC822 Name".to_string(),
                            content: RenderContent::Value(name.to_string()),
                        },
                        GeneralName::DNSName(name) => RenderElement {
                            header: "DNS Name".to_string(),
                            content: RenderContent::Value(name.to_string()),
                        },
                        GeneralName::X400Address(any) => RenderElement {
                            header: "X400 Address".to_string(),
                            content: RenderContent::Value(format!("{:?}", any)),
                        },
                        GeneralName::DirectoryName(x509_name) => RenderElement {
                            header: "Directory Name".to_string(),
                            content: RenderContent::Value(x509_name.to_string()),
                        },
                        GeneralName::EDIPartyName(any) => RenderElement {
                            header: "EDI Party Name".to_string(),
                            content: RenderContent::Value(format!("{:?}", any)),
                        },
                        GeneralName::URI(uri) => RenderElement {
                            header: "URI".to_string(),
                            content: RenderContent::Value(uri.to_string()),
                        },
                        GeneralName::IPAddress(items) => RenderElement {
                            header: "IP Address".to_string(),
                            content: RenderContent::Value(format!(
                                "{}",
                                // Convert IP address bytes to a string with dot notation
                                items
                                    .iter()
                                    .map(|b| b.to_string())
                                    .collect::<Vec<String>>()
                                    .join(".")
                            )),
                        },
                        GeneralName::RegisteredID(oid) => RenderElement {
                            header: "Registered ID".to_string(),
                            content: RenderContent::Value(oid.to_id_string()),
                        },
                        GeneralName::Invalid(tag, items) => RenderElement {
                            header: format!("Invalid General Name (tag {})", tag),
                            content: RenderContent::Value(format!("{:?}", items)),
                        },
                    })
                    .collect(),
            ),
        },
        ParsedExtension::CRLDistributionPoints(crl_dp) => RenderElement {
            header: format!("CRL Distribution Points ({})", ext.oid.to_id_string()),
            content: RenderContent::List(
                crl_dp
                    .points
                    .iter()
                    .map(|point| RenderElement {
                        header: "Distribution Point".to_string(),
                        content: RenderContent::List(vec![
                            RenderElement {
                                header: "Name".to_string(),
                                content: RenderContent::Value(format!(
                                    "{:?}",
                                    point.distribution_point
                                )),
                            },
                            RenderElement {
                                header: "Reasons".to_string(),
                                content: RenderContent::Value(format!("{:?}", point.reasons)),
                            },
                            RenderElement {
                                header: "CRL Issuer".to_string(),
                                content: RenderContent::Value(format!("{:?}", point.crl_issuer)),
                            },
                        ]),
                    })
                    .collect(),
            ),
        },
        ParsedExtension::SubjectInfoAccess(subject_info_access) => RenderElement {
            header: format!("Subject Info Access ({})", ext.oid.to_id_string()),
            content: RenderContent::List(
                subject_info_access
                    .accessdescs
                    .iter()
                    .map(|access_description| RenderElement {
                        header: "Access Description".to_string(),
                        content: RenderContent::List(vec![
                            RenderElement {
                                header: "Method".to_string(),
                                content: RenderContent::Value(
                                    access_description.access_method.to_id_string(),
                                ),
                            },
                            RenderElement {
                                header: "Location".to_string(),
                                content: RenderContent::Value(format!(
                                    "{:?}",
                                    access_description.access_location
                                )),
                            },
                        ]),
                    })
                    .collect(),
            ),
        },
        ParsedExtension::CertificatePolicies(_)
        | ParsedExtension::PolicyMappings(_)
        | ParsedExtension::IssuerAlternativeName(_)
        | ParsedExtension::BasicConstraints(_)
        | ParsedExtension::NameConstraints(_)
        | ParsedExtension::PolicyConstraints(_)
        | ParsedExtension::InhibitAnyPolicy(_)
        | ParsedExtension::AuthorityInfoAccess(_)
        | ParsedExtension::NSCertType(_)
        | ParsedExtension::NsCertComment(_)
        | ParsedExtension::CRLNumber(_)
        | ParsedExtension::ReasonCode(_)
        | ParsedExtension::InvalidityDate(_)
        | ParsedExtension::SCT(_)
        | ParsedExtension::IssuingDistributionPoint(_)
        | ParsedExtension::Unparsed => RenderElement {
            header: format!("Oid {}", ext.oid.to_id_string()),
            content: RenderContent::Value(format!("{:?}", ext.parsed_extension())),
        },
    }
}

struct RenderElement {
    header: String,
    content: RenderContent,
}

enum RenderContent {
    Empty,
    Value(String),
    List(Vec<RenderElement>),
}

fn render(elements: Vec<RenderElement>) {
    // Use `web_sys`'s global `window` function to get a handle on the global window object.
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let render = document
        .get_element_by_id("render")
        .expect("document should have a render element");

    // Clear render area
    render.set_inner_html("");

    let list = document
        .create_element("ol")
        .expect("should create ol element");
    render.append_child(&list).expect("should append list");

    for element in elements {
        let rendered = render_element(&document, element);
        list.append_child(&rendered).expect("should append child");
    }
}

fn render_element(document: &Document, element: RenderElement) -> Element {
    let parent = document
        .create_element("li")
        .expect("should create p element");

    match element.content {
        RenderContent::Empty => {
            parent.set_text_content(Some(&element.header));
        }
        RenderContent::Value(content) => {
            parent.set_text_content(Some(&format!("{}: {}", element.header, content)));
        }
        RenderContent::List(content) => {
            parent.set_text_content(Some(&format!("{}:", element.header)));

            let ul = document
                .create_element("ul")
                .expect("should create ul element");
            parent.append_child(&ul).expect("should append ul element");

            for boxx in content {
                let li = render_element(document, boxx);
                ul.append_child(&li).expect("should append li element");
            }
        }
    }

    parent
}
