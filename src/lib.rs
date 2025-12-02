use std::vec;

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
                Item::Pkcs1Key(_) | Item::Pkcs8Key(_) | Item::Sec1Key(_) => RenderElement {
                    header: "Private Key".to_string(),
                    content: "Please do not share private keys.".into(),
                },
                _ => RenderElement {
                    header: "Unkown Type".to_string(),
                    content: RenderContent::Empty,
                },
            },
            Err(err) => RenderElement {
                header: "Unkown Type".to_string(),
                content: format!("{:?}", err).into(),
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
                    content: format!("{} bytes left over", rem.len()).into(),
                };
            }

            let exts: Vec<_> = cert.extensions().iter().map(parse_x509_extension).collect();

            RenderElement {
                header: "X509".to_string(),
                content: RenderContent::List(vec![
                    RenderElement {
                        header: "Subject".to_string(),
                        content: cert.subject().to_string().into(),
                    },
                    RenderElement {
                        header: "Issuer".to_string(),
                        content: cert.issuer().to_string().into(),
                    },
                    RenderElement {
                        header: "Serial".to_string(),
                        content: cert.raw_serial_as_string().into(),
                    },
                    RenderElement {
                        header: "Extensions".to_string(),
                        content: exts.into(),
                    },
                ]),
            }
        }
        Err(err) => RenderElement {
            header: "Parsing x509 failed".to_string(),
            content: format!("{:?}", err).into(),
        },
    }
}

fn parse_x509_extension(ext: &X509Extension) -> RenderElement {
    match ext.parsed_extension() {
        ParsedExtension::UnsupportedExtension { oid } => RenderElement {
            header: "Unsupported extension".to_string(),
            content: format!("Oid {}", oid.to_id_string()).into(),
        },
        ParsedExtension::ParseError { error } => RenderElement {
            header: "Parse error".to_string(),
            content: format!("{}", error).into(),
        },
        ParsedExtension::AuthorityKeyIdentifier(aki) => RenderElement {
            header: format!("Authority Key Identifier ({})", ext.oid.to_id_string()),
            content: vec![
                RenderElement {
                    header: "Key Identifier".to_string(),
                    content: match aki.key_identifier {
                        Some(ref id) => format_key_identifier(&id.0),
                        None => "None".to_string(),
                    }
                    .into(),
                },
                RenderElement {
                    header: "Authority Cert Issuer".to_string(),
                    content: match aki.authority_cert_issuer {
                        Some(ref issuers) => issuers
                            .iter()
                            .map(|general_name| format_general_name(general_name))
                            .collect::<Vec<RenderElement>>(),
                        None => vec![],
                    }
                    .into(),
                },
                RenderElement {
                    header: "Authority Cert Serial".to_string(),
                    content: match aki.authority_cert_serial {
                        Some(ref serial) => format_key_identifier(serial),
                        None => "None".to_string(),
                    }
                    .into(),
                },
            ]
            .into(),
        },
        ParsedExtension::SubjectKeyIdentifier(ski) => RenderElement {
            header: format!("Subject Key Identifier ({})", ext.oid.to_id_string()),
            content: format!(
                "{}",
                // Convert the bytes to a hex string with colon separated format
                ski.0
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<String>>()
                    .join(":")
            )
            .into(),
        },
        ParsedExtension::KeyUsage(ku) => RenderElement {
            header: format!("Key Usage ({})", ext.oid.to_id_string()),
            content: RenderContent::List(vec![
                RenderElement {
                    header: "CRL Sign".to_string(),
                    content: ku.crl_sign().into(),
                },
                RenderElement {
                    header: "Data Encipherment".to_string(),
                    content: ku.data_encipherment().into(),
                },
                RenderElement {
                    header: "Decipher Only".to_string(),
                    content: ku.decipher_only().into(),
                },
                RenderElement {
                    header: "Digital Signature".to_string(),
                    content: ku.digital_signature().into(),
                },
                RenderElement {
                    header: "Encipher Only".to_string(),
                    content: ku.encipher_only().into(),
                },
                RenderElement {
                    header: "Key Agreement".to_string(),
                    content: ku.key_agreement().into(),
                },
                RenderElement {
                    header: "Key Cert Sign".to_string(),
                    content: ku.key_cert_sign().into(),
                },
                RenderElement {
                    header: "Key Encipherment".to_string(),
                    content: ku.key_encipherment().into(),
                },
                RenderElement {
                    header: "Non Repudiation".to_string(),
                    content: ku.non_repudiation().into(),
                },
            ]),
        },
        ParsedExtension::ExtendedKeyUsage(eku) => RenderElement {
            header: format!("Extended Key Usage ({})", ext.oid.to_id_string()),
            content: vec![
                RenderElement {
                    header: "Any".to_string(),
                    content: eku.any.into(),
                },
                RenderElement {
                    header: "Server Auth".to_string(),
                    content: eku.server_auth.into(),
                },
                RenderElement {
                    header: "Client Auth".to_string(),
                    content: eku.client_auth.into(),
                },
                RenderElement {
                    header: "Code Signing".to_string(),
                    content: eku.code_signing.into(),
                },
                RenderElement {
                    header: "E-Mail Protection".to_string(),
                    content: eku.email_protection.into(),
                },
                RenderElement {
                    header: "Time Stamping".to_string(),
                    content: eku.time_stamping.into(),
                },
                RenderElement {
                    header: "OCSP Signing".to_string(),
                    content: eku.ocsp_signing.into(),
                },
                RenderElement {
                    header: "Other".to_string(),
                    content: eku
                        .other
                        .iter()
                        .map(|e| RenderElement {
                            header: e.to_string(),
                            content: RenderContent::Empty,
                        })
                        .collect::<Vec<_>>()
                        .into(),
                },
            ]
            .into(),
        },
        ParsedExtension::SubjectAlternativeName(san) => RenderElement {
            header: format!("Subject Alternative Name ({})", ext.oid.to_id_string()),
            content: san
                .general_names
                .iter()
                .map(|general_name| format_general_name(general_name))
                .collect::<Vec<_>>()
                .into(),
        },
        ParsedExtension::CRLDistributionPoints(crl_dp) => RenderElement {
            header: format!("CRL Distribution Points ({})", ext.oid.to_id_string()),
            content: crl_dp
                .points
                .iter()
                .map(|point| RenderElement {
                    header: "Distribution Point".to_string(),
                    content: vec![
                        RenderElement {
                            header: "Name".to_string(),
                            content: format!("{:?}", point.distribution_point).into(),
                        },
                        RenderElement {
                            header: "Reasons".to_string(),
                            content: format!("{:?}", point.reasons).into(),
                        },
                        RenderElement {
                            header: "CRL Issuer".to_string(),
                            content: format!("{:?}", point.crl_issuer).into(),
                        },
                    ]
                    .into(),
                })
                .collect::<Vec<_>>()
                .into(),
        },
        ParsedExtension::SubjectInfoAccess(subject_info_access) => RenderElement {
            header: format!("Subject Info Access ({})", ext.oid.to_id_string()),
            content: subject_info_access
                .accessdescs
                .iter()
                .map(|access_description| RenderElement {
                    header: "Access Description".to_string(),
                    content: vec![
                        RenderElement {
                            header: "Method".to_string(),
                            content: access_description.access_method.to_id_string().into(),
                        },
                        RenderElement {
                            header: "Location".to_string(),
                            content: format!("{:?}", access_description.access_location).into(),
                        },
                    ]
                    .into(),
                })
                .collect::<Vec<_>>()
                .into(),
        },
        ParsedExtension::BasicConstraints(basic_constraints) => RenderElement {
            header: format!("Basic Constraints ({})", ext.oid.to_id_string()),
            content: vec![
                RenderElement {
                    header: "CA".to_string(),
                    content: basic_constraints.ca.into(),
                },
                RenderElement {
                    header: "Path Length Constraint".to_string(),
                    content: match basic_constraints.path_len_constraint {
                        Some(len) => len.to_string(),
                        None => "None".to_string(),
                    }
                    .into(),
                },
            ]
            .into(),
        },
        ParsedExtension::CertificatePolicies(_)
        | ParsedExtension::PolicyMappings(_)
        | ParsedExtension::IssuerAlternativeName(_)
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
            content: format!("{:?}", ext.parsed_extension()).into(),
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

impl Into<RenderContent> for String {
    fn into(self) -> RenderContent {
        RenderContent::Value(self)
    }
}

impl Into<RenderContent> for &str {
    fn into(self) -> RenderContent {
        RenderContent::Value(self.to_string())
    }
}

impl Into<RenderContent> for bool {
    fn into(self) -> RenderContent {
        RenderContent::Value(self.to_string())
    }
}

impl Into<RenderContent> for &dyn ToString {
    fn into(self) -> RenderContent {
        RenderContent::Value(self.to_string())
    }
}

impl Into<RenderContent> for Vec<RenderElement> {
    fn into(self) -> RenderContent {
        RenderContent::List(self)
    }
}

fn format_key_identifier(id: &[u8]) -> String {
    id.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":")
}

fn format_general_name(general_name: &GeneralName) -> RenderElement {
    match general_name {
        GeneralName::OtherName(oid, items) => RenderElement {
            header: format!("Other Name ({})", oid.to_id_string()),
            content: format!("{:?}", items).into(),
        },
        GeneralName::RFC822Name(name) => RenderElement {
            header: "RFC822 Name".to_string(),
            content: name.to_string().into(),
        },
        GeneralName::DNSName(name) => RenderElement {
            header: "DNS Name".to_string(),
            content: name.to_string().into(),
        },
        GeneralName::X400Address(any) => RenderElement {
            header: "X400 Address".to_string(),
            content: format!("{:?}", any).into(),
        },
        GeneralName::DirectoryName(x509_name) => RenderElement {
            header: "Directory Name".to_string(),
            content: x509_name.to_string().into(),
        },
        GeneralName::EDIPartyName(any) => RenderElement {
            header: "EDI Party Name".to_string(),
            content: format!("{:?}", any).into(),
        },
        GeneralName::URI(uri) => RenderElement {
            header: "URI".to_string(),
            content: uri.to_string().into(),
        },
        GeneralName::IPAddress(items) => RenderElement {
            header: "IP Address".to_string(),
            content: format!(
                "{}",
                // Convert IP address bytes to a string with dot notation
                items
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<String>>()
                    .join(".")
            )
            .into(),
        },
        GeneralName::RegisteredID(oid) => RenderElement {
            header: "Registered ID".to_string(),
            content: oid.to_id_string().into(),
        },
        GeneralName::Invalid(tag, items) => RenderElement {
            header: format!("Invalid General Name (tag {})", tag),
            content: format!("{:?}", items).into(),
        },
    }
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
