mod utils;

use rustls_pemfile::{read_all, Item};
use wasm_bindgen::prelude::*;
use web_sys::{Document, Element};
use x509_parser::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn parse(input: &str) {
    let results = match read_all(&mut input.as_bytes()) {
        Ok(vec) => vec
            .into_iter()
            .map(|pem| match pem {
                Item::X509Certificate(contents) => parse_x509(contents),
                _ => RenderElement {
                    header: "Unkown Type".to_string(),
                    content: RenderContent::Empty,
                },
            })
            .collect(),
        Err(err) => vec![RenderElement {
            header: "Unkown Type".to_string(),
            content: RenderContent::Value(format!("{:?}", err)),
        }],
    };

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
            content: RenderContent::Value(format!("{:?}", ski.0)),
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
                    .map(|general_name| RenderElement {
                        header: general_name.to_string(),
                        content: RenderContent::Empty,
                    })
                    .collect(),
            ),
        },
        ParsedExtension::CRLDistributionPoints(crl_dp) => RenderElement {
            header: format!("CRL Distribution Points ({})", ext.oid.to_id_string()),
            content: RenderContent::List(
                crl_dp.points
                    .iter()
                    .map(|point| RenderElement {
                        header: "Distribution Point".to_string(),
                        content: RenderContent::List(vec![
                            RenderElement {
                                header: "Name".to_string(),
                                content: RenderContent::Value(format!("{:?}", point.distribution_point)),
                            },
                            RenderElement {
                                header: "Reasons".to_string(),
                                content: RenderContent::Value(format!("{:?}", point.reasons)),
                            },
                            RenderElement {
                                header: "CRL Issuer".to_string(),
                                content: RenderContent::Value(format!("{:?}", point.crl_issuer)),
                            },
                        ])
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
