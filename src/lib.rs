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

            let exts = cert
                .extensions()
                .into_iter()
                .map(|ext| RenderElement {
                    header: format!("Type {}", ext.oid.to_id_string()),
                    content: RenderContent::Value(format!("{:?}", ext.parsed_extension())),
                })
                .collect();

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
                let li = render_element(&document, boxx);
                ul.append_child(&li).expect("should append li element");
            }
        }
    }

    parent
}
