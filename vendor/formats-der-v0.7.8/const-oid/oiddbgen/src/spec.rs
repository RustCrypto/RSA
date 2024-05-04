use std::collections::BTreeSet;

use proc_macro2::{Ident, TokenStream};
use quote::quote;

use crate::node::Node;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Spec(BTreeSet<Node>);

impl Spec {
    pub fn insert(&mut self, value: Node) -> bool {
        self.0.insert(value)
    }

    pub fn records(&self, path: TokenStream) -> TokenStream {
        let mut stream = TokenStream::default();

        for n in &self.0 {
            let name = n.name();
            let symb = n.symbol();
            stream.extend(quote! { (#path::#symb, #name), })
        }

        stream
    }

    pub fn module(&self, spec: &Ident) -> TokenStream {
        let mut defs = TokenStream::default();

        for n in &self.0 {
            defs.extend(n.definition())
        }

        quote! {
            pub mod #spec {
                #defs
            }
        }
    }
}
