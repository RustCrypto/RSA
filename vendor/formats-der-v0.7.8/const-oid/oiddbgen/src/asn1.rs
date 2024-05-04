use std::collections::BTreeMap;

use regex::Regex;

#[derive(Clone, Debug)]
pub struct Asn1Parser {
    tree: BTreeMap<String, (Option<String>, Option<String>)>,
    base: BTreeMap<&'static str, &'static str>,
}

impl Asn1Parser {
    const DEF: &'static str = r"(?mx)
        (?P<name>[a-zA-Z][a-zA-Z0-9-]*)             # name
        \s+
        OBJECT
        \s+
        IDENTIFIER
        \s*
        ::=
        \s*
        \{
            \s*
            (?P<base>[a-zA-Z][a-zA-Z0-9-]*\s*)??    # base
            (?P<tail>                               # tail
                (?:
                    (?:
                        [a-zA-Z][a-zA-Z0-9-]*\([0-9]+\)\s*
                    )
                    |
                    (?:
                        [0-9]+\s*
                    )
                )*
            )
        \}
    ";

    const ARC: &'static str = r"(?mx)
        (?:
            [a-zA-Z][a-zA-Z0-9-]*\(([0-9]+)\)
        )
        |
        (?:
            ([0-9]+)
        )
    ";

    pub fn new(asn1: &str, bases: &[(&'static str, &'static str)]) -> Self {
        let def = Regex::new(Self::DEF).unwrap();
        let arc = Regex::new(Self::ARC).unwrap();

        let mut base = BTreeMap::default();
        for (name, tail) in bases {
            base.insert(*name, *tail);
        }

        let mut tree = BTreeMap::default();
        for mat in def.find_iter(asn1) {
            let caps = def.captures(mat.as_str()).unwrap();
            let name = caps.name("name").unwrap().as_str().trim().to_string();
            let base = caps.name("base").map(|m| m.as_str().trim().to_string());
            let tail = caps.name("tail").map(|m| {
                arc.find_iter(m.as_str())
                    .map(|m| {
                        let c = arc.captures(m.as_str()).unwrap();
                        c.get(1).unwrap_or_else(|| c.get(2).unwrap()).as_str()
                    })
                    .collect::<Vec<_>>()
                    .join(".")
            });

            let tail = match tail.as_deref() {
                Some("") => None,
                _ => tail,
            };

            tree.insert(name, (base, tail));
        }

        Self { tree, base }
    }

    pub fn resolve(&self, name: &str) -> Option<String> {
        if let Some(tail) = self.base.get(name) {
            return Some(tail.to_string());
        }

        let (base, arcs) = self.tree.get(name)?;
        if let Some(base) = base {
            let base = self.resolve(base)?;
            if let Some(arcs) = arcs {
                Some(format!("{}.{}", base, arcs))
            } else {
                Some(base)
            }
        } else {
            arcs.clone()
        }
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = (String, String)> {
        self.tree
            .keys()
            .filter_map(|n| self.resolve(n).map(|p| (n.clone(), p)))
    }
}

#[test]
fn test() {
    let asn1 = super::Asn1Parser::new(
        r"
            foo OBJECT IDENTIFIER ::= { bar(1) baz(2) 3 }
            bat OBJECT IDENTIFIER ::= { foo qux(4) 5 }
            quz OBJECT IDENTIFIER ::= { bat 6 }
        ",
    );

    let answer = ("quz".to_string(), "1.2.3.4.5.6".to_string());

    let mut iter = asn1.iter();
    assert_eq!(Some(answer), iter.next());
    assert_eq!(None, iter.next());
}
