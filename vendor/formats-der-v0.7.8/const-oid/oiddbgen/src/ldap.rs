#[derive(Clone, Debug, Default)]
pub struct LdapParser<'a>(&'a str);

impl<'a> LdapParser<'a> {
    pub fn new(ldap: &'a str) -> Self {
        Self(ldap)
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = (String, String, String)> {
        self.0.lines().filter_map(|line| {
            let (name, next) = line.split_at(line.find(',').unwrap());
            let (.., next) = next[1..].split_at(next[1..].find(',').unwrap());
            let (obid, spec) = next[1..].split_at(next[1..].find(',').unwrap());

            let indx = obid.find('.')?;
            obid.split_at(indx).0.parse::<usize>().ok()?;

            if !spec.trim().starts_with(",[RFC") {
                return None;
            }

            let spec = spec[2..][..spec.len() - 3].to_ascii_lowercase();
            let name = name.trim().to_string();
            let obid = obid.trim().to_string();
            Some((spec, name, obid))
        })
    }
}
