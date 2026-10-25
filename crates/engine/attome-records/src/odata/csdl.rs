//! The OData `$metadata` document (CSDL XML, version 4.0) for the entities
//! and attributes a caller may read. Pure.

use attome_core::FieldType;

/// The schema namespace of every type.
pub const NAMESPACE: &str = "Attome";

/// One property of an entity type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    pub edm_type: &'static str,
    pub nullable: bool,
}

/// One entity type and its set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitySet {
    pub name: String,
    pub properties: Vec<Property>,
}

/// The EDM type a field type is served as.
pub fn edm_type(field: FieldType) -> &'static str {
    match field {
        FieldType::Number | FieldType::Currency => "Edm.Decimal",
        FieldType::Date => "Edm.DateTimeOffset",
        FieldType::Bool => "Edm.Boolean",
        FieldType::Lookup => "Edm.Guid",
        _ => "Edm.String",
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// The CSDL document. Names come from metadata (lowercase logical names),
/// and are escaped anyway.
pub fn document(sets: &[EntitySet]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <edmx:Edmx Version=\"4.0\" xmlns:edmx=\"http://docs.oasis-open.org/odata/ns/edmx\">\n\
         <edmx:DataServices>\n",
    );
    xml.push_str(&format!(
        "<Schema Namespace=\"{NAMESPACE}\" xmlns=\"http://docs.oasis-open.org/odata/ns/edm\">\n"
    ));
    for set in sets {
        xml.push_str(&format!(
            "<EntityType Name=\"{}\"><Key><PropertyRef Name=\"id\"/></Key>\n",
            escape(&set.name)
        ));
        for p in &set.properties {
            xml.push_str(&format!(
                "<Property Name=\"{}\" Type=\"{}\"{}/>\n",
                escape(&p.name),
                p.edm_type,
                if p.nullable {
                    ""
                } else {
                    " Nullable=\"false\""
                }
            ));
        }
        xml.push_str("</EntityType>\n");
    }
    xml.push_str("<EntityContainer Name=\"Container\">\n");
    for set in sets {
        let name = escape(&set.name);
        xml.push_str(&format!(
            "<EntitySet Name=\"{name}\" EntityType=\"{NAMESPACE}.{name}\"/>\n"
        ));
    }
    xml.push_str("</EntityContainer>\n</Schema>\n</edmx:DataServices>\n</edmx:Edmx>\n");
    xml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odata_metadata_lists_sets_keys_and_types() {
        let xml = document(&[EntitySet {
            name: "account".into(),
            properties: vec![
                Property {
                    name: "id".into(),
                    edm_type: "Edm.Guid",
                    nullable: false,
                },
                Property {
                    name: "name".into(),
                    edm_type: edm_type(FieldType::Text),
                    nullable: true,
                },
                Property {
                    name: "annual_revenue".into(),
                    edm_type: edm_type(FieldType::Currency),
                    nullable: true,
                },
            ],
        }]);
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<EntityType Name=\"account\"><Key><PropertyRef Name=\"id\"/></Key>"));
        assert!(xml.contains("<Property Name=\"id\" Type=\"Edm.Guid\" Nullable=\"false\"/>"));
        assert!(xml.contains("<Property Name=\"annual_revenue\" Type=\"Edm.Decimal\"/>"));
        assert!(xml.contains("<EntitySet Name=\"account\" EntityType=\"Attome.account\"/>"));
        assert_eq!(edm_type(FieldType::Date), "Edm.DateTimeOffset");
        assert_eq!(edm_type(FieldType::Lookup), "Edm.Guid");
        assert_eq!(edm_type(FieldType::Choice), "Edm.String");
    }

    #[test]
    fn odata_metadata_escapes_names() {
        let xml = document(&[EntitySet {
            name: "a\"<b".into(),
            properties: Vec::new(),
        }]);
        assert!(xml.contains("a&quot;&lt;b"));
        assert!(!xml.contains("a\"<b"));
    }
}
