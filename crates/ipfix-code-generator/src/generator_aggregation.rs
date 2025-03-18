use crate::{get_rust_type, InformationElement};

/// Generates `extract_as_key_str(&self, ie: &IE, indices: &Option<Vec<usize>>)
/// -> String` for `Fields`
pub fn impl_extract_as_key_str() -> String {
    let mut ret = String::new();
    ret.push_str(
        "    pub fn extract_as_key_str(&self, ie: &IE, indices: &Option<Vec<usize>>) -> Result<String, netgauze_analytics::flow::AggregationError> {\n",
    );
    ret.push_str("        let fields = self.get(*ie);\n");
    ret.push_str("        if fields.is_empty() {\n");
    ret.push_str("            return Ok(\"None\".to_string());\n");
    ret.push_str("        }\n\n");
    ret.push_str("        match indices {\n");
    ret.push_str("          Some(idxs) => Ok(idxs\n");
    ret.push_str("              .iter()\n");
    ret.push_str("              .map(|&idx| {\n");
    ret.push_str("                  fields.get(idx).map_or_else(\n");
    ret.push_str("                      || \"None\".to_string(),\n");
    ret.push_str("                      |field| {\n");
    ret.push_str("                          field\n");
    ret.push_str("                              .clone()\n");
    ret.push_str("                              .try_into()\n");
    ret.push_str(
        "                              .unwrap_or_else(|_| \"Unsupported\".to_string())\n",
    );
    ret.push_str("                      },\n");
    ret.push_str("                  )\n");
    ret.push_str("              })\n");
    ret.push_str("              .collect::<Vec<_>>()\n");
    ret.push_str("              .join(\",\")),\n");
    ret.push_str("          None => Ok(fields\n");
    ret.push_str("              .iter()\n");
    ret.push_str("              .map(|field| {\n");
    ret.push_str("                  field\n");
    ret.push_str("                      .clone()\n");
    ret.push_str("                      .try_into()\n");
    ret.push_str("                      .unwrap_or_else(|_| \"Unsupported\".to_string())\n");
    ret.push_str("              })\n");
    ret.push_str("              .collect::<Vec<_>>()\n");
    ret.push_str("              .join(\",\")),\n");
    ret.push_str("        }\n");
    ret.push_str("    }\n\n");
    ret
}

/// Generates `reduce(&mut self, incoming: &Fields, transform:
/// &indexmap::IndexMap<IE, netgauze_analytics::flow::AggrOp>)` for
/// `Fields`
pub fn impl_reduce(
    iana_ies: &Vec<InformationElement>,
    vendors: &Vec<(String, String, u32)>,
) -> String {
    let mut ret = String::new();

    ret.push_str("    pub fn reduce(&mut self, incoming: &Fields, transform: &indexmap::IndexMap<IE, netgauze_analytics::flow::AggrOp>) -> Result<(), netgauze_analytics::flow::AggregationError> {\n");
    ret.push_str("        for (ie, op) in transform {\n");
    ret.push_str("            match ie {\n");

    if !vendors.is_empty() {
        ret.push_str("                IE::Unknown { .. } => {},\n");
    }
    // TODO: maybe revisit thinking about structure of Transform
    for (name, pkg, _) in vendors {
        ret.push_str(format!("                IE::{name}(vendor_ie) => {{\n").as_str());
        ret.push_str(format!("                    if self.{pkg}.is_none() {{\n").as_str());
        ret.push_str(
            format!("                        self.{pkg} = Some({pkg}::Fields::default());\n")
                .as_str(),
        );
        ret.push_str("                    }\n");
        ret.push_str(
            format!("                    if let Some(vendor_fields) = self.{pkg}.as_mut() {{\n")
                .as_str(),
        );
        ret.push_str(format!("                        if let Some(vendor_incoming_fields) = &incoming.{pkg} {{\n").as_str());
        ret.push_str(format!("                            let mut vendor_transform: indexmap::IndexMap<{pkg}::IE,netgauze_analytics::flow::AggrOp> = indexmap::IndexMap::new();\n").as_str());
        ret.push_str(
            "                            vendor_transform.insert(*vendor_ie, op.clone());\n",
        );
        ret.push_str("                            \n");
        ret.push_str("                            vendor_fields.reduce(vendor_incoming_fields, &vendor_transform)?\n");
        ret.push_str("                        }\n");
        ret.push_str("                    }\n");
        ret.push_str("                }\n");
    }
    for ie in iana_ies {
        let rust_type = get_rust_type(&ie.data_type, &ie.name);
        if ie.name == "tcpControlBits" {
            ret.push_str("                IE::tcpControlBits => {\n");
            ret.push_str("                    netgauze_analytics::flow::reduce_boolmap(&mut self.tcpControlBits, &incoming.tcpControlBits, op)?\n");
            ret.push_str("                }\n");
        } else if ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"]
            .contains(&rust_type.as_str())
            && ie.subregistry.is_none()
        {
            ret.push_str(format!("                IE::{} => {{\n", ie.name).as_str());
            ret.push_str(format!("                    netgauze_analytics::flow::reduce_num(&mut self.{}, &incoming.{}, op)?\n", ie.name, ie.name).as_str());
            ret.push_str("                }\n");
        } else if ["Box<[u8]>", "Box<[u8; 32]>", "Box<str>"].contains(&rust_type.as_str()) {
            ret.push_str(format!("                IE::{} => {{\n", ie.name).as_str());
            ret.push_str(format!("                    netgauze_analytics::flow::reduce_misc_clone(&mut self.{}, &incoming.{}, op)?\n", ie.name, ie.name).as_str());
            ret.push_str("                }\n");
        } else {
            ret.push_str(format!("                IE::{} => {{\n", ie.name).as_str());
            ret.push_str(format!("                    netgauze_analytics::flow::reduce_misc(&mut self.{}, &incoming.{}, op)?\n", ie.name, ie.name).as_str());
            ret.push_str("                }\n");
        }
    }
    ret.push_str("             }\n");
    ret.push_str("        }\n");
    ret.push_str("    Ok(())\n");
    ret.push_str("    }\n");

    ret
}
