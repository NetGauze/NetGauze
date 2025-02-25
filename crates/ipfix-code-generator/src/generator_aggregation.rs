use crate::{InformationElement, get_rust_type};

/// Generates `extract_as_key_str(&self, ie: &IE, indices: &Option<Vec<usize>>) -> String` for `Fields`
pub fn impl_extract_as_key_str() -> String {
  let mut ret = String::new();
  ret.push_str("    pub fn extract_as_key_str(&self, ie: &IE, indices: &Option<Vec<usize>>) -> String {\n");
  ret.push_str("        match indices {\n");
  ret.push_str("          Some(idxs) => idxs\n");
  ret.push_str("              .iter()\n");
  ret.push_str("              .map(|&idx| {\n");
  ret.push_str("                  self.get(*ie).get(idx).map_or_else(\n");
  ret.push_str("                      || \"None\".to_string(),\n");
  ret.push_str("                      |field| {\n");
  ret.push_str("                          field\n");
  ret.push_str("                              .clone()\n");
  ret.push_str("                              .try_into()\n");
  ret.push_str("                              .unwrap_or_else(|_| \"Unsupported\".to_string())\n");
  ret.push_str("                      },\n");
  ret.push_str("                  )\n");
  ret.push_str("              })\n");
  ret.push_str("              .collect::<Vec<_>>()\n");
  ret.push_str("              .join(\",\"),\n");
  ret.push_str("          None => self\n");
  ret.push_str("              .get(*ie)\n");
  ret.push_str("              .iter()\n");
  ret.push_str("              .map(|field| {\n");
  ret.push_str("                  field\n");
  ret.push_str("                      .clone()\n");
  ret.push_str("                      .try_into()\n");
  ret.push_str("                      .unwrap_or_else(|_| \"Unsupported\".to_string())\n");
  ret.push_str("              })\n");
  ret.push_str("              .collect::<Vec<_>>()\n");
  ret.push_str("              .join(\",\"),\n");
  ret.push_str("        }\n");
  ret.push_str("    }\n\n");
  ret
}

/// Generates `reduce(&mut self, incoming: &Fields, transform: &std::collections::BTreeMap<IE, netgauze_analytics::flow::AggrOp>)` for `Fields`
pub fn impl_reduce(
  iana_ies: &Vec<InformationElement>,
  vendors: &Vec<(String, String, u32)>,
) -> String {
  let mut ret = String::new();

  ret.push_str("    pub fn reduce(&mut self, incoming: &Fields, transform: &std::collections::BTreeMap<IE, netgauze_analytics::flow::AggrOp>) {\n");
  ret.push_str("        for (ie, op) in transform {\n");
  ret.push_str("            match ie {\n");

  if !vendors.is_empty() {
      ret.push_str("                IE::Unknown { .. } => {},\n");
  }
  // TODO: maybe revisit thinking about structure of Transform
  for (name, pkg, _) in vendors {
      ret.push_str(format!("                IE::{name}(vendor_ie) => {{\n").as_str());
      ret.push_str(format!("                    if self.{pkg}.is_none() {{\n").as_str());
      ret.push_str(format!("                        self.{pkg} = Some({pkg}::Fields::default());\n").as_str());
      ret.push_str("                    }\n");
      ret.push_str(format!("                    if let Some(vendor_fields) = self.{pkg}.as_mut() {{\n").as_str());
      ret.push_str(format!("                        if let Some(vendor_incoming_fields) = &incoming.{pkg} {{\n").as_str());
      ret.push_str(format!("                            let mut vendor_transform: std::collections::BTreeMap<{pkg}::IE,netgauze_analytics::flow::AggrOp> = std::collections::BTreeMap::new();\n").as_str());
      ret.push_str("                            vendor_transform.insert(*vendor_ie, op.clone());\n");
      ret.push_str(format!("                            \n").as_str());
      ret.push_str(format!("                            vendor_fields.reduce(vendor_incoming_fields, &vendor_transform);\n").as_str());
      ret.push_str("                        }\n");
      ret.push_str("                    }\n");
      ret.push_str("                }\n");
  }
  for ie in iana_ies {
      let rust_type = get_rust_type(&ie.data_type);
      if ie.name == "tcpControlBits" {
          ret.push_str("                IE::tcpControlBits => {\n");
          ret.push_str("                    netgauze_analytics::flow::reduce_boolmap_vec(&mut self.tcpControlBits, &incoming.tcpControlBits, op);\n");
          ret.push_str("                }\n");
      }
      else if ["u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"].contains(&rust_type.as_str()) &&
              !ie.subregistry.is_some() {
          ret.push_str(format!("                IE::{} => {{\n", ie.name).as_str());
          ret.push_str(format!("                    netgauze_analytics::flow::reduce_num_vec(&mut self.{}, &incoming.{}, op);\n", ie.name, ie.name).as_str());
          ret.push_str("                }\n");
      }
      else if ["Vec<u8>", "String"].contains(&rust_type.as_str()) {
          ret.push_str(format!("                IE::{} => {{\n", ie.name).as_str());
          ret.push_str(format!("                    netgauze_analytics::flow::reduce_misc_vec_clone(&mut self.{}, &incoming.{}, op);\n", ie.name, ie.name).as_str());
          ret.push_str("                }\n");
      }
      else {
          ret.push_str(format!("                IE::{} => {{\n", ie.name).as_str());
          ret.push_str(format!("                    netgauze_analytics::flow::reduce_misc_vec(&mut self.{}, &incoming.{}, op);\n", ie.name, ie.name).as_str());
          ret.push_str("                }\n");
      }
  }
  ret.push_str("             }\n");
  ret.push_str("        }\n");
  ret.push_str("    }\n");

  ret
}
