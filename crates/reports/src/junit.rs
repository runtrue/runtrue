#[derive(Debug)]
struct JunitCase {
    name: String,
    class_name: Option<String>,
    path: Option<String>,
    failed: bool,
    skipped: bool,
}

#[derive(Debug)]
struct FailureCapture {
    element: String,
    message: String,
    detail: String,
    rule_id: Option<String>,
}

pub(crate) fn parse_junit(input: &[u8], limits: ReportLimits) -> Result<ParseOutput, ReportError> {
    let mut reader = Reader::from_reader(input);
    let config = reader.config_mut();
    config.trim_text(true);
    config.expand_empty_elements = true;
    config.check_end_names = true;

    let mut buffer = Vec::new();
    let mut event_count = 0_usize;
    let mut depth = 0_usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut case: Option<JunitCase> = None;
    let mut capture: Option<FailureCapture> = None;
    let mut summary = ReportSummary::default();
    let mut annotations = Vec::new();

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .map_err(|_| ReportError::Malformed("invalid JUnit XML".to_owned()))?;
        event_count = event_count
            .checked_add(1)
            .ok_or(ReportError::ComplexityLimit)?;
        if event_count > limits.max_events {
            return Err(ReportError::ComplexityLimit);
        }

        match event {
            Event::Start(start) => {
                if root_closed {
                    return Err(ReportError::Malformed(
                        "JUnit XML contains multiple root elements".to_owned(),
                    ));
                }
                depth = depth.checked_add(1).ok_or(ReportError::ComplexityLimit)?;
                if depth > limits.max_depth {
                    return Err(ReportError::ComplexityLimit);
                }
                let name = xml_name(start.name().as_ref())?;
                let attributes = xml_attributes(&start, limits)?;
                if !root_seen {
                    if name != "testsuites" && name != "testsuite" {
                        return Err(ReportError::Malformed(
                            "JUnit root must be testsuites or testsuite".to_owned(),
                        ));
                    }
                    root_seen = true;
                }

                match name.as_str() {
                    "testcase" => {
                        if case.is_some() {
                            return Err(ReportError::Malformed(
                                "JUnit testcases cannot be nested".to_owned(),
                            ));
                        }
                        if summary.total as usize >= limits.max_results {
                            return Err(ReportError::ComplexityLimit);
                        }
                        let name = attributes.get("name").ok_or_else(|| {
                            ReportError::Malformed("JUnit testcase.name is required".to_owned())
                        })?;
                        let path = attributes
                            .get("file")
                            .map(|value| safe_path(value))
                            .transpose()?;
                        case = Some(JunitCase {
                            name: bounded_string(name, limits)?,
                            class_name: attributes
                                .get("classname")
                                .map(|value| bounded_string(value, limits))
                                .transpose()?,
                            path,
                            failed: false,
                            skipped: false,
                        });
                    }
                    "failure" | "error" => {
                        let current = case.as_mut().ok_or_else(|| {
                            ReportError::Malformed(format!(
                                "JUnit {name} must be inside a testcase"
                            ))
                        })?;
                        if capture.is_some() {
                            return Err(ReportError::Malformed(
                                "JUnit failure elements cannot be nested".to_owned(),
                            ));
                        }
                        current.failed = true;
                        capture = Some(FailureCapture {
                            element: name,
                            message: attributes
                                .get("message")
                                .map_or_else(String::new, Clone::clone),
                            detail: String::new(),
                            rule_id: attributes.get("type").cloned(),
                        });
                    }
                    "skipped" => {
                        let current = case.as_mut().ok_or_else(|| {
                            ReportError::Malformed(
                                "JUnit skipped must be inside a testcase".to_owned(),
                            )
                        })?;
                        current.skipped = true;
                    }
                    _ => {}
                }
            }
            Event::End(end) => {
                let name = xml_name(end.name().as_ref())?;
                if matches!(name.as_str(), "failure" | "error") {
                    let captured = capture.take().ok_or_else(|| {
                        ReportError::Malformed("JUnit failure end is unmatched".to_owned())
                    })?;
                    if captured.element != name {
                        return Err(ReportError::Malformed(
                            "JUnit failure end is mismatched".to_owned(),
                        ));
                    }
                    let current = case.as_ref().ok_or_else(|| {
                        ReportError::Malformed("JUnit testcase ended unexpectedly".to_owned())
                    })?;
                    let message = junit_failure_message(current, &captured, limits)?;
                    annotations.push(Annotation {
                        level: AnnotationLevel::Error,
                        message,
                        rule_id: captured.rule_id,
                        path: current.path.clone(),
                        start_line: None,
                        start_column: None,
                        end_line: None,
                        end_column: None,
                    });
                    if annotations.len() > limits.max_results {
                        return Err(ReportError::ComplexityLimit);
                    }
                } else if name == "testcase" {
                    if capture.is_some() {
                        return Err(ReportError::Malformed(
                            "JUnit testcase ended inside a failure".to_owned(),
                        ));
                    }
                    let current = case.take().ok_or_else(|| {
                        ReportError::Malformed("JUnit testcase end is unmatched".to_owned())
                    })?;
                    checked_add(&mut summary.total, 1)?;
                    if current.failed {
                        checked_add(&mut summary.failed, 1)?;
                    } else if current.skipped {
                        checked_add(&mut summary.skipped, 1)?;
                    } else {
                        checked_add(&mut summary.passed, 1)?;
                    }
                }
                depth = depth.checked_sub(1).ok_or_else(|| {
                    ReportError::Malformed("JUnit XML close element is unmatched".to_owned())
                })?;
                if depth == 0 {
                    root_closed = true;
                }
            }
            Event::Text(text) => {
                if let Some(capture) = &mut capture {
                    let decoded = text
                        .xml10_content()
                        .map_err(|_| ReportError::Malformed("invalid JUnit text".to_owned()))?;
                    let text = quick_xml::escape::unescape(&decoded)
                        .map_err(|_| ReportError::Malformed("invalid JUnit text".to_owned()))?;
                    append_bounded(&mut capture.detail, &text, limits)?;
                }
            }
            Event::GeneralRef(reference) => {
                if let Some(capture) = &mut capture {
                    let value = if let Some(value) = reference
                        .resolve_char_ref()
                        .map_err(|_| ReportError::Malformed("invalid JUnit text".to_owned()))?
                    {
                        if !is_xml_1_0_character(value) {
                            return Err(ReportError::Malformed("invalid JUnit text".to_owned()));
                        }
                        value.to_string()
                    } else {
                        let name = reference
                            .decode()
                            .map_err(|_| ReportError::Malformed("invalid JUnit text".to_owned()))?;
                        quick_xml::escape::resolve_predefined_entity(&name)
                            .ok_or_else(|| {
                                ReportError::Malformed("unknown JUnit entity".to_owned())
                            })?
                            .to_owned()
                    };
                    append_bounded(&mut capture.detail, &value, limits)?;
                }
            }
            Event::CData(text) => {
                if let Some(capture) = &mut capture {
                    let text = str::from_utf8(text.as_ref())
                        .map_err(|_| ReportError::Malformed("JUnit XML is not UTF-8".to_owned()))?;
                    append_bounded(&mut capture.detail, text, limits)?;
                }
            }
            Event::Decl(_) if !root_seen && depth == 0 => {}
            Event::Comment(_) => {}
            Event::PI(_) | Event::DocType(_) | Event::Decl(_) => {
                return Err(ReportError::Malformed(
                    "JUnit processing instructions and DTDs are forbidden".to_owned(),
                ));
            }
            Event::Empty(_) => {
                return Err(ReportError::Malformed(
                    "unexpected unexpanded JUnit element".to_owned(),
                ));
            }
            Event::Eof => break,
        }
        buffer.clear();
    }

    if !root_seen || !root_closed || depth != 0 || case.is_some() || capture.is_some() {
        return Err(ReportError::Malformed(
            "JUnit XML ended before all elements were closed".to_owned(),
        ));
    }
    Ok((summary, annotations, None))
}

fn xml_name(value: &[u8]) -> Result<String, ReportError> {
    let value = str::from_utf8(value)
        .map_err(|_| ReportError::Malformed("JUnit XML names must be UTF-8".to_owned()))?;
    if value.is_empty() || value.contains(':') {
        return Err(ReportError::Malformed(
            "JUnit XML namespaces are not supported".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn xml_attributes(
    start: &quick_xml::events::BytesStart<'_>,
    limits: ReportLimits,
) -> Result<BTreeMap<String, String>, ReportError> {
    let mut values = BTreeMap::new();
    for attribute in start.attributes().with_checks(true) {
        let attribute =
            attribute.map_err(|_| ReportError::Malformed("invalid JUnit attribute".to_owned()))?;
        let name = xml_name(attribute.key.as_ref())?;
        if values.contains_key(&name) {
            return Err(ReportError::Malformed(format!(
                "duplicate JUnit attribute `{name}`"
            )));
        }
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| ReportError::Malformed("invalid JUnit attribute value".to_owned()))?;
        values.insert(name, bounded_string(&value, limits)?);
        if values.len() > limits.max_events {
            return Err(ReportError::ComplexityLimit);
        }
    }
    Ok(values)
}

fn is_xml_1_0_character(value: char) -> bool {
    matches!(value, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(value as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn append_bounded(
    destination: &mut String,
    value: &str,
    limits: ReportLimits,
) -> Result<(), ReportError> {
    let required = destination
        .len()
        .checked_add(value.len())
        .ok_or(ReportError::ComplexityLimit)?;
    if required > limits.max_string_bytes || value.contains('\0') {
        return Err(ReportError::ComplexityLimit);
    }
    destination.push_str(value);
    Ok(())
}

fn junit_failure_message(
    case: &JunitCase,
    failure: &FailureCapture,
    limits: ReportLimits,
) -> Result<String, ReportError> {
    let identity = case.class_name.as_ref().map_or_else(
        || case.name.clone(),
        |class_name| format!("{class_name}::{}", case.name),
    );
    let mut message = identity;
    if !failure.message.is_empty() {
        append_bounded(&mut message, ": ", limits)?;
        append_bounded(&mut message, &failure.message, limits)?;
    }
    if !failure.detail.is_empty() {
        append_bounded(&mut message, "\n", limits)?;
        append_bounded(&mut message, &failure.detail, limits)?;
    }
    bounded_string(&message, limits)
}
use crate::{
    limits::{bounded_string, checked_add},
    strict_json::safe_path,
    Annotation, AnnotationLevel, ParseOutput, ReportError, ReportLimits, ReportSummary,
};
use quick_xml::{events::Event, Reader, XmlVersion};
use std::{collections::BTreeMap, str};

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn junit_is_normalized_and_html_is_escaped() {
        let xml = br#"<?xml version="1.0"?>
            <testsuites><testsuite name="suite">
              <testcase name="works" classname="unit"/>
              <testcase name="fails" classname="unit" file="src/lib.rs">
                <failure type="assertion" message="&lt;script&gt;bad&lt;/script&gt;">left &amp; right</failure>
              </testcase>
              <testcase name="ignored"><skipped/></testcase>
            </testsuite></testsuites>"#;
        let report = ingest(ReportFormat::JunitXml, xml, ReportLimits::default()).unwrap();
        assert_eq!(report.summary.total, 3);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(report.annotations[0].path.as_deref(), Some("src/lib.rs"));
        assert!(report.annotations[0].message.contains("<script>"));
        assert!(!report.annotations[0].escaped_message().contains("<script>"));
        assert!(report.annotations[0]
            .escaped_message()
            .contains("&lt;script&gt;"));
    }

    #[test]
    fn junit_rejects_dtds_and_unsafe_paths() {
        let dtd = br#"<!DOCTYPE testsuite [<!ENTITY x "boom">]><testsuite/>"#;
        assert!(matches!(
            ingest(ReportFormat::JunitXml, dtd, ReportLimits::default()),
            Err(ReportError::Malformed(_))
        ));
        let path = br#"<testsuite><testcase name="x" file="../secret"/></testsuite>"#;
        assert!(matches!(
            ingest(ReportFormat::JunitXml, path, ReportLimits::default()),
            Err(ReportError::UnsafePath)
        ));

        for invalid_entity in [
            br#"<testsuite><testcase name="x"><failure>&unknown;</failure></testcase></testsuite>"#
                .as_slice(),
            br#"<testsuite><testcase name="x"><failure>&#1;</failure></testcase></testsuite>"#
                .as_slice(),
        ] {
            assert!(matches!(
                ingest(
                    ReportFormat::JunitXml,
                    invalid_entity,
                    ReportLimits::default()
                ),
                Err(ReportError::Malformed(_))
            ));
        }
    }
}
