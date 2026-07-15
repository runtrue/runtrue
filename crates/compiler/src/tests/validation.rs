use super::super::*;

#[test]
fn missing_dependencies_keep_their_semantic_path() {
    let source = r#"
version: 1
name: invalid
permissions:
  network: deny
  repository: deny
jobs:
  build:
    needs: [missing]
    steps:
      - run: { command: ["true"] }
"#;
    let error = Compiler::default()
        .compile_yaml(source, CompileContext::default())
        .expect_err("missing dependency must fail");
    assert!(error.to_string().contains("unknown dependency"));
}
