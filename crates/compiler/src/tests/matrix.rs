use super::super::*;

#[test]
fn static_matrix_expansion_stays_deterministic() {
    let source = r#"
version: 1
name: matrix
permissions:
  network: deny
  repository: deny
jobs:
  build:
    matrix:
      os: [linux, windows]
    steps:
      - run: { command: ["true"] }
"#;
    let compilation = Compiler::default()
        .compile_yaml(source, CompileContext::default())
        .expect("matrix workflow should compile");
    assert_eq!(compilation.capsule.jobs.len(), 2);
}
