(component
  (type $get-environment (func (result (list (tuple string string)))))
  (type $get-arguments (func (result (list string))))
  (type $get-initial-cwd (func (result (option string))))
  (type $environment (instance
    (export "get-environment" (func (type $get-environment)))
    (export "get-arguments" (func (type $get-arguments)))
    (export "get-initial-cwd" (func (type $get-initial-cwd)))))

  ;; Importing the final interface version makes this a concrete WASI 0.3
  ;; compatibility probe. Runtrue supplies an empty environment by default.
  (import "wasi:cli/environment@0.3.0"
    (instance $environment-import (type $environment)))

  (core module $action
    (func (export "run")))
  (core instance $action-instance (instantiate $action))
  (func (export "run")
    (canon lift (core func $action-instance "run"))))
