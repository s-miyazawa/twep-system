;; Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
;; SPDX-License-Identifier: BSD-2-Clause
(module
  (memory (export "memory") 1)
  (func (export "twep_app_abi_version") (result i32)
    i32.const 1)
  (func (export "twep_app_main") (param i32 i32 i32) (result i32)
    (loop $forever
      br $forever)
    i32.const 0)
  (func (export "twep_app_free") (param i32 i32)))
