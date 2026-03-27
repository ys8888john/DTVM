;; Test table.set instruction
;; Tests setting elements in tables

(module
  ;; Table with funcref elements
  (table $t1 10 funcref)

  ;; Table with externref elements
  (table $t2 10 externref)

  ;; Simple function to put in table
  (func $f1 (result i32)
    (i32.const 42)
  )

  ;; Set funcref in table
  (func (export "table_set_funcref") (param $idx i32)
    (local.get $idx)
    (ref.func $f1)
    (table.set $t1)
  )

  ;; Set null funcref in table
  (func (export "table_set_null_funcref") (param $idx i32)
    (local.get $idx)
    (ref.null func)
    (table.set $t1)
  )

  ;; Set null externref in table
  (func (export "table_set_null_externref") (param $idx i32)
    (local.get $idx)
    (ref.null extern)
    (table.set $t2)
  )

  ;; Get funcref from table and check if null
  (func (export "table_get_funcref_is_null") (param $idx i32) (result i32)
    (table.get $t1 (local.get $idx))
    (ref.is_null)
  )

  ;; Get externref from table and check if null
  (func (export "table_get_externref_is_null") (param $idx i32) (result i32)
    (table.get $t2 (local.get $idx))
    (ref.is_null)
  )
)

;; Initial elements should be null
(assert_return (invoke "table_get_funcref_is_null" (i32.const 0)) (i32.const 1))
(assert_return (invoke "table_get_externref_is_null" (i32.const 0)) (i32.const 1))

;; Set a function reference and verify it's not null
(assert_return (invoke "table_set_funcref" (i32.const 0)))
(assert_return (invoke "table_get_funcref_is_null" (i32.const 0)) (i32.const 0))

;; Set null and verify it's null
(assert_return (invoke "table_set_null_funcref" (i32.const 0)))
(assert_return (invoke "table_get_funcref_is_null" (i32.const 0)) (i32.const 1))

;; Set at different indices
(assert_return (invoke "table_set_funcref" (i32.const 5)))
(assert_return (invoke "table_get_funcref_is_null" (i32.const 5)) (i32.const 0))

;; Set externref null
(assert_return (invoke "table_set_null_externref" (i32.const 0)))
(assert_return (invoke "table_get_externref_is_null" (i32.const 0)) (i32.const 1))

;; Out of bounds access should trap
(assert_trap (invoke "table_set_funcref" (i32.const 10)) "out of bounds table access")
(assert_trap (invoke "table_set_null_externref" (i32.const 10)) "out of bounds table access")