;; Test table.get instruction
;; Tests retrieving elements from tables

(module
  ;; Table with funcref elements
  (table $t1 10 funcref)

  ;; Table with externref elements
  (table $t2 10 externref)

  ;; Get funcref from table (should be null initially)
  (func (export "table_get_funcref") (param $idx i32) (result funcref)
    (table.get $t1 (local.get $idx))
  )

  ;; Get externref from table (should be null initially)
  (func (export "table_get_externref") (param $idx i32) (result externref)
    (table.get $t2 (local.get $idx))
  )

  ;; Check if table element is null at given index
  (func (export "table_elem_is_null_funcref") (param $idx i32) (result i32)
    (table.get $t1 (local.get $idx))
    (ref.is_null)
  )

  ;; Check if table element is null at given index
  (func (export "table_elem_is_null_externref") (param $idx i32) (result i32)
    (table.get $t2 (local.get $idx))
    (ref.is_null)
  )
)

;; Initial table elements should be null
(assert_return (invoke "table_elem_is_null_funcref" (i32.const 0)) (i32.const 1))
(assert_return (invoke "table_elem_is_null_funcref" (i32.const 5)) (i32.const 1))
(assert_return (invoke "table_elem_is_null_funcref" (i32.const 9)) (i32.const 1))

(assert_return (invoke "table_elem_is_null_externref" (i32.const 0)) (i32.const 1))
(assert_return (invoke "table_elem_is_null_externref" (i32.const 5)) (i32.const 1))
(assert_return (invoke "table_elem_is_null_externref" (i32.const 9)) (i32.const 1))

;; Out of bounds access should trap
(assert_trap (invoke "table_get_funcref" (i32.const 10)) "out of bounds table access")
(assert_trap (invoke "table_get_externref" (i32.const 10)) "out of bounds table access")