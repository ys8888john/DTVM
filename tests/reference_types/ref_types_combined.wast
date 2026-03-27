;; Combined test for reference types proposal
;; Tests multiple features together

(module
  ;; Table with 20 funcref elements
  (table $tbl 20 funcref)

  ;; Helper functions
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    (i32.add (local.get $a) (local.get $b))
  )

  (func $sub (export "sub") (param $a i32) (param $b i32) (result i32)
    (i32.sub (local.get $a) (local.get $b))
  )

  (func $mul (export "mul") (param $a i32) (param $b i32) (result i32)
    (i32.mul (local.get $a) (local.get $b))
  )

  ;; Initialize table with function references
  (func (export "init_table")
    ;; Set add function at index 0
    (table.set $tbl (i32.const 0) (ref.func $add))
    ;; Set sub function at index 1
    (table.set $tbl (i32.const 1) (ref.func $sub))
    ;; Set mul function at index 2
    (table.set $tbl (i32.const 2) (ref.func $mul))
    ;; Leave others as null
  )

  ;; Get function reference from table and check if null
  (func (export "is_table_elem_null") (param $idx i32) (result i32)
    (table.get $tbl (local.get $idx))
    (ref.is_null)
  )

  ;; Store a null reference in the table
  (func (export "clear_table_elem") (param $idx i32)
    (table.set $tbl (local.get $idx) (ref.null func))
  )

  ;; Get the add function reference
  (func (export "get_add_ref") (result funcref)
    (ref.func $add)
  )

  ;; Get null funcref
  (func (export "get_null_funcref") (result funcref)
    (ref.null func)
  )

  ;; Test chaining operations
  (func (export "chained_test") (result i32)
    ;; Create null, check is_null (should be 1)
    (drop (ref.null func))
    (drop (ref.is_null))
    ;; Create func ref, check is_null (should be 0)
    (drop (ref.func $add))
    (ref.is_null)
    (i32.eqz)  ;; Negate: 0 becomes 1
  )
)

;; Test initialization
(assert_return (invoke "init_table"))

;; After init, index 0, 1, 2 should not be null
(assert_return (invoke "is_table_elem_null" (i32.const 0)) (i32.const 0))
(assert_return (invoke "is_table_elem_null" (i32.const 1)) (i32.const 0))
(assert_return (invoke "is_table_elem_null" (i32.const 2)) (i32.const 0))

;; Others should be null
(assert_return (invoke "is_table_elem_null" (i32.const 3)) (i32.const 1))
(assert_return (invoke "is_table_elem_null" (i32.const 10)) (i32.const 1))

;; Clear an element
(assert_return (invoke "clear_table_elem" (i32.const 1)))
(assert_return (invoke "is_table_elem_null" (i32.const 1)) (i32.const 1))

;; Test null reference
(assert_return (invoke "get_null_funcref") (ref.null func))

;; Test chained operations
(assert_return (invoke "chained_test") (i32.const 0))