;; Test ref.is_null instruction
;; Tests null detection for both funcref and externref

(module
  ;; Check if null funcref is null (should be 1)
  (func (export "is_null_funcref_null") (result i32)
    (ref.null func)
    (ref.is_null)
  )

  ;; Check if null externref is null (should be 1)
  (func (export "is_null_externref_null") (result i32)
    (ref.null extern)
    (ref.is_null)
  )

  ;; Check if a function reference is null (should be 0)
  (func (export "is_null_funcref_non_null") (result i32)
    (ref.func 0)  ;; Reference to this function
    (ref.is_null)
  )

  ;; Helper function to test with non-null reference
  (func $helper)

  ;; Check if a specific function reference is null (should be 0)
  (func (export "is_null_funcref_func") (result i32)
    (ref.func $helper)
    (ref.is_null)
  )
)

;; Null references should return 1 from ref.is_null
(assert_return (invoke "is_null_funcref_null") (i32.const 1))
(assert_return (invoke "is_null_externref_null") (i32.const 1))

;; Non-null references should return 0 from ref.is_null
(assert_return (invoke "is_null_funcref_non_null") (i32.const 0))
(assert_return (invoke "is_null_funcref_func") (i32.const 0))