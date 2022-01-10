;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

(ql:quickload :cl-yaml)

(defparameter *caldera-mapping-directory* "/Users/hes/Research-Projects/final-caldera-integration/caldera-integration-main/src/caldera/plugins/stockpile/data/abilities/**/*.yml")


(defun create-caldera-mapping-file (&key  (input-pathname *caldera-mapping-directory*)
                                          (output-pathname "aplan:home;attack-id-mapping.lisp"))
  ;; Directory is shadowed in the aplan package
  ;; because we have an object-type called directory
  (let ((all-pathnames (cl:directory input-pathname))
        (answer nil))
    (loop for pathname in all-pathnames
        do (push (get-mapping pathname) answer))
    (setq answer (sort answer #'string-lessp :key #'first))
    (with-open-file (f output-pathname
                     :direction :output
                     :if-exists :supersede
                     :if-does-not-exist :create)
      (write-string ";;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-" f)
      (terpri f)
      (print '(in-package :aplan) f)
      (terpri f)
      (loop for thing in answer
          do (pprint thing f)
             (terpri f)))))


(defun get-mapping (pathname)
  (let* ((yaml (cl-yaml:parse pathname))
         (entry (first yaml))
         (id (gethash "id" entry))
         (tactic-name (gethash "tactic" entry))
         (technique-ht (gethash "technique" entry))
         (attack-id (gethash "attack_id" technique-ht))
         (attack-name (gethash "name" technique-ht)))
    (list attack-id id attack-name tactic-name)))

(defun make-caldera-mapping-ht (&key (input-pathname "aplan:home;attack-id-mapping.lisp"))
  (let ((ht (make-hash-table :test #'equal)))
    (with-open-file (f input-pathname :direction :input)
      ;; skip the (in-package :aplan) form
      (read f)
      (loop for entry = (read f nil 'eof)
          until (eql entry 'eof)
          for (attack-id yaml-id) = entry
          do (setf (gethash attack-id ht) yaml-id))
      ht)))
