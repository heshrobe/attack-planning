;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)

(ql:quickload :cl-yaml)

(defparameter *caldera-mapping-directory* "/Users/hes/Research-Projects/final-caldera-integration/caldera-integration-main/src/caldera/plugins/stockpile/data/abilities/**/*.yml")


(defun create-caldera-mapping (&key  (input-pathname *caldera-mapping-directory*))
  (let ((ht (make-hash-table :test #'equal)))
    (loop for pathname in (cl:directory input-pathname)
        for mapping = (get-mapping pathname)
        do (push mapping (gethash (first mapping) ht nil)))
    ht))


(defun get-mapping (pathname)
  (let* ((yaml (cl-yaml:parse pathname))
         (entry (first yaml))
         (id (gethash "id" entry))
         (tactic-name (gethash "tactic" entry))
         (technique-ht (gethash "technique" entry))
         (attack-id (gethash "attack_id" technique-ht))
         (attack-name (gethash "name" technique-ht)))
    (list attack-id id attack-name tactic-name)))

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

(defun make-caldera-mapping-ht (&key (input-pathname "aplan:home;attack-id-mapping.lisp"))
  (let ((ht (make-hash-table :test #'equal)))
    (with-open-file (f input-pathname :direction :input)
      ;; skip the (in-package :aplan) form
      (read f)
      (loop for entry = (read f nil 'eof)
          until (eql entry 'eof)
          for (attack-id) = entry
          do (push entry (gethash attack-id ht nil)))
      ht)))




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Some hacks for dumping in a format that's easier for Caldera integration
;;; the idea is to only dump nodes that have ATT&CK identifiers (as opposed to attack-method names)
;;; and to not traverse below those nodes that do
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; The first thing we need is a cut-off function.
;;; The cut-off criterion is that:
;;; 1) the Node is an attack-plan node
;;; 2) It's attack-identifer is in the caldera-mapping

(defparameter *caldera-mapping* (create-caldera-mapping))

;;; Actually not using this at the moment.
(defun caldera-dumper-cutoff (node)
  (and (typep node 'attack-plan)
       (let* ((identifier (attack-identifier node))
             (entry (gethash identifier *caldera-mapping* nil)))
         entry)))

(defun dump-caldera-plan (root-node &optional (stream *standard-output*))
  (multiple-value-bind (computers users) (collect-computers-and-users root-node)
    (json:with-object (stream)
      (format stream "~2%")
      (json:as-object-member ('computers stream) (dump-computers computers stream))
      (format stream "~2%")
      (json:as-object-member ('users stream) (dump-users users stream))
      (format stream "~2%")
      (json:as-object-member ('nodes stream) (dump-nodes root-node stream #'caldera-dumper-cutoff))
      (format stream "~2%")
      (json:as-object-member ('links stream) (dump-links root-node stream)))
    ))

(defgeneric find-ability-id (attack-id goal abilities))

;;; default method handles the case when there's exactly one possibility
;;; specific methods will disambiguate -- eql dispatch on attack-id
(defmethod find-ability-id ((attack-id t) (goal attack-goal) abilities)
  (if (= (length abilities) 1)
      (second (first abilities))
    (error "You need a find-ability-id for ~a" attack-id)))

(defmethod find-ability-id ((attack-id (eql 't1003.008)) goal abilities)
  (declare (ignore abilities))
  (let ((goal-description (goal-name goal)))
    (when (eql (first goal-description) 'dump-password-data-for-cracker)
      (let* ((file (third goal-description))
             (file-name (role-name file)))
        (case file-name
          (password-file "dump_etc_passwd")
          (shadow-file "dump-etc-shadow"))))))

;;; This will create two steps in the sequence
(defmethod find-ability-id  ((attack-id (eql 't1078.002)) (goal t) abilities)
  (loop for ability in abilities collect (second ability)))

(defun get-caldera-id-sequence (root-node)
  (let ((answer nil))
    (flet ((do-a-node (node)
             (typecase node
               (attack-plan
                (let* ((attack-id (attack-identifier node))
                       (entry (gethash (attack-identifier node) *caldera-mapping*)))
                  (when entry
                    (let ((id (find-ability-id (intern attack-id 'aplan) (supergoal node) entry)))
                      (when id
                        (if (listp id)
                            (loop for id in id do (push (list attack-id id) answer))
                          (push (list attack-id id) answer)))))))
               (otherwise))))
      (traverse-merged-attack-graph root-node #'do-a-node :reverse-order t)
      (nreverse answer))))

(defun caldera-sequences-from-attack-plans (attack-plans)
  (remove-duplicates
   (loop for plan in attack-plans
       for merged-form = (merge-attack-plans (list plan))
       for sequence = (get-caldera-id-sequence (first merged-form))
       collect sequence)
   :test #'equal))
