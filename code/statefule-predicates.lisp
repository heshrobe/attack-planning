;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan ; readtable: joshua -*-

(in-package :aplan)



;;; A world-state; It comes before and after some action
;;; And contains a set of predicates true at that time

(defparameter *current-state* nil)
(defparameter *state-ht* (make-hash-table))

(defclass state ()
  ((state-name :accessor state-name :initarg :state-name)
   (predecessor :accessor predecessor :initarg :predecessor)
   (successor :accessor successor :initarg :successor))
  )

(defmethod print-object ((thing state) stream)
  (format stream "#<state ~a>" (state-name thing)))

(defun intern-state (name &optional (prior-state nil prior-state-supplied-p))
  (let ((state (gethash name *state-ht*)))
    (typecase prior-state
      ((null state))
      (symbol (setq prior-state (intern-state prior-state))))
    (unless state
      (setq state (make-instance 'state :state-name name))
      (setf (gethash name *state-ht*) state))
    (when prior-state-supplied-p
      (setf (predecessor state) prior-state
	    (successor prior-state) state))
    state))

(define-predicate-model stateful-predicate-mixin 
  ((true-states :accessor true-states :initform nil :initarg :true-states)
   (false-states :accessor false-states :initform nil :initarg :false-states))
  ()
  )

(define-predicate-method (clear stateful-predicate-mixin) (&optional clear-database undefrules)
  (declare (ignore undefrules))
  (when clear-database
    (clrhash *state-ht*)))


(define-predicate-method (tell stateful-predicate-mixin :after) (truth-value justification)
  (declare (ignore justification))
  (let* ((predication self)
	 (state *current-state*))
    (cond
     ((eql truth-value +true+) (push state (true-states predication)))
     ((eql truth-value +false+) (push state (false-states predication))))))

(define-predicate-method (ask stateful-predicate-mixin :around) (truth-value continuation do-backward-rules do-questions)
  (let* ((predication self)
	 (state *current-state*))
    (flet ((my-continuation (justifcation)
	     (when (cond
		     ((eql truth-value +true+) (member state (true-states predication)))
		     ((eql truth-value +false+) (member state (false-states predication))))
	       (funcall continuation justifcation))))
      (call-next-method predication truth-value #'my-continuation do-backward-rules do-questions))))



(define-predicate test-stateful (a b c) (stateful-predicate-mixin default-predicate-model))

(defun test-stateful (x y z state-name)
  (let ((*current-state* (intern-state state-name)))
    (tell `[test-statefull ,x ,y ,z])))

    