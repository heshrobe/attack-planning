;;; -*- Mode: Common-lisp; Package: Swank -*-

(in-package :swank)


(defmethod form-parser ((key (eql 'aplan::defattack-method)) form)
  (values (second form) :joshua-defrule))

(defmethod form-parser ((key (eql 'aplan::define-aplan-predicate)) form)
  (values (second form) :joshua-predicate))

(defmethod form-parser ((key (eql 'aplan::define-action)) form)
  (values (second form) :joshua-defrule))

(defmethod form-parser ((key (eql 'aplan::define-aplan-object)) form)
  (values (second form) :joshua-define-object-type))

;;; Aplan has lots of defining forms for things in the environment
;;; I may need to add more of these for all those things.
;;; The thing is since they're all macros they're all pretty easy
;;; like the ones above
