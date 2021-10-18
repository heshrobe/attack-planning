;;; -*- Mode: Common-lisp; Package: Swank -*-

(in-package :swank)


#+mcclim
(defmethod form-parser ((key (eql 'aplan::define-aplan-predicate)) form)
  (values (second form) :joshua-predicate))

;;; still need support for defattack-method, define-action and define-aplan-object
