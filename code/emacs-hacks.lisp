;;; -*- Mode: LISP; Syntax: Joshua; Package: aplan; readtable: joshua -*-

(in-package :aplan)



;;; for editor support

;;; This tells emacs how to kill defattack-method forms (fi:kill-definition C-c C-y)
#+allegero
(defmethod lep::definition-undefining-form (fspec (type (eql 'defattack-method)))
  `(undefrule ',fspec))

#+allegro
(defmethod lep::definition-undefining-form (fspec (type (eql 'define-action)))
  `(undefrule ',fspec))
				       

