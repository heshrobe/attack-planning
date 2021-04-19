;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*-

(in-package :cl-user)

(defpackage aplan
  (:shadow "DIRECTORY" "VALUE-OF" object-type-of)
  (:shadowing-import-from "CL-USER" "THROW")
  (:import-from ltms "ASSUME")
  (:export "DO-IT"
	   "ATTACK-PLAN-COLLECTOR" "ATTACK-PLANS" "MERGED-ATTACK-PLAN"  "MERGE-ATTACK-PLANS"
	   "DUMP-PLAN"
	   )      
  (:USE COMMON-LISP JOSHUA))


