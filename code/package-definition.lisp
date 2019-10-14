;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*-

(in-package :cl-user)

(defpackage aplan
  (:shadow "DIRECTORY" "VALUE-OF")
  (:shadowing-import-from "CL-USER" "THROW")
  (:export "DO-IT"
	   "ATTACK-PLAN-COLLECTOR" "ATTACK-PLANS" "MERGED-ATTACK-PLAN"  "MERGE-ATTACK-PLANS"
	   "DUMP-PLAN"
	   )      
  (:USE COMMON-LISP JOSHUA))


