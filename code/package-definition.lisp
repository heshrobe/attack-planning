;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*-

(in-package :cl-user)

(defpackage aplan
  (:shadow "DIRECTORY" "VALUE-OF" "OBJECT-TYPE-OF")
  (:shadowing-import-from "CL-USER" "THROW")
  (:import-from ltms "ASSUME")
  (:export "DO-IT"
           "DO-A-CASE"
	   "ATTACK-PLAN-COLLECTOR" "ATTACK-PLANS" "MERGED-ATTACK-PLAN"  "MERGE-ATTACK-PLANS"
	   "DUMP-PLAN"
	   )
  (:USE COMMON-LISP JOSHUA))
