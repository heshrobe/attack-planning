;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*-

(in-package :cl-user)

(defpackage aplan
  #+allegro
  (:shadow "DIRECTORY" )
  #+allegro 
  (:import-from "MP" "PROCESS-RUN-FUNCTION")
  (:shadowing-import-from "CL-USER" "THROW")
  (:USE COMMON-LISP JOSHUA))


