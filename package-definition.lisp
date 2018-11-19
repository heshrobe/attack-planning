;;; -*- Syntax: Ansi-common-lisp; Package: cl-USER; Base: 10; Mode: LISP -*-

(in-package :cl-user)

(defpackage aplan
  (:shadow "DIRECTORY" )
  #+allegro (:import-from "MP" "PROCESS-RUN-FUNCTION")
   #+allegro (:import-from excl funwrap fwrap arglist def-fwrapper call-next-fwrapper)
  (:shadowing-import-from "CL-USER" "THROW")
  (:USE COMMON-LISP JOSHUA))


